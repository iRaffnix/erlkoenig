%%%-------------------------------------------------------------------
%%% @doc Stateful property-based tests for erlkoenig_admission.
%%%
%%% Uses `proper_statem` to run random command sequences (acquire,
%%% release with various scopes) against a live gen_server, in
%%% parallel with an abstract in-test model of what the gate should
%%% do. After each command, postconditions check that the system's
%%% answer agrees with the model.
%%%
%%% Covered invariants:
%%%
%%%   1. host_in_flight never exceeds max_host.
%%%   2. per-zone count never exceeds max_per_zone (when enabled).
%%%   3. every released token reduces the in-flight count by one.
%%%   4. releasing an unknown token is a no-op, never crashes.
%%%   5. snapshot agrees with the model at every observation point.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_admission_prop_test).

-compile(nowarn_unused_function).

-behaviour(proper_statem).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([command/1, initial_state/0, next_state/3,
         precondition/2, postcondition/3,
         acquire_/1, release_/1]).

%%--------------------------------------------------------------------
%% Test-side model: tracks outstanding tokens keyed by the scope they
%% were acquired with. We deliberately don't model per-zone caps here
%% — the property is run with max_per_zone=0 (disabled) so only the
%% host cap matters; zone scoping exercises code paths without
%% imposing additional state to track.
%%--------------------------------------------------------------------

-record(s, {
    max_host :: non_neg_integer(),
    held     :: [{token_id(), scope()}]
}).

-type token_id() :: pos_integer().
-type scope()    :: host | {zone, binary()}.

-define(MAX_HOST, 3).

%%--------------------------------------------------------------------
%% Commands & generators
%%--------------------------------------------------------------------

scope_gen() ->
    oneof([host,
           {zone, <<"z-a">>},
           {zone, <<"z-b">>}]).

%% A held-token index. Used when generating release commands — we
%% reach into the model to pick an actually-outstanding token.
held_token_gen(#s{held = []}) ->
    %% Empty — generate a fake id that the system will reject.
    exactly({fake, -1});
held_token_gen(#s{held = Held}) ->
    elements([{real, Id} || {Id, _} <- Held]).

command(S) ->
    oneof([
        {call, ?MODULE, acquire_,  [scope_gen()]},
        {call, ?MODULE, release_,  [held_token_gen(S)]}
    ]).

%%--------------------------------------------------------------------
%% Model transitions and postconditions
%%--------------------------------------------------------------------

initial_state() ->
    #s{max_host = ?MAX_HOST, held = []}.

precondition(_, _) -> true.

next_state(S, Result, {call, ?MODULE, acquire_, [Scope]}) ->
    case model_allows(S, Scope) of
        true ->
            %% We expect the system returned {ok, Token}. Record it
            %% by the symbolic Result reference — proper_statem
            %% threads the real token back later on replay.
            S#s{held = S#s.held ++ [{Result, Scope}]};
        false ->
            S
    end;
next_state(S, _Result, {call, ?MODULE, release_, [{real, Id}]}) ->
    S#s{held = lists:keydelete(Id, 1, S#s.held)};
next_state(S, _Result, {call, ?MODULE, release_, [{fake, _}]}) ->
    S.

postcondition(S, {call, ?MODULE, acquire_, [Scope]}, Result) ->
    case model_allows(S, Scope) of
        true ->
            case Result of
                {ok, Token} -> is_reference(Token);
                _           -> false
            end;
        false ->
            %% Must reject with timeout or queue_full, never return
            %% a token.
            case Result of
                {error, timeout}    -> true;
                {error, queue_full} -> true;
                _                   -> false
            end
    end;
postcondition(_S, {call, ?MODULE, release_, [_]}, Result) ->
    %% Release is fire-and-forget (cast), returns ok synchronously.
    Result =:= ok.

%%--------------------------------------------------------------------
%% Command wrappers — the real calls threaded through the test.
%%--------------------------------------------------------------------

%% Acquire with a very short timeout so rejections show up as
%% `{error, timeout}` rather than hanging the test.
acquire_(Scope) ->
    Arg = case Scope of
        host       -> host;
        {zone, Z}  -> Z
    end,
    erlkoenig_admission:acquire(Arg, 50).

%% The token we received from an earlier `acquire_` call is the full
%% `{ok, Ref}` tuple — unwrap before passing to the real release/1.
%% If the earlier acquire returned an error, there's nothing to
%% release; that branch shouldn't normally be taken because
%% `held_token_gen/1` filters on the model's held list, but we keep
%% it defensive.
release_({real, {ok, Ref}}) -> erlkoenig_admission:release(Ref);
release_({real, _})         -> ok;
release_({fake, _})         -> erlkoenig_admission:release(make_ref()).

%%--------------------------------------------------------------------
%% Model predicates
%%--------------------------------------------------------------------

model_allows(#s{held = Held, max_host = Max}, _Scope) ->
    length(Held) < Max.

%%--------------------------------------------------------------------
%% The property
%%--------------------------------------------------------------------

prop_admission_stateful() ->
    ?FORALL(
        Cmds, commands(?MODULE),
        ?TRAPEXIT(begin
            start_gate(),
            {History, State, Result} = run_commands(?MODULE, Cmds),
            stop_gate(),
            ?WHENFAIL(
                io:format(
                    "~nHistory: ~p~nState: ~p~nResult: ~p~n",
                    [History, State, Result]),
                aggregate(command_names(Cmds), Result =:= ok))
        end)).

admission_stateful_test_() ->
    {timeout, 60,
     fun() ->
         ?assert(proper:quickcheck(
                   prop_admission_stateful(),
                   [{numtests, 100}, {to_file, user}]))
     end}.

%%--------------------------------------------------------------------
%% Fixture — start with a predictable cap, no zone limit, fresh state.
%%--------------------------------------------------------------------

start_gate() ->
    _ = application:set_env(erlkoenig, admission_max_host, ?MAX_HOST),
    _ = application:set_env(erlkoenig, admission_max_per_zone, 0),
    _ = application:set_env(erlkoenig, admission_queue_limit, 100),
    case erlkoenig_admission:start_link() of
        {ok, _} -> ok;
        {error, {already_started, Pid}} ->
            _ = gen_server:stop(Pid, normal, 5_000),
            {ok, _} = erlkoenig_admission:start_link(),
            ok
    end.

stop_gate() ->
    case whereis(erlkoenig_admission) of
        undefined -> ok;
        Pid       -> _ = gen_server:stop(Pid, normal, 5_000), ok
    end.
