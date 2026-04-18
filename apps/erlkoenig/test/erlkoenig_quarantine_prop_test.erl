%%%-------------------------------------------------------------------
%%% @doc Stateful property-based tests for erlkoenig_quarantine.
%%%
%%% Uses `proper_statem` to exercise the crashloop circuit breaker
%%% with random sequences of crash recordings, manual quarantines,
%%% unquarantines, and check-gate queries against a fixed pool of
%%% test binaries.
%%%
%%% Covered invariants:
%%%
%%%   1. A hash stays quarantined until explicitly unquarantined —
%%%      no command sequence can auto-lift it, except disabling the
%%%      whole module (out of scope for this property).
%%%   2. `check/1` returns an error iff the binary's hash is in the
%%%      quarantine set.
%%%   3. Manual quarantine wins over everything: even a binary with
%%%      zero recorded crashes becomes quarantined.
%%%   4. Unquarantine is idempotent and fire-and-forget: repeating
%%%      it is safe and leaves the set unchanged.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_quarantine_prop_test).

-compile(nowarn_unused_function).

-behaviour(proper_statem).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([command/1, initial_state/0, next_state/3,
         precondition/2, postcondition/3]).

%% Commands exported so {call, ?MODULE, ...} resolves.
-export([record_crash_/1, manual_quarantine_/1, unquarantine_/1,
         check_/1, is_quarantined_/1]).

%%--------------------------------------------------------------------
%% Fixture: a pool of three test binaries we pass around by name.
%% Each binary is random bytes, each maps to a distinct SHA-256.
%%--------------------------------------------------------------------

-define(BIN_A, <<"bin_a">>).
-define(BIN_B, <<"bin_b">>).
-define(BIN_C, <<"bin_c">>).

-define(THRESHOLD, 3).
%% Very long window so the model's simple count-based reasoning
%% matches the real system's timestamp-based reasoning: any crash
%% inside one test run is within-window.
-define(WINDOW_MS, 3_600_000).

-record(s, {
    %% Model belief about which hashes are quarantined.
    q      :: sets:set(binary()),
    %% Crash count per hash since the start of this test run.
    counts :: #{binary() => non_neg_integer()}
}).

%%--------------------------------------------------------------------
%% Commands
%%--------------------------------------------------------------------

bin_name() -> oneof([?BIN_A, ?BIN_B, ?BIN_C]).

command(_S) ->
    oneof([
        {call, ?MODULE, record_crash_,     [bin_name()]},
        {call, ?MODULE, manual_quarantine_, [bin_name()]},
        {call, ?MODULE, unquarantine_,      [bin_name()]},
        {call, ?MODULE, check_,             [bin_name()]},
        {call, ?MODULE, is_quarantined_,    [bin_name()]}
    ]).

%%--------------------------------------------------------------------
%% Model
%%--------------------------------------------------------------------

initial_state() ->
    #s{q = sets:new([{version, 2}]), counts = #{}}.

precondition(_, _) -> true.

next_state(S, _Result, {call, ?MODULE, record_crash_, [BinName]}) ->
    Hash = hash_of(BinName),
    N = maps:get(Hash, S#s.counts, 0) + 1,
    %% Crashloop auto-quarantine: once the count crosses the
    %% threshold, add the hash to the quarantine set. Past that,
    %% further crashes leave the set unchanged (already there).
    Q2 = case N >= ?THRESHOLD of
        true  -> sets:add_element(Hash, S#s.q);
        false -> S#s.q
    end,
    S#s{counts = (S#s.counts)#{Hash => N}, q = Q2};
next_state(S, _Result, {call, ?MODULE, manual_quarantine_, [BinName]}) ->
    Hash = hash_of(BinName),
    S#s{q = sets:add_element(Hash, S#s.q)};
next_state(S, _Result, {call, ?MODULE, unquarantine_, [BinName]}) ->
    Hash = hash_of(BinName),
    %% Unquarantine removes the hash from the set but does NOT
    %% reset the crash counter — a further crash above threshold
    %% will immediately re-quarantine. Matches observe_crash/2.
    S#s{q = sets:del_element(Hash, S#s.q)};
next_state(S, _Result, _Command) ->
    %% check/is_quarantined are pure queries.
    S.

postcondition(S, {call, ?MODULE, check_, [BinName]}, Result) ->
    Hash = hash_of(BinName),
    case sets:is_element(Hash, S#s.q) of
        true ->
            case Result of
                {error, {quarantined, Hash, _Since}} -> true;
                _ -> false
            end;
        false ->
            Result =:= ok
    end;
postcondition(S, {call, ?MODULE, is_quarantined_, [BinName]}, Result) ->
    Hash = hash_of(BinName),
    case sets:is_element(Hash, S#s.q) of
        true  ->
            case Result of
                {true, _Since} -> true;
                _ -> false
            end;
        false -> Result =:= false
    end;
postcondition(_, _, _) ->
    %% record_crash / manual_quarantine / unquarantine all return ok
    %% — we trust the synchronous return. The behaviour that matters
    %% is observable via check/is_quarantined above.
    true.

%%--------------------------------------------------------------------
%% Command wrappers
%%--------------------------------------------------------------------

record_crash_(BinName) ->
    erlkoenig_quarantine:record_crash(path_of(BinName)).

manual_quarantine_(BinName) ->
    erlkoenig_quarantine:quarantine(hash_of(BinName), test).

unquarantine_(BinName) ->
    erlkoenig_quarantine:unquarantine(hash_of(BinName)).

check_(BinName) ->
    erlkoenig_quarantine:check(path_of(BinName)).

is_quarantined_(BinName) ->
    erlkoenig_quarantine:is_quarantined(hash_of(BinName)).

%%--------------------------------------------------------------------
%% Hash & path helpers
%%--------------------------------------------------------------------

path_of(?BIN_A) -> get({path, ?BIN_A});
path_of(?BIN_B) -> get({path, ?BIN_B});
path_of(?BIN_C) -> get({path, ?BIN_C}).

hash_of(?BIN_A) -> get({hash, ?BIN_A});
hash_of(?BIN_B) -> get({hash, ?BIN_B});
hash_of(?BIN_C) -> get({hash, ?BIN_C}).

%%--------------------------------------------------------------------
%% Fixture setup: write three random binaries to /tmp, stash path +
%% hash in the process dictionary for the command wrappers.
%%--------------------------------------------------------------------

setup_fixture() ->
    lists:foreach(
        fun(Name) ->
            TsSuffix = integer_to_list(erlang:system_time(nanosecond)),
            Path = iolist_to_binary(
                ["/tmp/eunit_qtn_prop_", binary_to_list(Name),
                 "_", TsSuffix, ".bin"]),
            ok = file:write_file(binary_to_list(Path),
                                 crypto:strong_rand_bytes(128)),
            put({path, Name}, Path),
            {ok, Hash} = erlkoenig_sig:hash_file(Path),
            put({hash, Name}, Hash)
        end,
        [?BIN_A, ?BIN_B, ?BIN_C]).

teardown_fixture() ->
    lists:foreach(
        fun(Name) ->
            case get({path, Name}) of
                undefined -> ok;
                Path      -> _ = file:delete(binary_to_list(Path))
            end
        end,
        [?BIN_A, ?BIN_B, ?BIN_C]).

start_q() ->
    _ = application:set_env(erlkoenig, quarantine_enabled,   true),
    _ = application:set_env(erlkoenig, quarantine_threshold, ?THRESHOLD),
    _ = application:set_env(erlkoenig, quarantine_window_ms, ?WINDOW_MS),
    case erlkoenig_quarantine:start_link() of
        {ok, _} -> ok;
        {error, {already_started, Pid}} ->
            _ = gen_server:stop(Pid, normal, 5_000),
            {ok, _} = erlkoenig_quarantine:start_link(),
            ok
    end.

stop_q() ->
    case whereis(erlkoenig_quarantine) of
        undefined -> ok;
        Pid -> _ = gen_server:stop(Pid, normal, 5_000), ok
    end.

%%--------------------------------------------------------------------
%% Property
%%--------------------------------------------------------------------

prop_quarantine_stateful() ->
    ?FORALL(
        Cmds, commands(?MODULE),
        ?TRAPEXIT(begin
            setup_fixture(),
            start_q(),
            {History, State, Result} = run_commands(?MODULE, Cmds),
            stop_q(),
            teardown_fixture(),
            ?WHENFAIL(
                io:format(
                    "~nHistory: ~p~nState: ~p~nResult: ~p~n",
                    [History, State, Result]),
                aggregate(command_names(Cmds), Result =:= ok))
        end)).

quarantine_stateful_test_() ->
    {timeout, 60,
     fun() ->
         ?assert(proper:quickcheck(
                   prop_quarantine_stateful(),
                   [{numtests, 100}, {to_file, user}]))
     end}.
