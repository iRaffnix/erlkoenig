%%%-------------------------------------------------------------------
%%% @doc Audit-chain integrity fuzz.
%%%
%%% The audit log is tamper-evident via a SHA-256 hash chain + optional
%%% Ed25519 signatures.  A malformed log line (corruption, partial
%%% write, attacker injection) must:
%%%   1. NEVER crash the verifier — it must return {error, ErrorMap}
%%%      with an audit code cleanly
%%%   2. NEVER succeed when the chain is actually broken
%%%
%%% Targets:
%%%   - `verify_chain/1` over random binary files
%%%   - `canonical_json/1` over arbitrary Erlang terms
%%%   - `compute_this_hash/1` over partial event maps
%%%   - `hex_to_bin/1` — we know parse_git_sha had issues here
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_audit_fuzz_test).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(nowarn_unused_function).

verify_chain_arbitrary_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_verify_chain_arbitrary_safe(),
                 [{numtests, 300}, {to_file, user}, noshrink])
    end}.

canonical_json_arbitrary_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_canonical_json_safe(),
                 [{numtests, 1000}, {to_file, user}, noshrink])
    end}.

compute_this_hash_safe_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_compute_this_hash_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

hex_to_bin_safe_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_hex_to_bin_safe(),
                 [{numtests, 1000}, {to_file, user}, noshrink])
    end}.

chain_mutation_detected_test_() ->
    {timeout, 120, fun() ->
        true = proper:quickcheck(
                 prop_chain_mutation_detected(),
                 [{numtests, 50}, {to_file, user}])
    end}.

%% Random bytes written as a "log file".  verify_chain MUST return
%% either {ok, N} (for genuine valid prefix) or tagged error, never
%% raise.
prop_verify_chain_arbitrary_safe() ->
    ?FORALL(Bin, ?LET(N, proper_types:choose(0, 1024),
                      proper_types:binary(N)),
        begin
            Path = tmp_log_path(),
            ok = file:write_file(Path, Bin),
            R = try erlkoenig_audit:verify_chain(Path) of
                    {ok, N2} when is_integer(N2) -> ok_tagged;
                    {error, _} -> ok_tagged;
                    Other -> {unexpected, Other}
                catch C:E:_ -> {crash, C, E}
                end,
            _ = file:delete(Path),
            case R of
                ok_tagged -> true;
                Bad ->
                    io:format(user, "verify_chain crashed: ~p on ~p bytes~n",
                              [Bad, byte_size(Bin)]),
                    false
            end
        end).

%% canonical_json must not crash on any Erlang term that audit events
%% could plausibly contain.
prop_canonical_json_safe() ->
    ?FORALL(Term, audit_value_gen(),
        run_safely(fun() -> erlkoenig_audit:canonical_json(Term) end, Term)).

%% compute_this_hash takes a map and returns a hex-encoded binary.
%% The map shape varies across schema versions and external inputs
%% — the function must be total.
prop_compute_this_hash_safe() ->
    ?FORALL(EventMap, event_map_gen(),
        run_safely(fun() ->
            erlkoenig_audit:compute_this_hash(EventMap)
        end, EventMap)).

%% hex_to_bin is allowed to raise {bad_hex, _} — callers already
%% expect and catch that.  Property: EVERY raise is the tagged one,
%% not function_clause / badarg / anything else.
prop_hex_to_bin_safe() ->
    ?FORALL(Bin, ?LET(N, proper_types:choose(0, 128),
                      proper_types:binary(N)),
        begin
            Self = self(),
            Pid = spawn(fun() ->
                R = try erlkoenig_audit:hex_to_bin(Bin) of
                        V -> {ok, V}
                    catch
                        error:{bad_hex, _} -> ok_tagged_error;
                        error:{bad_hex, _, _} -> ok_tagged_error;
                        C:E:_ -> {crash, C, E}
                    end,
                Self ! {self(), R}
            end),
            receive
                {Pid, {ok, _}} -> true;
                {Pid, ok_tagged_error} -> true;
                {Pid, {crash, C, E}} ->
                    io:format(user,
                              "hex_to_bin raised untagged ~p:~p on ~p~n",
                              [C, E, Bin]),
                    false
            after 2000 ->
                exit(Pid, kill), false
            end
        end).

%% Chain-integrity property: build a real hash-chained log, then
%% MUTATE one byte somewhere after line 1.  Every mutation must be
%% detected.  If a mutation passes verify_chain, the tamper-evidence
%% guarantee is broken.
prop_chain_mutation_detected() ->
    ?FORALL({NumEvents, MutAtLine},
            {proper_types:choose(2, 8), proper_types:choose(2, 8)},
        ?IMPLIES(MutAtLine =< NumEvents,
        begin
            %% Build a well-formed chain via compute_this_hash.
            Lines = build_chain(NumEvents),
            Path  = tmp_log_path(),
            %% Baseline: unmutated file must verify cleanly.
            ok = file:write_file(Path, iolist_to_binary(
                [[L, "\n"] || L <- Lines])),
            {ok, NumEvents} = erlkoenig_audit:verify_chain(Path),

            %% Mutate one byte in line `MutAtLine`.
            {Before, [Target | After]} =
                lists:split(MutAtLine - 1, Lines),
            Mutated = mutate_byte(Target),
            MutLines = Before ++ [Mutated | After],
            ok = file:write_file(Path, iolist_to_binary(
                [[L, "\n"] || L <- MutLines])),

            Result = erlkoenig_audit:verify_chain(Path),
            _ = file:delete(Path),

            case Result of
                {error, #{code := 'EK_AUDIT_CHAIN_BROKEN'}} -> true;
                {error, #{code := 'EK_AUDIT_SIGNATURE_INVALID'}} -> true;
                {ok, _} ->
                    io:format(user,
                              "MUTATION NOT DETECTED at line ~p of ~p~n"
                              "  Orig: ~s~n"
                              "  Mut:  ~s~n",
                              [MutAtLine, NumEvents, Target, Mutated]),
                    false;
                Other ->
                    io:format(user, "verify_chain unexpected: ~p~n",
                              [Other]),
                    false
            end
        end)).

-define(GENESIS,
  <<"0000000000000000000000000000000000000000000000000000000000000000">>).

build_chain(N) -> build_chain_loop(N, ?GENESIS, 1, []).
build_chain_loop(0, _Prev, _I, Acc) -> lists:reverse(Acc);
build_chain_loop(N, Prev, I, Acc) ->
    Event0 = #{<<"v">> => 1, <<"type">> => <<"test">>,
               <<"seq">> => I, <<"prev_hash">> => Prev},
    ThisHash = erlkoenig_audit:compute_this_hash(Event0),
    Event = Event0#{<<"this_hash">> => ThisHash},
    Line = iolist_to_binary(json:encode(Event)),
    build_chain_loop(N - 1, ThisHash, I + 1, [Line | Acc]).

mutate_byte(Bin) when byte_size(Bin) > 0 ->
    Sz = byte_size(Bin),
    Pos = Sz div 2,
    <<A:Pos/binary, B, Rest/binary>> = Bin,
    Flipped = B bxor 16#20,  %% flip case / whitespace distinction
    <<A/binary, Flipped, Rest/binary>>.

%% -------------------------------------------------------------------

run_safely(F, Label) ->
    Self = self(),
    Pid = spawn(fun() ->
        R = try F() of V -> {ok, V}
            catch C:E:_ -> {crash, C, E}
            end,
        Self ! {self(), R}
    end),
    receive
        {Pid, {ok, _}} -> true;
        {Pid, {crash, C, E}} ->
            io:format(user, "CRASH ~p:~p on ~p~n", [C, E, Label]),
            false
    after 2000 ->
        exit(Pid, kill),
        io:format(user, "TIMEOUT on ~p~n", [Label]),
        false
    end.

tmp_log_path() ->
    lists:flatten(io_lib:format("/tmp/ek_audit_fuzz_~p.jsonl",
                                [erlang:unique_integer([positive])])).

audit_value_gen() ->
    proper_types:oneof([
        proper_types:integer(),
        proper_types:boolean(),
        proper_types:atom(),
        ?LET(N, proper_types:choose(0, 40),
             proper_types:binary(N)),
        proper_types:list(proper_types:integer()),
        ?LAZY(event_map_gen())
    ]).

event_map_gen() ->
    ?LET(Pairs, proper_types:list(
                  {simple_key_gen(), simple_value_gen()}),
         maps:from_list(Pairs)).

simple_key_gen() ->
    proper_types:oneof([
        <<"type">>, <<"subject">>, <<"ts">>, <<"prev_hash">>,
        <<"this_hash">>, <<"signature">>, <<"msg">>, <<"fields">>
    ]).

simple_value_gen() ->
    proper_types:oneof([
        proper_types:integer(),
        proper_types:boolean(),
        ?LET(N, proper_types:choose(0, 40),
             proper_types:binary(N))
    ]).
