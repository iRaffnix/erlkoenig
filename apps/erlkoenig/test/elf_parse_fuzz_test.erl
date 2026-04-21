%%%-------------------------------------------------------------------
%%% @doc ELF parser fuzz.
%%%
%%% `elf_parse:from_binary/1` reads the binary that's about to be
%%% spawned as a container.  The binary is operator-supplied but
%%% in a compromised-artifact scenario can be attacker-crafted.
%%%
%%% Crash here = container spawn aborts with stacktrace, or — worse —
%%% mid-boot supervisor trips, taking down unrelated workloads.
%%%
%%% ELF is a classic parser nightmare: 52-byte header, arbitrary
%%% phdr/shdr counts, wild offset fields.
%%% @end
%%%-------------------------------------------------------------------

-module(elf_parse_fuzz_test).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(nowarn_unused_function).

from_binary_arbitrary_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_from_binary_arbitrary_safe(),
                 [{numtests, 2000}, {to_file, user}, noshrink])
    end}.

from_binary_elf_magic_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_from_binary_elf_magic_safe(),
                 [{numtests, 1000}, {to_file, user}, noshrink])
    end}.

prop_from_binary_arbitrary_safe() ->
    ?FORALL(Bin, ?LET(N, proper_types:choose(0, 512),
                      proper_types:binary(N)),
        run_safely(fun() -> elf_parse:from_binary(Bin) end, Bin)).

%% Looks-like-ELF fuzz — real 4-byte magic, then random garbage.
%% This probes the post-magic-check parser paths (phdr/shdr offset
%% arithmetic), which are the suspicious ones.
prop_from_binary_elf_magic_safe() ->
    ?FORALL(Body, ?LET(N, proper_types:choose(0, 512),
                       proper_types:binary(N)),
        begin
            Bin = <<16#7f, "ELF", Body/binary>>,
            run_safely(fun() -> elf_parse:from_binary(Bin) end, Bin)
        end).

run_safely(F, Label) ->
    Self = self(),
    Pid = spawn(fun() ->
        R = try F() of
                V -> {ok, V}
            catch
                C:E:_ -> {crash, C, E}
            end,
        Self ! {self(), R}
    end),
    receive
        {Pid, {ok, _}} -> true;
        {Pid, {crash, C, E}} ->
            io:format(user, "CRASH ~p:~p on ~p bytes input (first 32: ~p)~n",
                      [C, E, byte_size(Label), binary:part(Label, 0, min(32, byte_size(Label)))]),
            false
    after 2000 ->
        exit(Pid, kill),
        io:format(user, "TIMEOUT on ~p bytes~n", [byte_size(Label)]),
        false
    end.
