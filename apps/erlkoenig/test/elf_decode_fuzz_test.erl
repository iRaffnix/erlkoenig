%%%-------------------------------------------------------------------
%%% @doc Instruction-decoder fuzz (x86_64 + aarch64).
%%%
%%% decode_all / extract_syscalls run over attacker-controlled .text
%%% bytes during container-binary analysis (syscall surface, seccomp
%%% policy synthesis).  A crash here aborts the static sandbox audit.
%%% @end
%%%-------------------------------------------------------------------

-module(elf_decode_fuzz_test).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(nowarn_unused_function).

x86_64_decode_all_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_x86_64_decode_all_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

x86_64_extract_syscalls_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_x86_64_extract_syscalls_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

x86_64_decode_single_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_x86_64_decode_single_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

aarch64_decode_all_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_aarch64_decode_all_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

aarch64_extract_syscalls_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_aarch64_extract_syscalls_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

aarch64_decode_single_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_aarch64_decode_single_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

%% -------------------------------------------------------------------

prop_x86_64_decode_all_safe() ->
    ?FORALL(Bin, ?LET(N, proper_types:choose(0, 512),
                      proper_types:binary(N)),
        run_safely(fun() -> elf_decode_x86_64:decode_all(Bin) end, Bin)).

prop_x86_64_extract_syscalls_safe() ->
    ?FORALL(Bin, ?LET(N, proper_types:choose(0, 512),
                      proper_types:binary(N)),
        run_safely(fun() -> elf_decode_x86_64:extract_syscalls(Bin) end, Bin)).

prop_x86_64_decode_single_safe() ->
    ?FORALL({Bin, Off},
            {?LET(N, proper_types:choose(0, 64),
                  proper_types:binary(N)),
             proper_types:choose(0, 80)},
        run_safely(fun() -> elf_decode_x86_64:decode(Bin, Off) end, {Bin, Off})).

prop_aarch64_decode_all_safe() ->
    ?FORALL(Bin, ?LET(N, proper_types:choose(0, 512),
                      proper_types:binary(N)),
        run_safely(fun() -> elf_decode_aarch64:decode_all(Bin) end, Bin)).

prop_aarch64_extract_syscalls_safe() ->
    ?FORALL(Bin, ?LET(N, proper_types:choose(0, 512),
                      proper_types:binary(N)),
        run_safely(fun() -> elf_decode_aarch64:extract_syscalls(Bin) end, Bin)).

prop_aarch64_decode_single_safe() ->
    ?FORALL({Bin, Off},
            {?LET(N, proper_types:choose(0, 64),
                  proper_types:binary(N)),
             proper_types:choose(0, 80)},
        run_safely(fun() -> elf_decode_aarch64:decode(Bin, Off) end, {Bin, Off})).

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
