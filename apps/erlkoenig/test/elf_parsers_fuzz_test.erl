%%%-------------------------------------------------------------------
%%% @doc ELF-content parsers fuzz.
%%%
%%% All of these run on the container binary before spawn (signature
%%% verification, language detection, syscall analysis).  If any
%%% crashes on a crafted ELF, container spawn fails hard.
%%% @end
%%%-------------------------------------------------------------------

-module(elf_parsers_fuzz_test).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(nowarn_unused_function).

x86_64_decode_all_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_x86_64_decode_all_safe(),
                 [{numtests, 1000}, {to_file, user}, noshrink])
    end}.

x86_64_decode_one_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_x86_64_decode_one_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

aarch64_decode_all_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_aarch64_decode_all_safe(),
                 [{numtests, 1000}, {to_file, user}, noshrink])
    end}.

prop_x86_64_decode_all_safe() ->
    ?FORALL(Bin, sized_binary(0, 256),
        run_safely(fun() -> elf_decode_x86_64:decode_all(Bin) end, Bin)).

prop_x86_64_decode_one_safe() ->
    ?FORALL({Bin, Off}, {sized_binary(0, 64), proper_types:choose(0, 32)},
        run_safely(fun() -> elf_decode_x86_64:decode(Bin, Off) end,
                   {Bin, Off})).

prop_aarch64_decode_all_safe() ->
    ?FORALL(Bin, sized_binary(0, 256),
        run_safely(fun() -> elf_decode_aarch64:decode_all(Bin) end, Bin)).

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

sized_binary(Min, Max) ->
    ?LET(N, proper_types:choose(Min, Max), proper_types:binary(N)).
