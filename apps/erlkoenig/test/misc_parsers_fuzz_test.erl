%%%-------------------------------------------------------------------
%%% @doc Sweep fuzz over remaining small parsers.
%%%
%%% These are internal / low-surface but still binary-input
%%% consumers.  Catching crashes here prevents cgroup accounting
%%% losses + unexpected aborts in config processing.
%%% @end
%%%-------------------------------------------------------------------

-module(misc_parsers_fuzz_test).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(nowarn_unused_function).

cgroup_parsers_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_cgroup_parsers_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

dns_filter_compile_one_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_dns_filter_compile_one_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

config_parse_container_name_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_parse_container_name_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

%% ----------------------------------------------------------------

prop_cgroup_parsers_safe() ->
    ?FORALL(Bin, proper_types:binary(),
        begin
            Fs = [
                fun() -> erlkoenig_cgroup:parse_memtotal(Bin) end,
                fun() -> erlkoenig_cgroup:parse_cpu_usage(Bin) end,
                fun() -> erlkoenig_cgroup:parse_oom_kill(Bin) end,
                fun() -> erlkoenig_cgroup:parse_pressure_some(Bin) end,
                fun() -> erlkoenig_cgroup:parse_cpu_stat_full(Bin, #{}) end,
                fun() -> erlkoenig_cgroup:parse_memory_events(Bin, #{}) end
            ],
            lists:all(fun(F) -> run_safely(F, Bin) end, Fs)
        end).

prop_dns_filter_compile_one_safe() ->
    ?FORALL(Bin, proper_types:binary(),
        run_safely(fun() -> erlkoenig_dns_filter:compile_one(Bin) end, Bin)).

prop_parse_container_name_safe() ->
    ?FORALL(Bin, proper_types:binary(),
        run_safely(fun() -> erlkoenig_config_nft:parse_container_name(Bin) end,
                   Bin)).

%% ----------------------------------------------------------------

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
