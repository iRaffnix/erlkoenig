%%%-------------------------------------------------------------------
%%% @doc Kernel event + mount-opt parser fuzz.
%%%
%%% Attacker / kernel-adjacent surfaces not previously fuzzed:
%%%   - erlkoenig_nft_nflog:parse_packet/1
%%%   - erlkoenig_nft_nflog:parse_ip_packet/2   (IPv4 + IPv6)
%%%   - erlkoenig_nft_ct:parse_ct_event/1
%%%   - erlkoenig_steering:decode_attrs/1
%%%   - erlkoenig_mount_opts:parse/1
%%% @end
%%%-------------------------------------------------------------------

-module(kernel_event_fuzz_test).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(nowarn_unused_function).

nflog_parse_packet_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_nflog_parse_packet_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

nflog_parse_ip_packet_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_nflog_parse_ip_packet_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

nft_ct_parse_ct_event_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_nft_ct_parse_ct_event_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

steering_decode_attrs_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_steering_decode_attrs_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

mount_opts_parse_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_mount_opts_parse_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

%% -------------------------------------------------------------------

prop_nflog_parse_packet_safe() ->
    ?FORALL(Attrs, attrs_list_gen(),
        run_safely(fun() -> erlkoenig_nft_nflog:parse_packet(Attrs) end, Attrs)).

prop_nflog_parse_ip_packet_safe() ->
    ?FORALL(Bin, ?LET(N, proper_types:choose(0, 128),
                      proper_types:binary(N)),
        run_safely(fun() ->
            erlkoenig_nft_nflog:parse_ip_packet(#{}, Bin)
        end, Bin)).

prop_nft_ct_parse_ct_event_safe() ->
    ?FORALL(Attrs, attrs_list_gen(),
        run_safely(fun() -> erlkoenig_nft_ct:parse_ct_event(Attrs) end, Attrs)).

prop_steering_decode_attrs_safe() ->
    ?FORALL(Bin, ?LET(N, proper_types:choose(0, 256),
                      proper_types:binary(N)),
        run_safely(fun() -> erlkoenig_steering:decode_attrs(Bin) end, Bin)).

prop_mount_opts_parse_safe() ->
    ?FORALL(Bin, ?LET(N, proper_types:choose(0, 128),
                      proper_types:binary(N)),
        run_safely(fun() -> erlkoenig_mount_opts:parse(Bin) end, Bin)).

%% -------------------------------------------------------------------

attrs_list_gen() ->
    ?LET(N, proper_types:choose(0, 8),
         [attr_entry() || _ <- lists:seq(1, N)]).

attr_entry() ->
    ?LET({K, V},
         {proper_types:choose(1, 32),
          ?LET(N, proper_types:choose(0, 32),
               proper_types:binary(N))},
         {K, V}).

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
