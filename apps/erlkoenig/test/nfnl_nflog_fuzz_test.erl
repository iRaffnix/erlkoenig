%%%-------------------------------------------------------------------
%%% @doc NFLOG packet parser fuzz.
%%%
%%% The NFLOG datapath receives raw packets that triggered nftables
%%% drop rules — the packet headers come straight from the wire.
%%% An attacker landing a crafted packet at a monitored port can
%%% supply malformed IPv4/IPv6 headers.
%%%
%%% Hot spots (read prior to fuzzing):
%%%   1. `<<_:4/binary, AttrBin/binary>> = Payload` in
%%%      process_messages — badmatch if Payload < 4 bytes.
%%%   2. `HeaderLen = IHL*4; Skip = HeaderLen - 20` — if IHL < 5,
%%%      Skip is negative → bit-size with negative length crashes.
%%%
%%% Both are DoS primitives against the threat_mesh feed.
%%% @end
%%%-------------------------------------------------------------------

-module(nfnl_nflog_fuzz_test).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(nowarn_unused_function).

-define(NFULA_PAYLOAD, 9).
-define(NFULA_PREFIX, 10).
-define(NFULA_IFINDEX_INDEV, 4).

parse_ip_arbitrary_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_parse_ip_arbitrary_safe(),
                 [{numtests, 1000}, {to_file, user}, noshrink])
    end}.

parse_ip_small_ihl_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_parse_ipv4_small_ihl_safe(),
                 [{numtests, 100}, {to_file, user}])
    end}.

parse_packet_arbitrary_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_parse_packet_arbitrary_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

process_messages_arbitrary_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_process_messages_arbitrary_safe(),
                 [{numtests, 1000}, {to_file, user}, noshrink])
    end}.

%% -------------------------------------------------------------------

prop_parse_ip_arbitrary_safe() ->
    ?FORALL(Bin, proper_types:binary(),
        run_safely(fun() ->
            erlkoenig_nft_nflog:parse_ip_packet(#{}, Bin)
        end, Bin)).

prop_parse_ipv4_small_ihl_safe() ->
    ?FORALL(IHL, proper_types:choose(0, 4),
        begin
            Pkt = <<4:4, IHL:4,
                    0:8, 100:16/big, 0:16, 0:16,
                    64:8, 6:8, 0:16,
                    10, 0, 0, 1,
                    10, 0, 0, 2,
                    0:16/big, 80:16/big,
                    0:32>>,
            run_safely(fun() ->
                erlkoenig_nft_nflog:parse_ip_packet(#{}, Pkt)
            end, {ihl, IHL})
        end).

prop_parse_packet_arbitrary_safe() ->
    ?FORALL(Attrs, attrs_gen(),
        run_safely(fun() ->
            erlkoenig_nft_nflog:parse_packet(Attrs)
        end, Attrs)).

prop_process_messages_arbitrary_safe() ->
    ?FORALL(Bin, proper_types:binary(),
        run_safely(fun() ->
            erlkoenig_nft_nflog:process_messages(Bin)
        end, Bin)).

%% -------------------------------------------------------------------

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
            io:format(user, "CRASH ~p:~p on ~p~n", [C, E, Label]),
            false
    after 2000 ->
        exit(Pid, kill),
        io:format(user, "parse hung on ~p~n", [Label]),
        false
    end.

attrs_gen() ->
    ?LET(N, proper_types:choose(0, 6),
         vector(N, attr_gen())).

attr_gen() ->
    proper_types:oneof([
        ?LET(B, sized_binary(0, 80),
             {proper_types:choose(1, 10), B}),
        ?LET(Idx, proper_types:choose(0, 16#ffffffff),
             {?NFULA_IFINDEX_INDEV, <<Idx:32/big>>}),
        ?LET(P, sized_binary(0, 40),
             {?NFULA_PREFIX, P}),
        ?LET(Pkt, sized_binary(0, 120),
             {?NFULA_PAYLOAD, Pkt})
    ]).

make_vector(N, Gen) -> [Gen || _ <- lists:seq(1, N)].

sized_binary(Min, Max) ->
    ?LET(N, proper_types:choose(Min, Max), proper_types:binary(N)).
