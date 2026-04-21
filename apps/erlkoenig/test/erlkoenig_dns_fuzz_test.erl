%%%-------------------------------------------------------------------
%%% @doc DNS parser fuzz — attacker-adjacent surface.
%%%
%%% `erlkoenig_dns:decode_query/1` parses raw DNS query packets from
%%% the container-facing resolver socket.  Anything a container can
%%% fit into a 65535-byte UDP datagram lands here.
%%%
%%% Known-suspicious targets:
%%%   - Pointer compression in decode_name: recursive pointer
%%%     following without loop detection ⇒ stack overflow via
%%%     self-referential or cyclic pointers.
%%%   - Truncated/lying length labels.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_dns_fuzz_test).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(nowarn_unused_function).

decode_query_arbitrary_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_decode_query_arbitrary_safe(),
                 [{numtests, 2000}, {to_file, user}, noshrink])
    end}.

decode_name_pointer_loop_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_decode_name_pointer_loop_safe(),
                 [{numtests, 50}, {to_file, user}])
    end}.

prop_decode_query_arbitrary_safe() ->
    ?FORALL(Bin, dns_packet_gen(),
        run_safely(fun() -> erlkoenig_dns:decode_query(Bin) end, Bin)).

%% Craft a DNS packet whose Question section contains a pointer
%% back to itself — the classic compression-pointer loop DoS.
prop_decode_name_pointer_loop_safe() ->
    ?FORALL(_Junk, ?LET(N, proper_types:choose(0, 4), proper_types:binary(N)),
        begin
            %% 12-byte header + pointer to offset 12 (= pointer
            %% points back at itself, infinite loop if followed).
            %% Pointer: 11 high bits = 0b11, 14 bits = 12.
            PtrToSelf = <<16#C0, 12>>,
            Pkt = <<16#1234:16, 16#0100:16, 1:16, 0:16, 0:16, 0:16,
                    PtrToSelf/binary,
                    1:16, 1:16>>,     %% QTYPE=A, QCLASS=IN
            run_safely(fun() ->
                erlkoenig_dns:decode_query(Pkt)
            end, {pointer_loop, Pkt})
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
            io:format(user, "CRASH ~p:~p on ~p~n", [C, E, Label]),
            false
    after 3000 ->
        exit(Pid, kill),
        io:format(user, "TIMEOUT / infinite-loop on ~p~n", [Label]),
        false
    end.

%% Generator: plausible-looking DNS packets — header + random body.
dns_packet_gen() ->
    ?LET({Id, Flags, Qd, Body},
         {proper_types:choose(0, 65535),
          proper_types:choose(0, 65535),
          proper_types:choose(0, 5),
          ?LET(N, proper_types:choose(0, 200),
               proper_types:binary(N))},
        <<Id:16, Flags:16, Qd:16, 0:16, 0:16, 0:16, Body/binary>>).
