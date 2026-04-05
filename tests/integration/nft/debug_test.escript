#!/usr/bin/env escript
%%! -pa _build/default/lib/erlkoenig/ebin

-define(NFPROTO_INET, 1).
-define(AF_NETLINK, 16).

main(_) ->
    os:cmd("nft delete table inet debug1 2>/dev/null"),
    os:cmd("nft delete table inet debug2 2>/dev/null"),

    Seq = erlang:system_time(second),

    %% Method 1: old way (inline batch) - manually build like smoke_test
    Attrs1 = iolist_to_binary([
        nfnl_attr:encode_str(1, <<"debug1">>),
        nfnl_attr:encode_u32(2, 0)
    ]),
    Msg1 = nfnl_msg:build_hdr(0, ?NFPROTO_INET, 16#0405, Seq + 1, Attrs1),
    Batch1 = iolist_to_binary([
        nfnl_msg:batch_begin(Seq),
        Msg1,
        nfnl_msg:batch_end(Seq + 2)
    ]),

    %% Method 2: new way (nft_batch:wrap)
    Msg2 = nft_table:add(?NFPROTO_INET, <<"debug2">>, Seq + 11),
    Batch2 = nft_batch:wrap([Msg2], Seq + 10),

    io:format("Batch1 (~w bytes): ~s~n~n", [byte_size(Batch1), hex(Batch1)]),
    io:format("Batch2 (~w bytes): ~s~n~n", [byte_size(Batch2), hex(Batch2)]),

    %% Send batch1
    {ok, S1} = socket:open(?AF_NETLINK, raw, 12),
    ok = socket:bind(S1, #{family => ?AF_NETLINK, addr => <<16:16/native, 0:16, 0:32, 0:32>>}),
    Dest = #{family => ?AF_NETLINK, addr => <<16:16/native, 0:16, 0:32, 0:32>>},
    R1 = socket:sendto(S1, Batch1, Dest),
    io:format("Send batch1: ~p~n", [R1]),
    case socket:recv(S1, 0, 3000) of
        {ok, D1} -> io:format("Recv batch1: ~w bytes~n", [byte_size(D1)]);
        E1 -> io:format("Recv batch1: ~p~n", [E1])
    end,
    socket:close(S1),

    %% Send batch2
    {ok, S2} = socket:open(?AF_NETLINK, raw, 12),
    ok = socket:bind(S2, #{family => ?AF_NETLINK, addr => <<16:16/native, 0:16, 0:32, 0:32>>}),
    R2 = socket:sendto(S2, Batch2, Dest),
    io:format("Send batch2: ~p~n", [R2]),
    case socket:recv(S2, 0, 3000) of
        {ok, D2} -> io:format("Recv batch2: ~w bytes~n", [byte_size(D2)]);
        E2 -> io:format("Recv batch2: ~p~n", [E2])
    end,
    socket:close(S2),

    io:format("~n~s", [os:cmd("nft list ruleset")]).

hex(Bin) ->
    lists:flatten([io_lib:format("~2.16.0B", [B]) || <<B>> <= Bin]).
