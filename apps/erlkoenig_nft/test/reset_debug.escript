#!/usr/bin/env escript
%%! -pa _build/default/lib/erlkoenig_nft/ebin

-define(INET, 1).

main(_) ->
    {ok, Sock} = nfnl_socket:open(),

    %% Build GETOBJ_RESET message manually
    Attrs = iolist_to_binary([
        nfnl_attr:encode_str(1, <<"nctest">>),
        nfnl_attr:encode_str(2, <<"ssh_pkts">>),
        nfnl_attr:encode_u32(3, 1)
    ]),
    Msg = nfnl_msg:build_hdr(21, ?INET, 16#0001 bor 16#0004, 999, Attrs),

    ok = nfnl_socket:send(Sock, Msg),

    %% Read first response
    {ok, Data1} = nfnl_socket:recv(Sock),
    <<Len1:32/little, Type1:16/little, Flags1:16/little, _:64, _/binary>> = Data1,
    io:format("Response 1: len=~B type=~B (subsys=~B msg=~B) flags=~.16B~n",
              [Len1, Type1, Type1 bsr 8, Type1 band 16#FF, Flags1]),
    io:format("Raw: ~p~n~n", [Data1]),

    %% Try second response
    case nfnl_socket:recv(Sock, 1000) of
        {ok, Data2} ->
            <<Len2:32/little, Type2:16/little, _:16/little, _/binary>> = Data2,
            io:format("Response 2: len=~B type=~B~n", [Len2, Type2]),
            io:format("Raw: ~p~n", [Data2]);
        {error, timeout} ->
            io:format("No second response~n")
    end,

    nfnl_socket:close(Sock).
