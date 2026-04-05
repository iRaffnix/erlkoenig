-module(nfnl_msg_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

all() ->
    [
        batch_begin_format,
        batch_end_format,
        build_hdr_newtable,
        build_hdr_length,
        msg_type_encoding
    ].

batch_begin_format(_) ->
    Msg = nfnl_msg:batch_begin(42),
    <<20:32/little, Type:16/little, 1:16/little, 42:32/little, 0:32/little, 0:8, 0:8, 10:16/big>> =
        Msg,
    %% Type = (0 << 8) | 16 = 16
    ?assertEqual(16, Type).

batch_end_format(_) ->
    Msg = nfnl_msg:batch_end(99),
    <<20:32/little, Type:16/little, 1:16/little, 99:32/little, 0:32/little, 0:8, 0:8, 10:16/big>> =
        Msg,
    %% Type = (0 << 8) | 17 = 17
    ?assertEqual(17, Type).

build_hdr_newtable(_) ->
    Attrs = nfnl_attr:encode_str(1, <<"test">>),
    Msg = nfnl_msg:build_hdr(0, 1, 16#0405, 100, Attrs),
    <<Len:32/little, Type:16/little, 16#0405:16/little, 100:32/little, 0:32/little, 1:8, 0:8,
        0:16/big, _Attrs/binary>> = Msg,
    %% NFT_MSG_NEWTABLE=0, subsys=10: type = (10 << 8) | 0 = 2560
    ?assertEqual(2560, Type),
    ?assertEqual(byte_size(Msg), Len).

build_hdr_length(_) ->
    %% Empty attrs → 16 (nlmsghdr) + 4 (nfgenmsg) = 20
    Msg = nfnl_msg:build_hdr(0, 1, 0, 1, <<>>),
    ?assertEqual(20, byte_size(Msg)),
    <<20:32/little, _/binary>> = Msg.

msg_type_encoding(_) ->
    %% NFT_MSG_NEWCHAIN=3 → (10 << 8) | 3 = 2563
    Msg = nfnl_msg:build_hdr(3, 1, 0, 1, <<>>),
    <<_:32, 2563:16/little, _/binary>> = Msg,
    %% NFT_MSG_NEWRULE=6 → (10 << 8) | 6 = 2566
    Msg2 = nfnl_msg:build_hdr(6, 1, 0, 1, <<>>),
    <<_:32, 2566:16/little, _/binary>> = Msg2.
