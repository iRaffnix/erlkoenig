-module(nfnl_attr_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

all() ->
    [
        encode_raw,
        encode_str_null_terminated,
        encode_u32_big_endian,
        encode_u64_big_endian,
        encode_nested_flag,
        encode_padding,
        decode_single,
        decode_multiple,
        decode_nested,
        roundtrip_simple,
        roundtrip_nested,
        roundtrip_real_table
    ].

%% --- Encoding ---

encode_raw(_) ->
    %% Type=1, Data = <<1,2,3>>  → Len=7, padded to 8
    Bin = nfnl_attr:encode(1, <<1, 2, 3>>),
    <<7:16/little, 1:16/little, 1, 2, 3, 0>> = Bin.

encode_str_null_terminated(_) ->
    Bin = nfnl_attr:encode_str(1, <<"test">>),
    %% "test" + \0 = 5 bytes data, Len=9, pad to 12
    <<9:16/little, 1:16/little, "test", 0, 0:24>> = Bin.

encode_u32_big_endian(_) ->
    Bin = nfnl_attr:encode_u32(2, 16#DEADBEEF),
    <<8:16/little, 2:16/little, 16#DEADBEEF:32/big>> = Bin.

encode_u64_big_endian(_) ->
    Bin = nfnl_attr:encode_u64(3, 16#0102030405060708),
    <<12:16/little, 3:16/little, 16#0102030405060708:64/big>> = Bin.

encode_nested_flag(_) ->
    Inner = nfnl_attr:encode_u32(1, 42),
    Bin = nfnl_attr:encode_nested(4, Inner),
    %% Type should have NLA_F_NESTED (0x8000) set
    <<_Len:16/little, Type:16/little, _/binary>> = Bin,
    16#8004 = Type.

encode_padding(_) ->
    %% 1 byte data → Len=5, needs 3 bytes padding
    Bin = nfnl_attr:encode(1, <<42>>),
    <<5:16/little, 1:16/little, 42, 0, 0, 0>> = Bin,
    ?assertEqual(8, byte_size(Bin)),

    %% 2 bytes data → Len=6, needs 2 bytes padding
    Bin2 = nfnl_attr:encode(1, <<1, 2>>),
    ?assertEqual(8, byte_size(Bin2)),

    %% 4 bytes data → Len=8, no padding
    Bin3 = nfnl_attr:encode(1, <<1, 2, 3, 4>>),
    ?assertEqual(8, byte_size(Bin3)).

%% --- Decoding ---

decode_single(_) ->
    Bin = nfnl_attr:encode_u32(7, 100),
    [{7, <<100:32/big>>}] = nfnl_attr:decode(Bin).

decode_multiple(_) ->
    Bin = iolist_to_binary([
        nfnl_attr:encode_str(1, <<"hello">>),
        nfnl_attr:encode_u32(2, 0)
    ]),
    [{1, <<"hello", 0>>}, {2, <<0:32>>}] = nfnl_attr:decode(Bin).

decode_nested(_) ->
    Inner = nfnl_attr:encode_u32(1, 99),
    Bin = nfnl_attr:encode_nested(5, Inner),
    [{5, nested, [{1, <<99:32/big>>}]}] = nfnl_attr:decode(Bin).

%% --- Roundtrips ---

roundtrip_simple(_) ->
    Original = [{1, <<"test", 0>>}, {2, <<0, 0, 0, 0>>}],
    Bin = iolist_to_binary([
        nfnl_attr:encode_str(1, <<"test">>),
        nfnl_attr:encode_u32(2, 0)
    ]),
    ?assertEqual(Original, nfnl_attr:decode(Bin)).

roundtrip_nested(_) ->
    Inner = iolist_to_binary([
        nfnl_attr:encode_u32(1, 1),
        nfnl_attr:encode_u32(2, 0)
    ]),
    Bin = nfnl_attr:encode_nested(4, Inner),
    [{4, nested, Children}] = nfnl_attr:decode(Bin),
    [{1, <<1:32/big>>}, {2, <<0:32/big>>}] = Children.

%% Real-world: NEWTABLE attributes for "test2" table
roundtrip_real_table(_) ->
    Bin = iolist_to_binary([
        nfnl_attr:encode_str(1, <<"test2">>),
        nfnl_attr:encode_u32(2, 0)
    ]),
    Decoded = nfnl_attr:decode(Bin),
    [{1, <<"test2", 0>>}, {2, <<0:32>>}] = Decoded.
