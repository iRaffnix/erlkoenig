-module(nft_expr_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

-define(NFT_REG_1, 1).

all() ->
    [meta_load_l4proto,
     cmp_eq_tcp,
     cmp_neq,
     payload_tcp_dport,
     payload_ip_saddr,
     immediate_accept,
     immediate_drop,
     immediate_jump,
     expr_name_encoded,
     expr_data_nested,
     rule_has_expressions,
     full_tcp_dport_80_accept].

%% --- Meta ---

meta_load_l4proto(_) ->
    Bin = nft_expr_meta:load(l4proto, ?NFT_REG_1),
    {<<"meta">>, Attrs} = decode_expr(Bin),
    %% NFTA_META_KEY(2) = 16 (l4proto), NFTA_META_DREG(1) = 1
    ?assertMatch({2, <<16:32/big>>}, lists:keyfind(2, 1, Attrs)),
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, Attrs)).

%% --- Cmp ---

cmp_eq_tcp(_) ->
    Bin = nft_expr_cmp:eq(?NFT_REG_1, <<6>>),
    {<<"cmp">>, Attrs} = decode_expr(Bin),
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, Attrs)),  %% SREG=1
    ?assertMatch({2, <<0:32/big>>}, lists:keyfind(2, 1, Attrs)),  %% OP=EQ(0)
    %% NFTA_CMP_DATA(3) is nested with NFTA_DATA_VALUE(1) = <<6>>
    {3, nested, DataAttrs} = lists:keyfind(3, 1, Attrs),
    ?assertMatch({1, <<6>>}, lists:keyfind(1, 1, DataAttrs)).

cmp_neq(_) ->
    Bin = nft_expr_cmp:neq(?NFT_REG_1, <<17>>),
    {<<"cmp">>, Attrs} = decode_expr(Bin),
    ?assertMatch({2, <<1:32/big>>}, lists:keyfind(2, 1, Attrs)).  %% OP=NEQ(1)

%% --- Payload ---

payload_tcp_dport(_) ->
    Bin = nft_expr_payload:tcp_dport(?NFT_REG_1),
    {<<"payload">>, Attrs} = decode_expr(Bin),
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, Attrs)),  %% DREG=1
    ?assertMatch({2, <<2:32/big>>}, lists:keyfind(2, 1, Attrs)),  %% BASE=transport(2)
    ?assertMatch({3, <<2:32/big>>}, lists:keyfind(3, 1, Attrs)),  %% OFFSET=2
    ?assertMatch({4, <<2:32/big>>}, lists:keyfind(4, 1, Attrs)).  %% LEN=2

payload_ip_saddr(_) ->
    Bin = nft_expr_payload:ip_saddr(?NFT_REG_1),
    {<<"payload">>, Attrs} = decode_expr(Bin),
    ?assertMatch({2, <<1:32/big>>}, lists:keyfind(2, 1, Attrs)),  %% BASE=network(1)
    ?assertMatch({3, <<12:32/big>>}, lists:keyfind(3, 1, Attrs)), %% OFFSET=12
    ?assertMatch({4, <<4:32/big>>}, lists:keyfind(4, 1, Attrs)).  %% LEN=4

%% --- Immediate ---

immediate_accept(_) ->
    Bin = nft_expr_immediate:accept(),
    {<<"immediate">>, Attrs} = decode_expr(Bin),
    %% DREG=0 (verdict register)
    ?assertMatch({1, <<0:32/big>>}, lists:keyfind(1, 1, Attrs)),
    %% DATA → VERDICT → CODE = 1 (NF_ACCEPT)
    {2, nested, DataAttrs} = lists:keyfind(2, 1, Attrs),
    {2, nested, VerdictAttrs} = lists:keyfind(2, 1, DataAttrs),
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, VerdictAttrs)).

immediate_drop(_) ->
    Bin = nft_expr_immediate:drop(),
    {<<"immediate">>, Attrs} = decode_expr(Bin),
    {2, nested, DataAttrs} = lists:keyfind(2, 1, Attrs),
    {2, nested, VerdictAttrs} = lists:keyfind(2, 1, DataAttrs),
    ?assertMatch({1, <<0:32/big>>}, lists:keyfind(1, 1, VerdictAttrs)).

immediate_jump(_) ->
    Bin = nft_expr_immediate:jump(<<"mychain">>),
    {<<"immediate">>, Attrs} = decode_expr(Bin),
    {2, nested, DataAttrs} = lists:keyfind(2, 1, Attrs),
    {2, nested, VerdictAttrs} = lists:keyfind(2, 1, DataAttrs),
    %% CODE = 0xFFFFFFFD (NFT_JUMP = -3)
    ?assertMatch({1, <<16#FFFFFFFD:32/big>>}, lists:keyfind(1, 1, VerdictAttrs)),
    %% CHAIN = "mychain\0"
    ?assertMatch({2, <<"mychain", 0>>}, lists:keyfind(2, 1, VerdictAttrs)).

%% --- Expr wrapper ---

expr_name_encoded(_) ->
    Bin = nft_expr:build(<<"test">>, <<>>),
    Decoded = nfnl_attr:decode(Bin),
    ?assertMatch({1, <<"test", 0>>}, lists:keyfind(1, 1, Decoded)).

expr_data_nested(_) ->
    Inner = nfnl_attr:encode_u32(1, 42),
    Bin = nft_expr:build(<<"test">>, Inner),
    Decoded = nfnl_attr:decode(Bin),
    ?assertMatch({2, nested, [{1, <<42:32/big>>}]}, lists:keyfind(2, 1, Decoded)).

%% --- Rule ---

rule_has_expressions(_) ->
    Exprs = [nft_expr_immediate:accept()],
    Msg = nft_rule:add(1, <<"fw">>, <<"in">>, Exprs, 1),
    <<_:20/binary, Attrs/binary>> = Msg,
    Decoded = nfnl_attr:decode(Attrs),
    ?assertMatch({1, <<"fw", 0>>}, lists:keyfind(1, 1, Decoded)),
    ?assertMatch({2, <<"in", 0>>}, lists:keyfind(2, 1, Decoded)),
    ?assertMatch({4, nested, _}, lists:keyfind(4, 1, Decoded)).

%% --- Full integration: "tcp dport 80 accept" ---

full_tcp_dport_80_accept(_) ->
    Exprs = [
        nft_expr_meta:load(l4proto, 1),
        nft_expr_cmp:eq(1, <<6>>),
        nft_expr_payload:tcp_dport(1),
        nft_expr_cmp:eq(1, <<0, 80>>),
        nft_expr_immediate:accept()
    ],
    Msg = nft_rule:add(1, <<"fw">>, <<"input">>, Exprs, 100),
    %% Should be a valid message
    <<Len:32/little, 2566:16/little, _/binary>> = Msg,
    ?assertEqual(byte_size(Msg), Len),
    %% Should have 5 expressions
    <<_:20/binary, Attrs/binary>> = Msg,
    Decoded = nfnl_attr:decode(Attrs),
    {4, nested, ExprList} = lists:keyfind(4, 1, Decoded),
    ?assertEqual(5, length(ExprList)).

%% --- Helpers ---

decode_expr(Bin) ->
    Decoded = nfnl_attr:decode(Bin),
    {1, NameBin} = lists:keyfind(1, 1, Decoded),
    %% Strip null terminator
    NameLen = byte_size(NameBin) - 1,
    <<Name:NameLen/binary, 0>> = NameBin,
    {2, nested, Attrs} = lists:keyfind(2, 1, Decoded),
    {Name, Attrs}.
