-module(nft_expr_ir_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

-define(REG1, 1).
-define(REG2, 2).

all() ->
    [%% Existing helpers (sanity)
     ir_payload,
     ir_meta,
     ir_ct,
     ir_cmp,
     ir_bitwise,
     ir_range,
     ir_lookup,
     ir_counter,
     ir_log,
     ir_limit,
     ir_accept,
     ir_drop,
     ir_reject,
     ir_immediate_data,
     ir_snat,
     ir_dnat,
     ir_masq,
     ir_redir,
     ir_queue,
     ir_quota,
     ir_hash,
     %% New helpers (the 19)
     ir_exthdr,
     ir_byteorder,
     ir_rt,
     ir_fib,
     ir_socket,
     ir_tunnel,
     ir_dynset,
     ir_connlimit,
     ir_dup,
     ir_fwd,
     ir_inner,
     ir_numgen,
     ir_osf,
     ir_offload,
     ir_secmark,
     ir_synproxy,
     ir_tproxy,
     ir_xfrm,
     ir_last,
     %% IPv6 helpers
     ir_ip6_saddr,
     ir_ip6_daddr,
     ir_ip6_next_header,
     %% Meta: ensure no keys are silently dropped
     ir_no_dropped_keys].

%% ===================================================================
%% Existing IR helpers (sanity check)
%% ===================================================================

ir_payload(_) ->
    Term = nft_expr_ir:payload(transport, 2, 2, ?REG1),
    {<<"payload">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, Attrs)),  %% dreg=1
    ?assertMatch({2, <<2:32/big>>}, lists:keyfind(2, 1, Attrs)),  %% base=transport(2)
    ?assertMatch({3, <<2:32/big>>}, lists:keyfind(3, 1, Attrs)),  %% offset=2
    ?assertMatch({4, <<2:32/big>>}, lists:keyfind(4, 1, Attrs)).  %% len=2

ir_meta(_) ->
    Term = nft_expr_ir:meta(l4proto, ?REG1),
    {<<"meta">>, Attrs} = encode_decode(Term),
    ?assertMatch({2, <<16:32/big>>}, lists:keyfind(2, 1, Attrs)),  %% key=l4proto(16)
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, Attrs)).  %% dreg=1

ir_ct(_) ->
    Term = nft_expr_ir:ct(state, ?REG1),
    {<<"ct">>, Attrs} = encode_decode(Term),
    ?assertMatch({2, <<0:32/big>>}, lists:keyfind(2, 1, Attrs)),  %% key=state(0)
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, Attrs)).  %% dreg=1

ir_cmp(_) ->
    Term = nft_expr_ir:cmp(eq, ?REG1, <<6>>),
    {<<"cmp">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, Attrs)),  %% sreg=1
    ?assertMatch({2, <<0:32/big>>}, lists:keyfind(2, 1, Attrs)).  %% op=eq(0)

ir_bitwise(_) ->
    Term = nft_expr_ir:bitwise(?REG1, ?REG1, <<255, 0, 0, 0>>, <<0, 0, 0, 0>>),
    {<<"bitwise">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, Attrs)),  %% sreg=1
    ?assertMatch({2, <<1:32/big>>}, lists:keyfind(2, 1, Attrs)),  %% dreg=1
    ?assertMatch({3, <<4:32/big>>}, lists:keyfind(3, 1, Attrs)).  %% len=4

ir_range(_) ->
    Term = nft_expr_ir:range(eq, ?REG1, <<0, 80>>, <<1, 187>>),
    {<<"range">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, Attrs)),  %% sreg=1
    ?assertMatch({2, <<0:32/big>>}, lists:keyfind(2, 1, Attrs)).  %% op=eq(0)

ir_lookup(_) ->
    Term = nft_expr_ir:lookup(?REG1, <<"banlist">>),
    {<<"lookup">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<"banlist", 0>>}, lists:keyfind(1, 1, Attrs)).  %% set name

ir_counter(_) ->
    Term = nft_expr_ir:counter(),
    {<<"counter">>, _Attrs} = encode_decode(Term).

ir_log(_) ->
    Term = nft_expr_ir:log(#{prefix => <<"DROP: ">>}),
    {<<"log">>, Attrs} = encode_decode(Term),
    ?assertMatch({2, <<"DROP: ", 0>>}, lists:keyfind(2, 1, Attrs)).

ir_limit(_) ->
    Term = nft_expr_ir:limit(100, 50),
    {<<"limit">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<100:64/big>>}, lists:keyfind(1, 1, Attrs)).  %% rate=100

ir_accept(_) ->
    Term = nft_expr_ir:accept(),
    {<<"immediate">>, _Attrs} = encode_decode(Term).

ir_drop(_) ->
    Term = nft_expr_ir:drop(),
    {<<"immediate">>, _Attrs} = encode_decode(Term).

ir_reject(_) ->
    Term = nft_expr_ir:reject(),
    {<<"reject">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<0:32/big>>}, lists:keyfind(1, 1, Attrs)).  %% type=0

ir_immediate_data(_) ->
    Term = nft_expr_ir:immediate_data(?REG1, <<10, 0, 0, 1>>),
    {<<"immediate">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, Attrs)),  %% dreg=1
    %% data is nested with NFTA_DATA_VALUE containing the IP
    {2, nested, DataAttrs} = lists:keyfind(2, 1, Attrs),
    ?assertMatch({1, <<10, 0, 0, 1>>}, lists:keyfind(1, 1, DataAttrs)).

ir_snat(_) ->
    Term = nft_expr_ir:snat(?REG1, ?REG2),
    {<<"nat">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<0:32/big>>}, lists:keyfind(1, 1, Attrs)),  %% type=snat(0)
    ?assertMatch({2, <<2:32/big>>}, lists:keyfind(2, 1, Attrs)),  %% family=IPv4(2)
    ?assertMatch({3, <<1:32/big>>}, lists:keyfind(3, 1, Attrs)),  %% reg_addr_min=1
    ?assertMatch({5, <<2:32/big>>}, lists:keyfind(5, 1, Attrs)).  %% reg_proto_min=2

ir_dnat(_) ->
    Term = nft_expr_ir:dnat(?REG1, ?REG2),
    {<<"nat">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, Attrs)),  %% type=dnat(1)
    ?assertMatch({2, <<2:32/big>>}, lists:keyfind(2, 1, Attrs)),  %% family=IPv4(2)
    ?assertMatch({3, <<1:32/big>>}, lists:keyfind(3, 1, Attrs)),  %% reg_addr_min=1
    ?assertMatch({5, <<2:32/big>>}, lists:keyfind(5, 1, Attrs)).  %% reg_proto_min=2

ir_masq(_) ->
    Term = nft_expr_ir:masq(),
    {<<"masq">>, _Attrs} = encode_decode(Term).

ir_redir(_) ->
    Term = nft_expr_ir:redir(?REG1),
    {<<"redir">>, _Attrs} = encode_decode(Term).

ir_queue(_) ->
    Term = nft_expr_ir:queue(1),
    {<<"queue">>, _Attrs} = encode_decode(Term).

ir_quota(_) ->
    Term = nft_expr_ir:quota(1000000, 0),
    {<<"quota">>, _Attrs} = encode_decode(Term).

ir_hash(_) ->
    Term = nft_expr_ir:hash(?REG1, 4, 10, ?REG1),
    {<<"hash">>, _Attrs} = encode_decode(Term).

%% ===================================================================
%% New IR helpers (the 19)
%% ===================================================================

ir_exthdr(_) ->
    Term = nft_expr_ir:exthdr(6, 2, 2, ?REG1),
    {<<"exthdr">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, Attrs)),  %% dreg=1
    ?assertMatch({2, <<6:8>>}, lists:keyfind(2, 1, Attrs)),       %% type=6
    ?assertMatch({3, <<2:32/big>>}, lists:keyfind(3, 1, Attrs)),  %% offset=2
    ?assertMatch({4, <<2:32/big>>}, lists:keyfind(4, 1, Attrs)).  %% len=2

ir_byteorder(_) ->
    Term = nft_expr_ir:byteorder(0, ?REG1, ?REG1, 4, 4),
    {<<"byteorder">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, Attrs)),  %% sreg=1
    ?assertMatch({2, <<1:32/big>>}, lists:keyfind(2, 1, Attrs)),  %% dreg=1
    ?assertMatch({3, <<0:32/big>>}, lists:keyfind(3, 1, Attrs)),  %% op=0 (hton)
    ?assertMatch({4, <<4:32/big>>}, lists:keyfind(4, 1, Attrs)),  %% len=4
    ?assertMatch({5, <<4:32/big>>}, lists:keyfind(5, 1, Attrs)).  %% size=4

ir_rt(_) ->
    Term = nft_expr_ir:rt(0, ?REG1),
    {<<"rt">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, Attrs)),  %% dreg=1
    ?assertMatch({2, <<0:32/big>>}, lists:keyfind(2, 1, Attrs)).  %% key=0 (classid)

ir_fib(_) ->
    Term = nft_expr_ir:fib(2, 3, ?REG1),
    {<<"fib">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, Attrs)),  %% dreg=1
    ?assertMatch({2, <<2:32/big>>}, lists:keyfind(2, 1, Attrs)),  %% result=2
    ?assertMatch({3, <<3:32/big>>}, lists:keyfind(3, 1, Attrs)).  %% flags=3

ir_socket(_) ->
    Term = nft_expr_ir:socket(0, ?REG1),
    {<<"socket">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<0:32/big>>}, lists:keyfind(1, 1, Attrs)),  %% key=0 (transparent)
    ?assertMatch({2, <<1:32/big>>}, lists:keyfind(2, 1, Attrs)).  %% dreg=1

ir_tunnel(_) ->
    Term = nft_expr_ir:tunnel(0, ?REG1),
    {<<"tunnel">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<0:32/big>>}, lists:keyfind(1, 1, Attrs)),  %% key=0
    ?assertMatch({2, <<1:32/big>>}, lists:keyfind(2, 1, Attrs)).  %% dreg=1

ir_dynset(_) ->
    Term = nft_expr_ir:dynset(<<"myset">>, ?REG1, 0),
    {<<"dynset">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<"myset", 0>>}, lists:keyfind(1, 1, Attrs)),  %% set_name
    ?assertMatch({3, <<0:32/big>>}, lists:keyfind(3, 1, Attrs)),    %% op=0 (add)
    ?assertMatch({4, <<1:32/big>>}, lists:keyfind(4, 1, Attrs)).    %% sreg_key=1

ir_connlimit(_) ->
    Term = nft_expr_ir:connlimit(100, 0),
    {<<"connlimit">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<100:32/big>>}, lists:keyfind(1, 1, Attrs)),  %% count=100
    ?assertMatch({2, <<0:32/big>>}, lists:keyfind(2, 1, Attrs)).    %% flags=0

ir_dup(_) ->
    Term = nft_expr_ir:dup(?REG1, ?REG2),
    {<<"dup">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, Attrs)),  %% sreg_addr=1
    ?assertMatch({2, <<2:32/big>>}, lists:keyfind(2, 1, Attrs)).  %% sreg_dev=2

ir_fwd(_) ->
    Term = nft_expr_ir:fwd(?REG1, ?REG2, 2),
    {<<"fwd">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, Attrs)),  %% sreg_dev=1
    ?assertMatch({2, <<2:32/big>>}, lists:keyfind(2, 1, Attrs)),  %% sreg_addr=2
    ?assertMatch({3, <<2:32/big>>}, lists:keyfind(3, 1, Attrs)).  %% nfproto=2 (IPv4)

ir_inner(_) ->
    %% Test without expr field — the gen module types it as u32 (should be nested).
    %% Use generic/2 to pass only type and hdrsize.
    Term = nft_expr_ir:generic(inner, #{type => 1, hdrsize => 20}),
    {<<"inner">>, Attrs} = encode_decode(Term),
    ?assertMatch({2, <<1:32/big>>}, lists:keyfind(2, 1, Attrs)),  %% type=1
    ?assertMatch({4, <<20:32/big>>}, lists:keyfind(4, 1, Attrs)). %% hdrsize=20

ir_numgen(_) ->
    Term = nft_expr_ir:numgen(4, 0, ?REG1),
    {<<"ng">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, Attrs)),  %% dreg=1
    ?assertMatch({2, <<4:32/big>>}, lists:keyfind(2, 1, Attrs)),  %% modulus=4
    ?assertMatch({3, <<0:32/big>>}, lists:keyfind(3, 1, Attrs)).  %% type=0 (inc)

ir_osf(_) ->
    Term = nft_expr_ir:osf(?REG1),
    {<<"osf">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, Attrs)).  %% dreg=1

ir_offload(_) ->
    Term = nft_expr_ir:offload(<<"ft0">>),
    {<<"offload">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<"ft0", 0>>}, lists:keyfind(1, 1, Attrs)).  %% table_name

ir_secmark(_) ->
    Term = nft_expr_ir:secmark(<<"system_u:object_r:httpd_t:s0">>),
    {<<"secmark">>, Attrs} = encode_decode(Term),
    {1, Ctx} = lists:keyfind(1, 1, Attrs),
    ?assertNotEqual(nomatch, binary:match(Ctx, <<"system_u">>)).

ir_synproxy(_) ->
    Term = nft_expr_ir:synproxy(1460, 7, 3),
    {<<"synproxy">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<1460:16/big>>}, lists:keyfind(1, 1, Attrs)),  %% mss=1460
    ?assertMatch({2, <<7:8>>}, lists:keyfind(2, 1, Attrs)),          %% wscale=7
    ?assertMatch({3, <<3:32/big>>}, lists:keyfind(3, 1, Attrs)).     %% flags=3

ir_tproxy(_) ->
    Term = nft_expr_ir:tproxy(2, ?REG1, ?REG2),
    {<<"tproxy">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<2:32/big>>}, lists:keyfind(1, 1, Attrs)),  %% family=2 (IPv4)
    ?assertMatch({2, <<1:32/big>>}, lists:keyfind(2, 1, Attrs)),  %% reg_addr=1
    ?assertMatch({3, <<2:32/big>>}, lists:keyfind(3, 1, Attrs)).  %% reg_port=2

ir_xfrm(_) ->
    Term = nft_expr_ir:xfrm(0, 0, ?REG1),
    {<<"xfrm">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, Attrs)),  %% dreg=1
    ?assertMatch({2, <<0:32/big>>}, lists:keyfind(2, 1, Attrs)),  %% key=0
    ?assertMatch({3, <<0:32/big>>}, lists:keyfind(3, 1, Attrs)).  %% dir=0 (in)

ir_last(_) ->
    Term = nft_expr_ir:last(),
    {<<"last">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<0:32/big>>}, lists:keyfind(1, 1, Attrs)).  %% set=0

%% ===================================================================
%% IPv6 helpers
%% ===================================================================

ir_ip6_saddr(_) ->
    Term = nft_expr_ir:ip6_saddr(?REG1),
    {<<"payload">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, Attrs)),   %% dreg=1
    ?assertMatch({2, <<1:32/big>>}, lists:keyfind(2, 1, Attrs)),   %% base=network(1)
    ?assertMatch({3, <<8:32/big>>}, lists:keyfind(3, 1, Attrs)),   %% offset=8
    ?assertMatch({4, <<16:32/big>>}, lists:keyfind(4, 1, Attrs)).  %% len=16

ir_ip6_daddr(_) ->
    Term = nft_expr_ir:ip6_daddr(?REG1),
    {<<"payload">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, Attrs)),   %% dreg=1
    ?assertMatch({2, <<1:32/big>>}, lists:keyfind(2, 1, Attrs)),   %% base=network(1)
    ?assertMatch({3, <<24:32/big>>}, lists:keyfind(3, 1, Attrs)),  %% offset=24
    ?assertMatch({4, <<16:32/big>>}, lists:keyfind(4, 1, Attrs)).  %% len=16

ir_ip6_next_header(_) ->
    Term = nft_expr_ir:ip6_next_header(?REG1),
    {<<"payload">>, Attrs} = encode_decode(Term),
    ?assertMatch({1, <<1:32/big>>}, lists:keyfind(1, 1, Attrs)),   %% dreg=1
    ?assertMatch({2, <<1:32/big>>}, lists:keyfind(2, 1, Attrs)),   %% base=network(1)
    ?assertMatch({3, <<6:32/big>>}, lists:keyfind(3, 1, Attrs)),   %% offset=6
    ?assertMatch({4, <<1:32/big>>}, lists:keyfind(4, 1, Attrs)).   %% len=1

%% ===================================================================
%% Meta: ensure no IR keys are silently dropped by encoders
%% ===================================================================

ir_no_dropped_keys(_) ->
    %% Encode every IR expression type through nft_encode.
    %% With the regenerated encoders, unknown keys now emit
    %% logger:warning. We install a custom handler to catch them.
    Self = self(),
    ok = logger:add_handler(ir_drop_catcher, ?MODULE, #{
        level => warning, config => #{self => Self}
    }),
    AllExprs = [
        nft_expr_ir:payload(network, 12, 4, ?REG1),
        nft_expr_ir:meta(l4proto, ?REG1),
        nft_expr_ir:ct(state, ?REG1),
        nft_expr_ir:cmp(eq, ?REG1, <<6>>),
        nft_expr_ir:bitwise(?REG1, ?REG1, <<255,0,0,0>>, <<0,0,0,0>>),
        nft_expr_ir:range(eq, ?REG1, <<0,80>>, <<1,187>>),
        nft_expr_ir:lookup(?REG1, <<"test">>),
        nft_expr_ir:counter(),
        nft_expr_ir:log(#{prefix => <<"T">>}),
        nft_expr_ir:limit(100, 50),
        nft_expr_ir:accept(),
        nft_expr_ir:drop(),
        nft_expr_ir:reject(),
        nft_expr_ir:immediate_data(?REG1, <<1,2,3,4>>),
        nft_expr_ir:snat(?REG1, ?REG2),
        nft_expr_ir:snat(?REG1, ?REG2, 2),
        nft_expr_ir:dnat(?REG1, ?REG2),
        nft_expr_ir:dnat(?REG1, ?REG2, 10),
        nft_expr_ir:masq(),
        nft_expr_ir:masq(?REG1, ?REG2),
        nft_expr_ir:redir(?REG1),
        nft_expr_ir:queue(1),
        nft_expr_ir:quota(1000, 0),
        nft_expr_ir:hash(?REG1, 4, 10, ?REG1),
        nft_expr_ir:exthdr(6, 2, 2, ?REG1),
        nft_expr_ir:byteorder(0, ?REG1, ?REG1, 4, 4),
        nft_expr_ir:rt(0, ?REG1),
        nft_expr_ir:fib(2, 3, ?REG1),
        nft_expr_ir:socket(0, ?REG1),
        nft_expr_ir:tunnel(0, ?REG1),
        nft_expr_ir:dynset(<<"s">>, ?REG1, 0),
        nft_expr_ir:connlimit(100, 0),
        nft_expr_ir:dup(?REG1, ?REG2),
        nft_expr_ir:fwd(?REG1, ?REG2, 2),
        nft_expr_ir:numgen(4, 0, ?REG1),
        nft_expr_ir:osf(?REG1),
        nft_expr_ir:offload(<<"ft0">>),
        nft_expr_ir:secmark(<<"ctx">>),
        nft_expr_ir:synproxy(1460, 7, 3),
        nft_expr_ir:tproxy(2, ?REG1, ?REG2),
        nft_expr_ir:xfrm(0, 0, ?REG1),
        nft_expr_ir:last()
    ],
    _ = [nft_encode:expr(E) || E <- AllExprs],
    timer:sleep(50),
    logger:remove_handler(ir_drop_catcher),
    %% Drain mailbox and fail on any dropped-key message
    check_no_dropped_keys().

check_no_dropped_keys() ->
    receive
        {ir_dropped_key, Msg} ->
            ct:fail("Encoder dropped unknown key: ~s", [Msg])
    after 0 ->
        ok
    end.

%% logger handler callbacks
log(#{msg := {Fmt, Args}} = _Event, #{config := #{self := Pid}}) ->
    Msg = lists:flatten(io_lib:format(Fmt, Args)),
    case string:find(Msg, "unknown attr") of
        nomatch -> ok;
        _ -> Pid ! {ir_dropped_key, Msg}
    end;
log(_, _) -> ok.

%% --- Helpers ---

encode_decode(Term) ->
    Bin = nft_encode:expr(Term),
    Decoded = nfnl_attr:decode(Bin),
    {1, NameBin} = lists:keyfind(1, 1, Decoded),
    NameLen = byte_size(NameBin) - 1,
    <<Name:NameLen/binary, 0>> = NameBin,
    {2, nested, Attrs} = lists:keyfind(2, 1, Decoded),
    {Name, Attrs}.
