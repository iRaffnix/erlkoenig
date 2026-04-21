%%%-------------------------------------------------------------------
%%% EUnit: nft_set_elem:add_range_elems/5 wire-format.
%%%
%%% `add_range_elems` emits one NEWSETELEM netlink message where
%%% each input range `{Start, End}` translates to two
%%% NFTA_LIST_ELEM children:
%%%
%%%   1. key=Start, no flags
%%%   2. key=End+1, flags=NFT_SET_ELEM_INTERVAL_END (=1)
%%%
%%% This is the format the in-tree nftables userspace uses — test 30
%%% confirms it round-trips through a live kernel. These EUnit tests
%%% pin the binary byte layout so a future refactor of the attribute
%%% encoder cannot silently drop the interval-end flag or swap the
%%% order, either of which would load an open-ended range and
%%% silently defeat CIDR allowlists.
%%%-------------------------------------------------------------------
-module(nft_set_elem_tests).

-include_lib("eunit/include/eunit.hrl").
-include("../include/nft_constants.hrl").

%% NLM_F_* macros are already provided by nft_constants.hrl.

-define(INET,  1).
-define(TABLE, <<"t">>).
-define(SET,   <<"s">>).

%% =================================================================
%% Message header shape
%% =================================================================

empty_range_list_produces_valid_header_test() ->
    Msg = nft_set_elem:add_range_elems(?INET, ?TABLE, ?SET, [], 42),
    %% Message is at least the 16-byte netlink header + the
    %% 4-byte NFGENMSG + a handful of nested attrs. Double-check
    %% the length prefix matches actual byte size.
    <<Len:32/little, _/binary>> = Msg,
    ?assertEqual(byte_size(Msg), Len),
    %% Type = NFT_MSG_NEWSETELEM | (NFNL_SUBSYS_NFTABLES << 8).
    %% Subsys 10 shifted = 0x0a00; NEWSETELEM = 12; together 0x0a0c.
    <<_:32, Type:16/little, Flags:16/little, _/binary>> = Msg,
    ?assertEqual(16#0A0C, Type),
    ?assertEqual(?NLM_F_REQUEST bor ?NLM_F_ACK bor ?NLM_F_CREATE, Flags).

%% =================================================================
%% Single range: key + interval-end pair
%% =================================================================

single_range_emits_two_list_elems_test() ->
    %% 10.0.0.0/8  →  Start=10.0.0.0, End+1=11.0.0.0
    Start = <<10, 0, 0, 0>>,
    End   = <<10, 255, 255, 255>>,
    Msg = nft_set_elem:add_range_elems(?INET, ?TABLE, ?SET,
                                         [{Start, End}], 1),
    %% The inner payload after the NFGENMSG header contains a
    %% nested NFTA_SET_ELEM_LIST_ELEMENTS (type=3) attribute; inside
    %% are NFTA_LIST_ELEM children. Assert: exactly two list_elem
    %% children, second carries the INTERVAL_END flag.
    {StartKey, EndKey, EndFlags} = extract_pair(Msg),
    ?assertEqual(Start, StartKey),
    %% End+1 = 11.0.0.0 = <<11,0,0,0>>
    ?assertEqual(<<11, 0, 0, 0>>, EndKey),
    ?assertEqual(?NFT_SET_ELEM_INTERVAL_END, EndFlags).

%% =================================================================
%% Singleton range: Start == End  →  End+1 still emitted
%% =================================================================

singleton_range_still_emits_end_plus_one_test() ->
    %% 203.0.113.42/32 — point, but we still emit 2 list_elems
    Key = <<203, 0, 113, 42>>,
    Msg = nft_set_elem:add_range_elems(?INET, ?TABLE, ?SET,
                                         [{Key, Key}], 1),
    {StartKey, EndKey, EndFlags} = extract_pair(Msg),
    ?assertEqual(Key, StartKey),
    ?assertEqual(<<203, 0, 113, 43>>, EndKey),
    ?assertEqual(?NFT_SET_ELEM_INTERVAL_END, EndFlags).

%% =================================================================
%% Wrap-around: 255.255.255.255 + 1 overflows to 0.0.0.0.
%% We let the kernel reject that with EINVAL rather than silently
%% truncating — this test documents the current behaviour.
%% =================================================================

wrap_around_end_test() ->
    Key = <<255, 255, 255, 255>>,
    Msg = nft_set_elem:add_range_elems(?INET, ?TABLE, ?SET,
                                         [{Key, Key}], 1),
    {_, EndKey, _} = extract_pair(Msg),
    %% next_key wraps at the bit width — documented, not pretty
    ?assertEqual(<<0, 0, 0, 0>>, EndKey).

%% =================================================================
%% Two ranges → four list_elem entries
%% =================================================================

two_ranges_emit_four_list_elems_test() ->
    A = {<<10, 0, 0, 0>>, <<10, 255, 255, 255>>},
    B = {<<192, 168, 0, 0>>, <<192, 168, 255, 255>>},
    Msg = nft_set_elem:add_range_elems(?INET, ?TABLE, ?SET,
                                         [A, B], 2),
    Elems = extract_list_elems(Msg),
    ?assertEqual(4, length(Elems)).

%% =================================================================
%% Internal: pull key + flags out of the nested attrs. We
%% don't repeat the full nla parser — just enough to validate.
%% =================================================================

extract_pair(Msg) ->
    [First, Second] =
        case extract_list_elems(Msg) of
            [E1, E2] -> [E1, E2];
            Other    -> error({expected_two_list_elems, Other})
        end,
    {StartKey, StartFlags} = parse_elem(First),
    {EndKey,   EndFlags}   = parse_elem(Second),
    ?assertEqual(0, StartFlags),
    {StartKey, EndKey, EndFlags}.

%% Walk the message down to NFTA_SET_ELEM_LIST_ELEMENTS (= 3) and
%% return the raw child bodies (each a NFTA_LIST_ELEM = 1 body).
extract_list_elems(Msg) ->
    %% Skip 16-byte nlmsghdr + 4-byte nfgen_family/version/res_id.
    <<_:16/binary, _:32, AttrsBin/binary>> = Msg,
    Attrs = decode_attrs(AttrsBin),
    {_, ElementsNested} =
        lists:keyfind(?NFTA_SET_ELEM_LIST_ELEMENTS, 1, Attrs),
    %% Strip NLA_F_NESTED bit off each list_elem type when parsing.
    [Body || {?NFTA_LIST_ELEM, Body} <-
                 decode_attrs(ElementsNested)].

parse_elem(ElemBody) ->
    Attrs = decode_attrs(ElemBody),
    Key = case lists:keyfind(?NFTA_SET_ELEM_KEY, 1, Attrs) of
              {_, KeyInner} ->
                  [{1, Bytes} | _] = decode_attrs(KeyInner),
                  Bytes;
              false -> undefined
          end,
    Flags = case lists:keyfind(?NFTA_SET_ELEM_FLAGS, 1, Attrs) of
                {_, <<F:32/big>>} -> F;
                false -> 0
            end,
    {Key, Flags}.

%% Thin TLV walker — strips NLA_F_NESTED (0x8000) off the type.
decode_attrs(<<>>) -> [];
decode_attrs(<<Len:16/little, Type:16/little, Rest/binary>>)
    when Len >= 4 ->
    BodyLen = Len - 4,
    <<Body:BodyLen/binary, Tail0/binary>> = Rest,
    Pad = pad4(BodyLen),
    Tail = case Tail0 of
        <<_:Pad/binary, T/binary>> -> T;
        _ -> <<>>
    end,
    [{Type band 16#7FFF, Body} | decode_attrs(Tail)];
decode_attrs(_) -> [].

pad4(N) -> (4 - (N rem 4)) rem 4.
