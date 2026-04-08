%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%

-module(nft_set_elem).
-moduledoc """
nf_tables set element operations.

Adds or removes elements from a named set. Each element has a key
that must match the set's key type and length.

Wire format for adding elements:
    NFTA_SET_ELEM_LIST_TABLE  = table name
    NFTA_SET_ELEM_LIST_SET    = set name
    NFTA_SET_ELEM_LIST_ELEMENTS (nested)
      └── NFTA_LIST_ELEM (nested)
            └── NFTA_SET_ELEM_KEY (nested)
                  └── NFTA_DATA_VALUE = raw key bytes

For timeout elements, NFTA_SET_ELEM_TIMEOUT is added inside the
NFTA_LIST_ELEM alongside the key.

Corresponds to libnftnl src/set_elem.c.
""".

-export([
    add/5, add/6,
    add_elems/5,
    add_vmap_elems/5,
    add_vmap_elems/6,
    add_data_map_elems/6,
    del/5
]).

-include("nft_constants.hrl").

%% --- Public API ---

-doc """
Add a single element to a set.

Key is the raw element data in the format matching the set's key type.
For ipv4_addr sets, use a 4-byte binary: <<192, 168, 1, 100>>.
For inet_service sets, use a 2-byte binary: <<0, 80>>.

Example:
    %% Add IP 10.0.0.5 to the "banned" set
    nft_set_elem:add(1, <<"fw">>, <<"banned">>, <<10, 0, 0, 5>>, Seq)
""".
-spec add(0..255, binary(), binary(), binary(), non_neg_integer()) ->
    nfnl_msg:nl_msg().
add(Family, Table, Set, Key, Seq) ->
    ElemAttrs = nfnl_attr:encode_nested(
        ?NFTA_SET_ELEM_KEY,
        nfnl_attr:encode(?NFTA_DATA_VALUE, Key)
    ),
    build_elem_msg(?NFT_MSG_NEWSETELEM, Family, Table, Set, ElemAttrs, Seq).

-doc """
Add a single element to a set with a timeout in milliseconds.

The element is automatically removed after the timeout expires.

Example:
    %% Ban IP for 1 hour (3600000 ms)
    nft_set_elem:add(1, <<"fw">>, <<"banned">>, <<10, 0, 0, 5>>, 3600000, Seq)
""".
-spec add(
    0..255,
    binary(),
    binary(),
    binary(),
    non_neg_integer(),
    non_neg_integer()
) -> nfnl_msg:nl_msg().
add(Family, Table, Set, Key, Timeout, Seq) ->
    ElemAttrs = iolist_to_binary([
        nfnl_attr:encode_nested(
            ?NFTA_SET_ELEM_KEY,
            nfnl_attr:encode(?NFTA_DATA_VALUE, Key)
        ),
        nfnl_attr:encode_u64(?NFTA_SET_ELEM_TIMEOUT, Timeout)
    ]),
    build_elem_msg(?NFT_MSG_NEWSETELEM, Family, Table, Set, ElemAttrs, Seq).

-doc """
Remove a single element from a set.

Example:
    nft_set_elem:del(1, <<"fw">>, <<"banned">>, <<10, 0, 0, 5>>, Seq)
""".
-spec del(0..255, binary(), binary(), binary(), non_neg_integer()) ->
    nfnl_msg:nl_msg().
del(Family, Table, Set, Key, Seq) ->
    ElemAttrs = nfnl_attr:encode_nested(
        ?NFTA_SET_ELEM_KEY,
        nfnl_attr:encode(?NFTA_DATA_VALUE, Key)
    ),
    build_elem_msg(?NFT_MSG_DELSETELEM, Family, Table, Set, ElemAttrs, Seq).

-doc """
Add multiple elements to a set in a single message.

Keys is a list of raw binary keys matching the set's key type.

Example:
    nft_set_elem:add_elems(1, <<"fw">>, <<"banned">>,
        [<<10, 0, 0, 5>>, <<192, 168, 1, 100>>], Seq)
""".
-spec add_elems(0..255, binary(), binary(), [binary()], non_neg_integer()) ->
    nfnl_msg:nl_msg().
add_elems(Family, Table, Set, Keys, Seq) ->
    ElemList = iolist_to_binary([
        nfnl_attr:encode_nested(
            ?NFTA_LIST_ELEM,
            nfnl_attr:encode_nested(
                ?NFTA_SET_ELEM_KEY,
                nfnl_attr:encode(?NFTA_DATA_VALUE, Key)
            )
        )
     || Key <- Keys
    ]),
    Attrs = iolist_to_binary([
        nfnl_attr:encode_str(?NFTA_SET_ELEM_LIST_TABLE, Table),
        nfnl_attr:encode_str(?NFTA_SET_ELEM_LIST_SET, Set),
        nfnl_attr:encode_nested(?NFTA_SET_ELEM_LIST_ELEMENTS, ElemList)
    ]),
    NlFlags = ?NLM_F_REQUEST bor ?NLM_F_ACK bor ?NLM_F_CREATE,
    nfnl_msg:build_hdr(?NFT_MSG_NEWSETELEM, Family, NlFlags, Seq, Attrs).

-doc """
Add multiple verdict map elements to a set.

Elements is a list of {Key, Verdict} tuples where Verdict is:
    accept | drop | {jump, ChainName} | {goto, ChainName}

Example:
    nft_set_elem:add_vmap_elems(1, <<"fw">>, <<"port_dispatch">>, [
        {<<22:16/big>>, {jump, <<"ssh_chain">>}},
        {<<80:16/big>>, {jump, <<"http_chain">>}}
    ], Seq)
""".
-spec add_vmap_elems(
    0..255,
    binary(),
    binary(),
    [{binary(), atom() | {atom(), binary()}}],
    non_neg_integer()
) -> nfnl_msg:nl_msg().
add_vmap_elems(Family, Table, Set, Elements, Seq) ->
    add_vmap_elems(Family, Table, Set, Elements, 0, Seq).

-doc """
Add multiple verdict map elements with SET_ID for intra-batch references.

When the vmap and its elements are created in the same batch, the kernel
cannot find the vmap by name (not committed yet). SET_ID correlates the
element addition with the pending vmap creation. Use 0 for committed vmaps.
""".
-spec add_vmap_elems(
    0..255,
    binary(),
    binary(),
    [{binary(), atom() | {atom(), binary()}}],
    non_neg_integer(),
    non_neg_integer()
) -> nfnl_msg:nl_msg().
add_vmap_elems(Family, Table, Set, Elements, SetId, Seq) ->
    ElemList = iolist_to_binary([
        nfnl_attr:encode_nested(
            ?NFTA_LIST_ELEM,
            iolist_to_binary([
                nfnl_attr:encode_nested(
                    ?NFTA_SET_ELEM_KEY,
                    nfnl_attr:encode(?NFTA_DATA_VALUE, Key)
                ),
                nfnl_attr:encode_nested(
                    ?NFTA_SET_ELEM_DATA,
                    encode_verdict_data(Verdict)
                )
            ])
        )
     || {Key, Verdict} <- Elements
    ]),
    SetIdAttr = case SetId of
        0 -> [];
        _ -> [nfnl_attr:encode_u32(?NFTA_SET_ELEM_LIST_SET_ID, SetId)]
    end,
    Attrs = iolist_to_binary(lists:flatten([
        nfnl_attr:encode_str(?NFTA_SET_ELEM_LIST_TABLE, Table),
        nfnl_attr:encode_str(?NFTA_SET_ELEM_LIST_SET, Set),
        SetIdAttr,
        nfnl_attr:encode_nested(?NFTA_SET_ELEM_LIST_ELEMENTS, ElemList)
    ])),
    NlFlags = ?NLM_F_REQUEST bor ?NLM_F_ACK bor ?NLM_F_CREATE,
    nfnl_msg:build_hdr(?NFT_MSG_NEWSETELEM, Family, NlFlags, Seq, Attrs).

-doc """
Add elements to a data map (key → data value).

Unlike vmap elements (key → verdict), data map elements store
raw values (e.g., IP addresses) that can be loaded into registers.

Used for jhash loadbalancing: {<<0:32>> → <<10,0,0,2>>}, ...

SetId must match the ID used in add_data_map/4 when both the map
and its elements are created in the same Netlink batch. The kernel
uses NFTA_SET_ELEM_LIST_SET_ID to correlate element additions with
pending (uncommitted) set creations within a transaction.
""".
-spec add_data_map_elems(0..255, binary(), binary(),
    [{binary(), binary()}], non_neg_integer(), non_neg_integer()) ->
    nfnl_msg:nl_msg().
add_data_map_elems(Family, Table, Set, Elements, SetId, Seq) ->
    ElemList = iolist_to_binary([
        nfnl_attr:encode_nested(
            ?NFTA_LIST_ELEM,
            iolist_to_binary([
                nfnl_attr:encode_nested(
                    ?NFTA_SET_ELEM_KEY,
                    nfnl_attr:encode(?NFTA_DATA_VALUE, Key)
                ),
                nfnl_attr:encode_nested(
                    ?NFTA_SET_ELEM_DATA,
                    nfnl_attr:encode(?NFTA_DATA_VALUE, Value)
                )
            ])
        )
     || {Key, Value} <- Elements
    ]),
    SetIdAttr = case SetId of
        0 -> [];
        _ -> [nfnl_attr:encode_u32(?NFTA_SET_ELEM_LIST_SET_ID, SetId)]
    end,
    Attrs = iolist_to_binary(lists:flatten([
        nfnl_attr:encode_str(?NFTA_SET_ELEM_LIST_TABLE, Table),
        nfnl_attr:encode_str(?NFTA_SET_ELEM_LIST_SET, Set),
        SetIdAttr,
        nfnl_attr:encode_nested(?NFTA_SET_ELEM_LIST_ELEMENTS, ElemList)
    ])),
    NlFlags = ?NLM_F_REQUEST bor ?NLM_F_ACK bor ?NLM_F_CREATE,
    nfnl_msg:build_hdr(?NFT_MSG_NEWSETELEM, Family, NlFlags, Seq, Attrs).

%% --- Internal ---

-spec build_elem_msg(
    12 | 14,
    0..255,
    binary(),
    binary(),
    binary(),
    non_neg_integer()
) -> nfnl_msg:nl_msg().
build_elem_msg(MsgType, Family, Table, Set, ElemAttrs, Seq) ->
    ElemList = nfnl_attr:encode_nested(?NFTA_LIST_ELEM, ElemAttrs),
    Attrs = iolist_to_binary([
        nfnl_attr:encode_str(?NFTA_SET_ELEM_LIST_TABLE, Table),
        nfnl_attr:encode_str(?NFTA_SET_ELEM_LIST_SET, Set),
        nfnl_attr:encode_nested(?NFTA_SET_ELEM_LIST_ELEMENTS, ElemList)
    ]),
    NlFlags = ?NLM_F_REQUEST bor ?NLM_F_ACK bor ?NLM_F_CREATE,
    nfnl_msg:build_hdr(MsgType, Family, NlFlags, Seq, Attrs).

encode_verdict_data(accept) ->
    nfnl_attr:encode_nested(
        ?NFTA_DATA_VERDICT,
        nfnl_attr:encode_u32(?NFTA_VERDICT_CODE, ?NF_ACCEPT)
    );
encode_verdict_data(drop) ->
    nfnl_attr:encode_nested(
        ?NFTA_DATA_VERDICT,
        nfnl_attr:encode_u32(?NFTA_VERDICT_CODE, ?NF_DROP)
    );
encode_verdict_data({jump, Chain}) ->
    nfnl_attr:encode_nested(
        ?NFTA_DATA_VERDICT,
        iolist_to_binary([
            nfnl_attr:encode_u32(?NFTA_VERDICT_CODE, ?NFT_JUMP),
            nfnl_attr:encode_str(?NFTA_VERDICT_CHAIN, Chain)
        ])
    );
encode_verdict_data({goto, Chain}) ->
    nfnl_attr:encode_nested(
        ?NFTA_DATA_VERDICT,
        iolist_to_binary([
            nfnl_attr:encode_u32(?NFTA_VERDICT_CODE, ?NFT_GOTO),
            nfnl_attr:encode_str(?NFTA_VERDICT_CHAIN, Chain)
        ])
    ).
