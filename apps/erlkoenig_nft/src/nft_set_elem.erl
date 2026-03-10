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

-export([add/5, add/6,
         del/5]).

%% --- Constants ---

-define(NFT_MSG_NEWSETELEM, 12).
-define(NFT_MSG_DELSETELEM, 14).

-define(NFTA_SET_ELEM_LIST_TABLE,    1).
-define(NFTA_SET_ELEM_LIST_SET,      2).
-define(NFTA_SET_ELEM_LIST_ELEMENTS, 3).

-define(NFTA_SET_ELEM_KEY,     1).
-define(NFTA_SET_ELEM_TIMEOUT, 4).

-define(NFTA_LIST_ELEM, 1).
-define(NFTA_DATA_VALUE, 1).

-define(NLM_F_REQUEST, 16#0001).
-define(NLM_F_ACK,     16#0004).
-define(NLM_F_CREATE,  16#0400).

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
    ElemAttrs = nfnl_attr:encode_nested(?NFTA_SET_ELEM_KEY,
        nfnl_attr:encode(?NFTA_DATA_VALUE, Key)),
    build_elem_msg(?NFT_MSG_NEWSETELEM, Family, Table, Set, ElemAttrs, Seq).

-doc """
Add a single element to a set with a timeout in milliseconds.

The element is automatically removed after the timeout expires.

Example:
    %% Ban IP for 1 hour (3600000 ms)
    nft_set_elem:add(1, <<"fw">>, <<"banned">>, <<10, 0, 0, 5>>, 3600000, Seq)
""".
-spec add(0..255, binary(), binary(), binary(), non_neg_integer(),
          non_neg_integer()) -> nfnl_msg:nl_msg().
add(Family, Table, Set, Key, Timeout, Seq) ->
    ElemAttrs = iolist_to_binary([
        nfnl_attr:encode_nested(?NFTA_SET_ELEM_KEY,
            nfnl_attr:encode(?NFTA_DATA_VALUE, Key)),
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
    ElemAttrs = nfnl_attr:encode_nested(?NFTA_SET_ELEM_KEY,
        nfnl_attr:encode(?NFTA_DATA_VALUE, Key)),
    build_elem_msg(?NFT_MSG_DELSETELEM, Family, Table, Set, ElemAttrs, Seq).

%% --- Internal ---

-spec build_elem_msg(0..255, 0..255, binary(), binary(), binary(),
                     non_neg_integer()) -> nfnl_msg:nl_msg().
build_elem_msg(MsgType, Family, Table, Set, ElemAttrs, Seq) ->
    ElemList = nfnl_attr:encode_nested(?NFTA_LIST_ELEM, ElemAttrs),
    Attrs = iolist_to_binary([
        nfnl_attr:encode_str(?NFTA_SET_ELEM_LIST_TABLE, Table),
        nfnl_attr:encode_str(?NFTA_SET_ELEM_LIST_SET, Set),
        nfnl_attr:encode_nested(?NFTA_SET_ELEM_LIST_ELEMENTS, ElemList)
    ]),
    NlFlags = ?NLM_F_REQUEST bor ?NLM_F_ACK bor ?NLM_F_CREATE,
    nfnl_msg:build_hdr(MsgType, Family, NlFlags, Seq, Attrs).
