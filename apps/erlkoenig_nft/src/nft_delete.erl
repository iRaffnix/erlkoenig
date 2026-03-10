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

-module(nft_delete).
-moduledoc """
nf_tables delete operations.

Deletes tables, chains, rules, and sets via Netlink. Each function
builds a message with the corresponding NFT_MSG_DEL* type.

For tables and chains, the name is sufficient to identify the object.
For rules, a handle is needed (obtained via get/list operations).
For sets, the name identifies the set within the table.

All delete messages must be wrapped in a batch before sending.

Note: deleting a table also deletes all chains, rules, and sets
within it. This is the simplest way to do a full cleanup.
""".

-export([table/3,
         chain/4,
         flush_chain/4,
         rule/5,
         set/4]).

%% --- Constants ---

-define(NFT_MSG_DELTABLE, 2).
-define(NFT_MSG_DELCHAIN, 5).
-define(NFT_MSG_DELRULE,  8).
-define(NFT_MSG_DELSET,  11).

-define(NFTA_TABLE_NAME,  1).
-define(NFTA_CHAIN_TABLE, 1).
-define(NFTA_CHAIN_NAME,  3).
-define(NFTA_RULE_TABLE,  1).
-define(NFTA_RULE_CHAIN,  2).
-define(NFTA_RULE_HANDLE, 3).
-define(NFTA_SET_TABLE,   1).
-define(NFTA_SET_NAME,    2).

-define(NLM_F_REQUEST, 16#0001).
-define(NLM_F_ACK,     16#0004).

%% --- Public API ---

-doc """
Delete a table and everything in it.

Example:
    Msg = nft_delete:table(1, <<"fw">>, Seq)
""".
-spec table(0..255, binary(), non_neg_integer()) -> nfnl_msg:nl_msg().
table(Family, Name, Seq)
  when is_integer(Family), is_binary(Name), is_integer(Seq) ->
    Attrs = nfnl_attr:encode_str(?NFTA_TABLE_NAME, Name),
    Flags = ?NLM_F_REQUEST bor ?NLM_F_ACK,
    nfnl_msg:build_hdr(?NFT_MSG_DELTABLE, Family, Flags, Seq, Attrs).

-doc """
Delete a chain from a table.

The chain must be empty (no rules) unless the table itself is
being deleted.

Example:
    Msg = nft_delete:chain(1, <<"fw">>, <<"input">>, Seq)
""".
-spec chain(0..255, binary(), binary(), non_neg_integer()) -> nfnl_msg:nl_msg().
chain(Family, Table, Name, Seq)
  when is_integer(Family), is_binary(Table), is_binary(Name), is_integer(Seq) ->
    Attrs = iolist_to_binary([
        nfnl_attr:encode_str(?NFTA_CHAIN_TABLE, Table),
        nfnl_attr:encode_str(?NFTA_CHAIN_NAME, Name)
    ]),
    Flags = ?NLM_F_REQUEST bor ?NLM_F_ACK,
    nfnl_msg:build_hdr(?NFT_MSG_DELCHAIN, Family, Flags, Seq, Attrs).

-doc """
Flush (delete) all rules from a chain without deleting the chain itself.

Sends NFT_MSG_DELRULE with table and chain but no handle,
which the kernel interprets as "delete all rules in this chain".

Example:
    Msg = nft_delete:flush_chain(1, <<"fw">>, <<"input">>, Seq)
""".
-spec flush_chain(0..255, binary(), binary(), non_neg_integer()) -> nfnl_msg:nl_msg().
flush_chain(Family, Table, Chain, Seq)
  when is_integer(Family), is_binary(Table), is_binary(Chain), is_integer(Seq) ->
    Attrs = iolist_to_binary([
        nfnl_attr:encode_str(?NFTA_RULE_TABLE, Table),
        nfnl_attr:encode_str(?NFTA_RULE_CHAIN, Chain)
    ]),
    Flags = ?NLM_F_REQUEST bor ?NLM_F_ACK,
    nfnl_msg:build_hdr(?NFT_MSG_DELRULE, Family, Flags, Seq, Attrs).

-doc """
Delete a specific rule by its handle.

The handle is a unique identifier assigned by the kernel when the
rule is created. Use nft_query:list_rules/3 to find handles.

Example:
    Msg = nft_delete:rule(1, <<"fw">>, <<"input">>, 5, Seq)
""".
-spec rule(0..255, binary(), binary(), non_neg_integer(), non_neg_integer()) ->
    nfnl_msg:nl_msg().
rule(Family, Table, Chain, Handle, Seq)
  when is_integer(Family), is_binary(Table), is_binary(Chain),
       is_integer(Handle), is_integer(Seq) ->
    Attrs = iolist_to_binary([
        nfnl_attr:encode_str(?NFTA_RULE_TABLE, Table),
        nfnl_attr:encode_str(?NFTA_RULE_CHAIN, Chain),
        nfnl_attr:encode_u64(?NFTA_RULE_HANDLE, Handle)
    ]),
    Flags = ?NLM_F_REQUEST bor ?NLM_F_ACK,
    nfnl_msg:build_hdr(?NFT_MSG_DELRULE, Family, Flags, Seq, Attrs).

-doc """
Delete a named set from a table.

The set must not be referenced by any rule's lookup expression.

Example:
    Msg = nft_delete:set(1, <<"fw">>, <<"banned">>, Seq)
""".
-spec set(0..255, binary(), binary(), non_neg_integer()) -> nfnl_msg:nl_msg().
set(Family, Table, Name, Seq)
  when is_integer(Family), is_binary(Table), is_binary(Name), is_integer(Seq) ->
    Attrs = iolist_to_binary([
        nfnl_attr:encode_str(?NFTA_SET_TABLE, Table),
        nfnl_attr:encode_str(?NFTA_SET_NAME, Name)
    ]),
    Flags = ?NLM_F_REQUEST bor ?NLM_F_ACK,
    nfnl_msg:build_hdr(?NFT_MSG_DELSET, Family, Flags, Seq, Attrs).
