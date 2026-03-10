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

-module(nft_table).
-moduledoc """
nf_tables table operations.

A table is the top-level container in nf_tables. It holds chains,
sets, and stateful objects. Every table belongs to a protocol family
(inet, ipv4, ipv6, arp, bridge, netdev).

Protocol families:
    0  = unspec
    1  = inet    (dual-stack, most common)
    2  = ipv4
    3  = arp
    5  = netdev
    7  = bridge
    10 = ipv6

Corresponds to libnftnl src/table.c.
""".

-export([add/3]).

%% --- Constants ---

-define(NFT_MSG_NEWTABLE, 0).

%% NFTA_TABLE_* from linux/netfilter/nf_tables.h
-define(NFTA_TABLE_NAME,  1).
-define(NFTA_TABLE_FLAGS, 2).

-define(NLM_F_REQUEST, 16#0001).
-define(NLM_F_ACK,     16#0004).
-define(NLM_F_CREATE,  16#0400).

%% --- Public API ---

-doc """
Build a NEWTABLE message.

Creates a table with the given name in the specified protocol family.
The message must be wrapped in a batch before sending.

Example:
    Msg = nft_table:add(1, <<"fw">>, Seq),
    Batch = nft_batch:wrap([Msg], Seq).
""".
-spec add(0..255, binary(), non_neg_integer()) -> nfnl_msg:nl_msg().
add(Family, Name, Seq)
  when is_integer(Family), Family >= 0, Family =< 255,
       is_binary(Name), byte_size(Name) > 0,
       is_integer(Seq), Seq >= 0 ->
    Attrs = iolist_to_binary([
        nfnl_attr:encode_str(?NFTA_TABLE_NAME, Name),
        nfnl_attr:encode_u32(?NFTA_TABLE_FLAGS, 0)
    ]),
    Flags = ?NLM_F_REQUEST bor ?NLM_F_ACK bor ?NLM_F_CREATE,
    nfnl_msg:build_hdr(?NFT_MSG_NEWTABLE, Family, Flags, Seq, Attrs).
