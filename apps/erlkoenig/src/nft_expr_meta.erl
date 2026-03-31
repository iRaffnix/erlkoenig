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

-module(nft_expr_meta).
-moduledoc """
nf_tables meta expression.

Loads packet metadata into a register for subsequent comparison.
This is the most common way to inspect packet properties that are
not part of the packet payload itself.

    meta load <key> => reg <N>

Common keys:
    l4proto   (16)  Layer 4 protocol (TCP=6, UDP=17, ICMP=1)
    nfproto   (15)  Netfilter protocol family
    iifname    (6)  Input interface name
    oifname    (7)  Output interface name
    mark       (3)  Packet firewall mark
    len        (0)  Packet length

Corresponds to libnftnl src/expr/meta.c.
""".

-export([load/2]).

-export_type([meta_key/0]).

%% --- Types ---

-type meta_key() ::
    len
    | protocol
    | mark
    | iif
    | oif
    | iifname
    | oifname
    | nfproto
    | l4proto
    | non_neg_integer().
%% Symbolic or numeric meta key. Numeric values are passed through
%% for keys not yet given an atom alias.

-include("nft_constants.hrl").

%% --- Public API ---

-doc """
Build a meta load expression.

Loads the specified metadata key into the given register.

Example:
    %% Load L4 protocol into register 1
    nft_expr_meta:load(l4proto, 1)
""".
-spec load(meta_key(), non_neg_integer()) -> binary().
load(Key, Reg) when is_integer(Reg), Reg >= 0 ->
    Attrs = iolist_to_binary([
        nfnl_attr:encode_u32(?NFTA_META_KEY, key_val(Key)),
        nfnl_attr:encode_u32(?NFTA_META_DREG, Reg)
    ]),
    nft_expr:build(<<"meta">>, Attrs).

%% --- Internal ---

-spec key_val(meta_key()) -> non_neg_integer().
key_val(len) -> ?NFT_META_LEN;
key_val(protocol) -> ?NFT_META_PROTOCOL;
key_val(mark) -> ?NFT_META_MARK;
key_val(iif) -> ?NFT_META_IIF;
key_val(oif) -> ?NFT_META_OIF;
key_val(iifname) -> ?NFT_META_IIFNAME;
key_val(oifname) -> ?NFT_META_OIFNAME;
key_val(nfproto) -> ?NFT_META_NFPROTO;
key_val(l4proto) -> ?NFT_META_L4PROTO;
key_val(N) when is_integer(N), N >= 0 -> N.
