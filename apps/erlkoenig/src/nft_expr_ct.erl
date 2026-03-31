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

-module(nft_expr_ct).
-moduledoc """
nf_tables conntrack expression.

Loads connection tracking state into a register. Conntrack is the
kernel's stateful packet inspection — it tracks TCP connections,
UDP streams, and ICMP exchanges.

    ct load <key> => reg <N>

The most common use is loading the connection state to match
established connections:

    ct load state => reg 1
    bitwise reg 1 = (reg 1 & 0x06) ^ 0x00
    cmp neq reg 1 0x00
    immediate reg 0 accept

State bits (from nf_conntrack_common.h):
    IP_CT_ESTABLISHED = 0x02
    IP_CT_RELATED     = 0x04
    IP_CT_NEW         = 0x08
    IP_CT_ESTABLISHED_REPLY = 0x20

CT keys (from nft_ct_keys in nf_tables.h):
    state      (0)   Connection state bitmask
    direction  (1)   Original or reply
    status     (2)   Connection status
    mark       (3)   Conntrack mark
    expiration (5)   Time until timeout
    src        (8)   Source address
    dst        (9)   Destination address
    protocol  (10)   L4 protocol
    proto_src (11)   L4 source port
    proto_dst (12)   L4 destination port

Corresponds to libnftnl src/expr/ct.c.
""".

-export([load/2]).

-export_type([ct_key/0]).

%% --- Types ---

-type ct_key() ::
    state
    | direction
    | status
    | mark
    | expiration
    | src
    | dst
    | protocol
    | proto_src
    | proto_dst
    | non_neg_integer().

-include("nft_constants.hrl").

%% --- Public API ---

-doc """
Build a ct load expression.

Loads the specified conntrack key into the given register.

Example:
    %% Load connection state into register 1
    nft_expr_ct:load(state, 1)
""".
-spec load(ct_key(), non_neg_integer()) -> binary().
load(Key, Reg) when is_integer(Reg), Reg >= 0 ->
    Attrs = iolist_to_binary([
        nfnl_attr:encode_u32(?NFTA_CT_KEY, key_val(Key)),
        nfnl_attr:encode_u32(?NFTA_CT_DREG, Reg)
    ]),
    nft_expr:build(<<"ct">>, Attrs).

%% --- Internal ---

-spec key_val(ct_key()) -> non_neg_integer().
key_val(state) -> ?NFT_CT_STATE;
key_val(direction) -> ?NFT_CT_DIRECTION;
key_val(status) -> ?NFT_CT_STATUS;
key_val(mark) -> ?NFT_CT_MARK;
key_val(expiration) -> ?NFT_CT_EXPIRATION;
key_val(src) -> ?NFT_CT_SRC;
key_val(dst) -> ?NFT_CT_DST;
key_val(protocol) -> ?NFT_CT_PROTOCOL;
key_val(proto_src) -> ?NFT_CT_PROTO_SRC;
key_val(proto_dst) -> ?NFT_CT_PROTO_DST;
key_val(N) when is_integer(N), N >= 0 -> N.
