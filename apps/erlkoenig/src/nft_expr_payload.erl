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

-module(nft_expr_payload).
-moduledoc """
nf_tables payload expression.

Loads bytes from the packet into a register for subsequent comparison.
The payload expression specifies which protocol layer (base), the byte
offset within that layer, and how many bytes to load.

    payload load <len>b @ <base> header + <offset> => reg <N>

Bases:
    link      (0)  Link layer (Ethernet)
    network   (1)  Network layer (IP)
    transport (2)  Transport layer (TCP/UDP/ICMP)

Common field offsets:
    TCP/UDP sport:   base=transport, offset=0, len=2
    TCP/UDP dport:   base=transport, offset=2, len=2
    IPv4 saddr:      base=network,   offset=12, len=4
    IPv4 daddr:      base=network,   offset=16, len=4
    IPv4 protocol:   base=network,   offset=9,  len=1

Loaded data is in network byte order (big-endian), which is why
cmp values must also be big-endian.

Corresponds to libnftnl src/expr/payload.c.
""".

-export([
    load/4,
    tcp_sport/1,
    tcp_dport/1,
    udp_sport/1,
    udp_dport/1,
    ip_saddr/1,
    ip_daddr/1,
    ip_protocol/1
]).

-export_type([base/0]).

%% --- Types ---

-type base() :: link | network | transport | non_neg_integer().
%% Protocol layer base. Numeric values are passed through for
%% bases not yet given an atom alias (e.g. inner=3, tunnel=4).

-include("nft_constants.hrl").

%% --- Public API ---

-doc """
Build a payload load expression.

Loads Len bytes from Base + Offset into the given register.

Example:
    %% Load 2 bytes from transport header offset 2 (dport) into reg 1
    nft_expr_payload:load(transport, 2, 2, 1)
""".
-spec load(base(), non_neg_integer(), pos_integer(), non_neg_integer()) -> binary().
load(Base, Offset, Len, Reg) when
    is_integer(Offset),
    Offset >= 0,
    is_integer(Len),
    Len > 0,
    is_integer(Reg),
    Reg >= 0
->
    Attrs = iolist_to_binary([
        nfnl_attr:encode_u32(?NFTA_PAYLOAD_DREG, Reg),
        nfnl_attr:encode_u32(?NFTA_PAYLOAD_BASE, base_val(Base)),
        nfnl_attr:encode_u32(?NFTA_PAYLOAD_OFFSET, Offset),
        nfnl_attr:encode_u32(?NFTA_PAYLOAD_LEN, Len)
    ]),
    nft_expr:build(<<"payload">>, Attrs).

%% --- Convenience ---

-doc "Load TCP source port (2 bytes) into register.".
-spec tcp_sport(non_neg_integer()) -> binary().
tcp_sport(Reg) -> load(transport, 0, 2, Reg).

-doc "Load TCP destination port (2 bytes) into register.".
-spec tcp_dport(non_neg_integer()) -> binary().
tcp_dport(Reg) -> load(transport, 2, 2, Reg).

-doc "Load UDP source port (2 bytes) into register.".
-spec udp_sport(non_neg_integer()) -> binary().
udp_sport(Reg) -> load(transport, 0, 2, Reg).

-doc "Load UDP destination port (2 bytes) into register.".
-spec udp_dport(non_neg_integer()) -> binary().
udp_dport(Reg) -> load(transport, 2, 2, Reg).

-doc "Load IPv4 source address (4 bytes) into register.".
-spec ip_saddr(non_neg_integer()) -> binary().
ip_saddr(Reg) -> load(network, 12, 4, Reg).

-doc "Load IPv4 destination address (4 bytes) into register.".
-spec ip_daddr(non_neg_integer()) -> binary().
ip_daddr(Reg) -> load(network, 16, 4, Reg).

-doc "Load IPv4 protocol field (1 byte) into register.".
-spec ip_protocol(non_neg_integer()) -> binary().
ip_protocol(Reg) -> load(network, 9, 1, Reg).

%% --- Internal ---

-spec base_val(base()) -> non_neg_integer().
base_val(link) -> ?NFT_PAYLOAD_LL_HEADER;
base_val(network) -> ?NFT_PAYLOAD_NETWORK_HEADER;
base_val(transport) -> ?NFT_PAYLOAD_TRANSPORT_HEADER;
base_val(N) when is_integer(N), N >= 0 -> N.
