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

-module(nft_expr_counter).
-moduledoc """
nf_tables counter expression.

Counts packets and bytes matching a rule. When added to a rule,
the kernel maintains running totals that can be queried.

    counter packets 0 bytes 0

The counter is typically placed before the verdict expression so
it counts all packets that reach that point in the rule:

    tcp dport 80 counter accept

To read counter values, use nft_query:get_rules/3 which sends
NFT_MSG_GETRULE and parses the response including counter data.

Attribute encoding uses htobe64 (big-endian 64-bit), matching
libnftnl src/expr/counter.c.

Corresponds to libnftnl src/expr/counter.c.
""".

-export([new/0, new/2]).

-include("nft_constants.hrl").

%% --- Public API ---

-doc "Add a zero-initialized counter to a rule.".
-spec new() -> binary().
new() ->
    new(0, 0).

-doc """
Add a counter with initial values.

Typically both are 0. Non-zero values can be used to restore
counters after a rule reload.
""".
-spec new(non_neg_integer(), non_neg_integer()) -> binary().
new(Packets, Bytes) when
    is_integer(Packets),
    Packets >= 0,
    is_integer(Bytes),
    Bytes >= 0
->
    Attrs = iolist_to_binary([
        nfnl_attr:encode_u64(?NFTA_COUNTER_BYTES, Bytes),
        nfnl_attr:encode_u64(?NFTA_COUNTER_PACKETS, Packets)
    ]),
    nft_expr:build(<<"counter">>, Attrs).
