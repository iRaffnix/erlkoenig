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

-module(nft_expr_immediate).
-moduledoc """
nf_tables immediate expression.

Sets a register to a fixed value or verdict. This is how rules
terminate: by loading a verdict (accept, drop, jump, goto, return)
into register 0 (the verdict register).

Two modes of operation:

1. Verdict mode: loads a verdict code into the verdict register.
       immediate reg 0 accept
       immediate reg 0 drop
       immediate reg 0 jump -> mychain

2. Data mode: loads raw data into a general-purpose register.
   (Not yet implemented — needed for SNAT/DNAT addresses.)

Verdict codes (from linux/netfilter/nf_tables.h):
    NF_DROP      =  0
    NF_ACCEPT    =  1
    NFT_JUMP     = -3  (0xFFFFFFFD)  requires chain name
    NFT_GOTO     = -4  (0xFFFFFFFC)  requires chain name
    NFT_RETURN   = -5  (0xFFFFFFFB)

The nested structure for a verdict is:
    NFTA_IMMEDIATE_DREG = 0 (verdict register)
    NFTA_IMMEDIATE_DATA (nested)
      └── NFTA_DATA_VERDICT (nested)
            ├── NFTA_VERDICT_CODE = htonl(code)
            └── NFTA_VERDICT_CHAIN = "name" (only for jump/goto)

Corresponds to libnftnl src/expr/immediate.c.
""".

-export([
    accept/0,
    drop/0,
    return/0,
    verdict/1,
    jump/1,
    goto/1
]).

-export_type([verdict_type/0]).

%% --- Types ---

-type verdict_type() :: accept | drop | return.

-include("nft_constants.hrl").

%% --- Public API ---

-doc "Accept the packet.".
-spec accept() -> binary().
accept() -> verdict(accept).

-doc "Drop the packet.".
-spec drop() -> binary().
drop() -> verdict(drop).

-doc "Return to the calling chain.".
-spec return() -> binary().
return() -> verdict(return).

-doc """
Build a simple verdict expression (accept, drop, or return).

Example:
    nft_expr_immediate:verdict(accept)
""".
-spec verdict(verdict_type()) -> binary().
verdict(V) when is_atom(V) ->
    VerdictNest = nfnl_attr:encode_nested(
        ?NFTA_DATA_VERDICT,
        nfnl_attr:encode_u32(?NFTA_VERDICT_CODE, verdict_code(V))
    ),
    build_verdict(VerdictNest).

-doc """
Jump to a named chain. Processing continues at the target chain
and returns here when the target chain is fully evaluated or
a return verdict is reached.

Example:
    nft_expr_immediate:jump(<<"rate_limit">>)
""".
-spec jump(binary()) -> binary().
jump(Chain) when is_binary(Chain), byte_size(Chain) > 0 ->
    chain_verdict(?NFT_JUMP, Chain).

-doc """
Goto a named chain. Like jump, but does not return to the
calling chain. Equivalent to a tail call.

Example:
    nft_expr_immediate:goto(<<"blocklist">>)
""".
-spec goto(binary()) -> binary().
goto(Chain) when is_binary(Chain), byte_size(Chain) > 0 ->
    chain_verdict(?NFT_GOTO, Chain).

%% --- Internal ---

-spec chain_verdict(4294967292 | 4294967293, binary()) -> binary().
chain_verdict(Code, Chain) ->
    VerdictNest = nfnl_attr:encode_nested(
        ?NFTA_DATA_VERDICT,
        iolist_to_binary([
            nfnl_attr:encode_u32(?NFTA_VERDICT_CODE, Code),
            nfnl_attr:encode_str(?NFTA_VERDICT_CHAIN, Chain)
        ])
    ),
    build_verdict(VerdictNest).

-spec build_verdict(<<_:32, _:_*8>>) -> binary().
build_verdict(VerdictNest) ->
    DataNest = nfnl_attr:encode_nested(?NFTA_IMMEDIATE_DATA, VerdictNest),
    Attrs = iolist_to_binary([
        nfnl_attr:encode_u32(?NFTA_IMMEDIATE_DREG, ?NFT_REG_VERDICT),
        DataNest
    ]),
    nft_expr:build(<<"immediate">>, Attrs).

-spec verdict_code(verdict_type()) -> 0 | 1 | 4294967291.
verdict_code(accept) -> ?NF_ACCEPT;
verdict_code(drop) -> ?NF_DROP;
verdict_code(return) -> ?NFT_RETURN.
