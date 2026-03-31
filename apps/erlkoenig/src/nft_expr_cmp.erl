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

-module(nft_expr_cmp).
-moduledoc """
nf_tables compare expression.

Compares the contents of a register against a fixed value.
Typically used after a meta or payload expression has loaded
data into the register.

    cmp <op> reg <N> <value>

If the comparison fails, the kernel stops evaluating the current
rule and moves to the next one. This is how nf_tables implements
matching: a chain of load-compare pairs that all must succeed
for the rule's verdict to apply.

Operators:
    eq   (0)  Equal
    neq  (1)  Not equal
    lt   (2)  Less than
    lte  (3)  Less than or equal
    gt   (4)  Greater than
    gte  (5)  Greater than or equal

The comparison value is raw bytes in network byte order, matching
what the meta/payload expression loaded into the register.

Corresponds to libnftnl src/expr/cmp.c.
""".

-export([eq/2, neq/2, lt/2, lte/2, gt/2, gte/2, cmp/3]).

-export_type([cmp_op/0]).

%% --- Types ---

-type cmp_op() :: eq | neq | lt | lte | gt | gte.

-include("nft_constants.hrl").

%% --- Public API ---

-doc "Compare register equal to value.".
-spec eq(non_neg_integer(), binary()) -> binary().
eq(Reg, Value) -> cmp(eq, Reg, Value).

-doc "Compare register not equal to value.".
-spec neq(non_neg_integer(), binary()) -> binary().
neq(Reg, Value) -> cmp(neq, Reg, Value).

-doc "Compare register less than value.".
-spec lt(non_neg_integer(), binary()) -> binary().
lt(Reg, Value) -> cmp(lt, Reg, Value).

-doc "Compare register less than or equal to value.".
-spec lte(non_neg_integer(), binary()) -> binary().
lte(Reg, Value) -> cmp(lte, Reg, Value).

-doc "Compare register greater than value.".
-spec gt(non_neg_integer(), binary()) -> binary().
gt(Reg, Value) -> cmp(gt, Reg, Value).

-doc "Compare register greater than or equal to value.".
-spec gte(non_neg_integer(), binary()) -> binary().
gte(Reg, Value) -> cmp(gte, Reg, Value).

-doc """
Build a compare expression with explicit operator.

Reg is the source register to compare.
Value is the raw comparison data in network byte order.

Example:
    %% Check if register 1 equals TCP (protocol 6)
    nft_expr_cmp:cmp(eq, 1, <<6>>)

    %% Check if register 1 equals port 80 (big-endian)
    nft_expr_cmp:cmp(eq, 1, <<0, 80>>)
""".
-spec cmp(cmp_op(), non_neg_integer(), binary()) -> binary().
cmp(Op, Reg, Value) when
    is_atom(Op), is_integer(Reg), Reg >= 0, is_binary(Value)
->
    DataNest = nfnl_attr:encode_nested(
        ?NFTA_CMP_DATA,
        nfnl_attr:encode(?NFTA_DATA_VALUE, Value)
    ),
    Attrs = iolist_to_binary([
        nfnl_attr:encode_u32(?NFTA_CMP_SREG, Reg),
        nfnl_attr:encode_u32(?NFTA_CMP_OP, op_val(Op)),
        DataNest
    ]),
    nft_expr:build(<<"cmp">>, Attrs).

%% --- Internal ---

-spec op_val(cmp_op()) -> 0..5.
op_val(eq) -> ?NFT_CMP_EQ;
op_val(neq) -> ?NFT_CMP_NEQ;
op_val(lt) -> ?NFT_CMP_LT;
op_val(lte) -> ?NFT_CMP_LTE;
op_val(gt) -> ?NFT_CMP_GT;
op_val(gte) -> ?NFT_CMP_GTE.
