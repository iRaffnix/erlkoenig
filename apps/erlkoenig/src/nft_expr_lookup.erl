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

-module(nft_expr_lookup).
-moduledoc """
nf_tables lookup expression.

Checks if a register value exists in a named set. This is how
sets are referenced from rules.

    lookup reg <N> set <name>

With the NFT_LOOKUP_F_INV flag, the match is inverted ("not in set").

Corresponds to libnftnl src/expr/lookup.c.
""".

-export([match/3, not_match/3]).

-include("nft_constants.hrl").

%% --- Public API ---

-doc """
Build a lookup expression: check if register is in set.

Example:
    %% Check if register 1 is in set "banned"
    nft_expr_lookup:match(1, <<"banned">>, 1)
""".
-spec match(non_neg_integer(), binary(), non_neg_integer()) -> binary().
match(Reg, SetName, SetId) when is_integer(Reg), is_binary(SetName) ->
    Attrs = iolist_to_binary([
        nfnl_attr:encode_str(?NFTA_LOOKUP_SET, SetName),
        nfnl_attr:encode_u32(?NFTA_LOOKUP_SREG, Reg),
        nfnl_attr:encode_u32(?NFTA_LOOKUP_SET_ID, SetId)
    ]),
    nft_expr:build(<<"lookup">>, Attrs).

-doc "Build a lookup expression: check if register is NOT in set.".
-spec not_match(non_neg_integer(), binary(), non_neg_integer()) -> binary().
not_match(Reg, SetName, SetId) when is_integer(Reg), is_binary(SetName) ->
    Attrs = iolist_to_binary([
        nfnl_attr:encode_str(?NFTA_LOOKUP_SET, SetName),
        nfnl_attr:encode_u32(?NFTA_LOOKUP_SREG, Reg),
        nfnl_attr:encode_u32(?NFTA_LOOKUP_SET_ID, SetId),
        nfnl_attr:encode_u32(?NFTA_LOOKUP_FLAGS, ?NFT_LOOKUP_F_INV)
    ]),
    nft_expr:build(<<"lookup">>, Attrs).
