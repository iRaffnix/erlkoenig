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

-module(nft_expr_objref).
-moduledoc """
nf_tables object reference expression.

References a named stateful object (counter, quota, limit) from
within a rule. When the rule matches, the referenced object's
state is updated.

    rule ... objref type counter name "ssh_pkts" ...

This allows multiple rules to share a single counter, and the
counter to persist across rule reloads.

Corresponds to libnftnl src/expr/objref.c.
""".

-export([counter/1]).

-include("nft_constants.hrl").

%% --- Local attribute constants ---

-define(NFTA_OBJREF_IMM_TYPE, 1).
-define(NFTA_OBJREF_IMM_NAME, 2).

%% --- Public API ---

-doc """
Reference a named counter object.

The counter must already exist in the same table. When the rule
containing this expression matches a packet, the named counter
is incremented.

Example:
    nft_expr_objref:counter(<<"ssh_pkts">>)
""".
-spec counter(binary()) -> binary().
counter(Name) when is_binary(Name), byte_size(Name) > 0 ->
    Attrs = iolist_to_binary([
        nfnl_attr:encode_u32(?NFTA_OBJREF_IMM_TYPE, ?NFT_OBJECT_COUNTER),
        nfnl_attr:encode_str(?NFTA_OBJREF_IMM_NAME, Name)
    ]),
    nft_expr:build(<<"objref">>, Attrs).
