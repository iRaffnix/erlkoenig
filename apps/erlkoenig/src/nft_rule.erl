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

-module(nft_rule).
-moduledoc """
nf_tables rule operations.

A rule is an ordered list of expressions that the kernel evaluates
left to right. If all match expressions succeed, the terminal
expression (typically a verdict like accept or drop) is executed.

A rule belongs to a table and chain. The NLM_F_APPEND flag causes
the rule to be appended at the end of the chain.

The expressions are wrapped in a nested NFTA_RULE_EXPRESSIONS
attribute, with each expression in its own NFTA_LIST_ELEM container:

    NFTA_RULE_TABLE = "fw"
    NFTA_RULE_CHAIN = "input"
    NFTA_RULE_EXPRESSIONS (nested)
      ├── NFTA_LIST_ELEM (nested) = meta expression
      ├── NFTA_LIST_ELEM (nested) = cmp expression
      ├── NFTA_LIST_ELEM (nested) = payload expression
      ├── NFTA_LIST_ELEM (nested) = cmp expression
      └── NFTA_LIST_ELEM (nested) = immediate expression

Corresponds to libnftnl src/rule.c.
""".

-export([add/5]).

-include("nft_constants.hrl").

%% --- Public API ---

-doc """
Build a NEWRULE message that appends a rule to the given chain.

Expressions is a list of pre-built expression binaries from the
nft_expr_* modules. They are evaluated in order by the kernel.

The message must be wrapped in a batch before sending.

Example:
    %% tcp dport 80 accept
    Msg = nft_rule:add(1, <<"fw">>, <<"input">>, [
        nft_expr_meta:load(l4proto, 1),
        nft_expr_cmp:eq(1, <<6>>),
        nft_expr_payload:tcp_dport(1),
        nft_expr_cmp:eq(1, <<0, 80>>),
        nft_expr_immediate:accept()
    ], Seq).
""".
-spec add(0..255, binary(), binary(), [binary()], non_neg_integer()) -> nfnl_msg:nl_msg().
add(Family, Table, Chain, Expressions, Seq) when
    is_integer(Family),
    Family >= 0,
    Family =< 255,
    is_binary(Table),
    byte_size(Table) > 0,
    is_binary(Chain),
    byte_size(Chain) > 0,
    is_list(Expressions),
    is_integer(Seq),
    Seq >= 0
->
    ExprBin = iolist_to_binary([nfnl_attr:encode_nested(?NFTA_LIST_ELEM, E) || E <- Expressions]),
    Attrs = iolist_to_binary([
        nfnl_attr:encode_str(?NFTA_RULE_TABLE, Table),
        nfnl_attr:encode_str(?NFTA_RULE_CHAIN, Chain),
        nfnl_attr:encode_nested(?NFTA_RULE_EXPRESSIONS, ExprBin)
    ]),
    Flags = ?NLM_F_REQUEST bor ?NLM_F_ACK bor ?NLM_F_CREATE bor ?NLM_F_APPEND,
    nfnl_msg:build_hdr(?NFT_MSG_NEWRULE, Family, Flags, Seq, Attrs).
