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

-module(nft_chain).
-moduledoc """
nf_tables chain operations.

A chain lives inside a table and holds an ordered list of rules.
Base chains are attached to a netfilter hook (input, forward, output, ...)
and have a type and default policy. Regular chains are not attached to
a hook and are reached via jump/goto from other chains.

Hook points (inet/ip/ip6):
    prerouting  = 0   Before routing decision
    input       = 1   Destined for local process
    forward     = 2   Routed through this host
    output      = 3   From local process
    postrouting = 4   After routing decision

Chain types:
    filter   Most common, for accept/drop decisions
    nat      For SNAT/DNAT (only in nat hooks)
    route    For rerouting (only in output hook)

The hook attributes are encoded as a nested TLV inside the chain
message, matching libnftnl's NFTA_CHAIN_HOOK nesting in src/chain.c.

Corresponds to libnftnl src/chain.c.
""".

-export([add/3, add_regular/3]).

-export_type([hook/0, chain_type/0, policy/0, chain_opts/0]).

%% --- Types ---

-type hook() :: prerouting | input | forward | output | postrouting.

-type chain_type() :: filter | nat | route.

-type policy() :: accept | drop.

-type chain_opts() :: #{
    table    := binary(),
    name     := binary(),
    hook     := hook(),
    type     => chain_type(),
    priority => integer(),
    policy   => policy()
}.
%% Required keys: table, name, hook.
%% Defaults: type=filter, priority=0, policy=accept.

-include("nft_constants.hrl").

%% --- Local constants ---

-define(NFT_MSG_NEWCHAIN, 3).

-define(NFTA_CHAIN_TABLE,  1).
-define(NFTA_CHAIN_NAME,   3).
-define(NFTA_CHAIN_HOOK,   4).
-define(NFTA_CHAIN_POLICY, 5).
-define(NFTA_CHAIN_TYPE,   7).

-define(NFTA_HOOK_HOOKNUM,  1).
-define(NFTA_HOOK_PRIORITY, 2).

-define(NLM_F_REQUEST, 16#0001).
-define(NLM_F_ACK,     16#0004).
-define(NLM_F_CREATE,  16#0400).

%% --- Public API ---

-doc """
Build a NEWCHAIN message for a base chain.

Creates a chain attached to a netfilter hook with the given type
and default policy. The message must be wrapped in a batch.

Example:
    Msg = nft_chain:add(1, #{
        table    => <<"fw">>,
        name     => <<"input">>,
        hook     => input,
        type     => filter,
        priority => 0,
        policy   => accept
    }, Seq).
""".
-spec add(0..255, chain_opts(), non_neg_integer()) -> nfnl_msg:nl_msg().
add(Family, Opts, Seq)
  when is_integer(Family), Family >= 0, Family =< 255,
       is_map(Opts), is_integer(Seq), Seq >= 0 ->
    Table = maps:get(table, Opts),
    Name  = maps:get(name, Opts),
    Hook  = hook_num(maps:get(hook, Opts)),
    Prio  = maps:get(priority, Opts, 0),
    Type  = atom_to_binary(maps:get(type, Opts, filter)),
    Pol   = policy_val(maps:get(policy, Opts, accept)),

    HookNest = nfnl_attr:encode_nested(?NFTA_CHAIN_HOOK,
        iolist_to_binary([
            nfnl_attr:encode_u32(?NFTA_HOOK_HOOKNUM, Hook),
            nfnl_attr:encode(?NFTA_HOOK_PRIORITY, <<Prio:32/big-signed>>)
        ])),

    Attrs = iolist_to_binary([
        nfnl_attr:encode_str(?NFTA_CHAIN_TABLE, Table),
        nfnl_attr:encode_str(?NFTA_CHAIN_NAME, Name),
        HookNest,
        nfnl_attr:encode_u32(?NFTA_CHAIN_POLICY, Pol),
        nfnl_attr:encode_str(?NFTA_CHAIN_TYPE, Type)
    ]),

    Flags = ?NLM_F_REQUEST bor ?NLM_F_ACK bor ?NLM_F_CREATE,
    nfnl_msg:build_hdr(?NFT_MSG_NEWCHAIN, Family, Flags, Seq, Attrs).

-doc """
Build a NEWCHAIN message for a regular chain (no hook).

Regular chains are not attached to a netfilter hook. They are
reached via jump/goto from base chains or other regular chains.

Example:
    Msg = nft_chain:add_regular(1, #{
        table => <<"fw">>,
        name  => <<"ct_abc123">>
    }, Seq).
""".
-spec add_regular(0..255, #{table := binary(), name := binary()},
                  non_neg_integer()) -> nfnl_msg:nl_msg().
add_regular(Family, #{table := Table, name := Name}, Seq)
  when is_integer(Family), Family >= 0, Family =< 255,
       is_binary(Table), byte_size(Table) > 0,
       is_binary(Name), byte_size(Name) > 0,
       is_integer(Seq), Seq >= 0 ->
    Attrs = iolist_to_binary([
        nfnl_attr:encode_str(?NFTA_CHAIN_TABLE, Table),
        nfnl_attr:encode_str(?NFTA_CHAIN_NAME, Name)
    ]),
    Flags = ?NLM_F_REQUEST bor ?NLM_F_ACK bor ?NLM_F_CREATE,
    nfnl_msg:build_hdr(?NFT_MSG_NEWCHAIN, Family, Flags, Seq, Attrs).

%% --- Internal ---

-spec hook_num(hook()) -> 0..4.
hook_num(prerouting)  -> ?NF_INET_PRE_ROUTING;
hook_num(input)       -> ?NF_INET_LOCAL_IN;
hook_num(forward)     -> ?NF_INET_FORWARD;
hook_num(output)      -> ?NF_INET_LOCAL_OUT;
hook_num(postrouting) -> ?NF_INET_POST_ROUTING.

-spec policy_val(policy()) -> 0..1.
policy_val(accept) -> ?NF_ACCEPT;
policy_val(drop)   -> ?NF_DROP.
