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

-module(nft_flowtable).
-moduledoc """
nf_tables flowtable operations.

A flowtable declares a fast-path offload point. Packets matching
established connections can be offloaded to the flowtable's ingress
hook, bypassing the full nf_tables evaluation pipeline.

Flowtables are attached to one or more network devices at the
ingress hook (hooknum=0 in NF_NETDEV_INGRESS).

Corresponds to NFT_MSG_NEWFLOWTABLE (0x16) in nf_tables.h.
""".

-export([add/3]).

-export_type([flowtable_opts/0]).

%% --- Types ---

-type flowtable_opts() :: #{
    table := binary(),
    name := binary(),
    hook := ingress,
    priority => integer(),
    devices => [binary()],
    flags => non_neg_integer()
}.
%% Required keys: table, name, hook.
%% Defaults: priority=0, devices=[], flags=0.

-include("nft_constants.hrl").

%% --- Public API ---

-doc """
Build a NEWFLOWTABLE message.

Creates a flowtable with the given name in the specified table,
attached to the ingress hook on the listed devices.

Example:
    Msg = nft_flowtable:add(1, #{
        table    => <<"fw">>,
        name     => <<"ft0">>,
        hook     => ingress,
        priority => 0,
        devices  => [<<"eth0">>, <<"eth1">>],
        flags    => 0
    }, Seq).
""".
-spec add(0..255, flowtable_opts(), non_neg_integer()) -> nfnl_msg:nl_msg().
add(Family, Opts, Seq) when
    is_integer(Family),
    Family >= 0,
    Family =< 255,
    is_map(Opts),
    is_integer(Seq),
    Seq >= 0
->
    Table = maps:get(table, Opts),
    Name = maps:get(name, Opts),
    Prio = maps:get(priority, Opts, 0),
    Devices = maps:get(devices, Opts, []),
    FtFlags = maps:get(flags, Opts, 0),

    HookNest = nfnl_attr:encode_nested(
        ?NFTA_FLOWTABLE_HOOK,
        iolist_to_binary([
            nfnl_attr:encode_u32(?NFTA_FLOWTABLE_HOOK_NUM, ?NF_NETDEV_INGRESS),
            nfnl_attr:encode(?NFTA_FLOWTABLE_HOOK_PRIORITY, <<Prio:32/big-signed>>)
        ])
    ),

    DevsNest =
        case Devices of
            [] ->
                <<>>;
            _ ->
                DevAttrs = iolist_to_binary(
                    [nfnl_attr:encode_str(?NFTA_DEVICE_NAME, D) || D <- Devices]
                ),
                nfnl_attr:encode_nested(?NFTA_FLOWTABLE_DEVS, DevAttrs)
        end,

    Attrs = iolist_to_binary([
        nfnl_attr:encode_str(?NFTA_FLOWTABLE_TABLE, Table),
        nfnl_attr:encode_str(?NFTA_FLOWTABLE_NAME, Name),
        HookNest,
        DevsNest,
        nfnl_attr:encode_u32(?NFTA_FLOWTABLE_FLAGS, FtFlags)
    ]),

    Flags = ?NLM_F_REQUEST bor ?NLM_F_ACK bor ?NLM_F_CREATE,
    nfnl_msg:build_hdr(?NFT_MSG_NEWFLOWTABLE, Family, Flags, Seq, Attrs).
