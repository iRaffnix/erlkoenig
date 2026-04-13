%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_nft_container).
-moduledoc """
Build nftables netlink batches for per-container firewalls.

Takes a container's nft config (table + chains + rules) and produces
a binary blob that can be sent to the C runtime via CMD_NFT_SETUP.
The C runtime applies it inside the container's network namespace.

The batch is a complete nftables transaction:
  BATCH_BEGIN + DELTABLE(if exists) + NEWTABLE + NEWCHAIN*N + NEWRULE*M + BATCH_END

Reuses the existing nft_encode/nft_table/nft_chain/nft_batch modules.
""".

-export([build_batch/1, build_batch/2]).

-define(FAMILY_INT, 1).  %% inet (dual-stack) for nft_table/nft_delete/nft_chain
-define(FAMILY_ATOM, inet).  %% for nft_encode:rule_fun

-doc """
Build an nft batch from container nft config.

Config shape:
  #{table => <<\"ct_api\">>,
    chains => [
      #{name => <<\"output\">>, hook => output, type => filter,
        priority => 0, policy => drop,
        rules => [{accept, #{ct => established}}, {accept, #{tcp => 5432}}]},
      ...
    ]}
""".
-spec build_batch(map()) -> binary().
build_batch(NftConfig) ->
    build_batch(NftConfig, <<"ct_container">>).

-spec build_batch(map(), binary()) -> binary().
build_batch(#{chains := Chains} = _Config, TableName) ->
    %% Create table (NLM_F_CREATE — succeeds if already exists).
    %% First call: creates. Subsequent calls: no-op, chains/rules are appended.
    %% For atomic replacement: flush chains first, then re-add.
    CreateFun = fun(S) -> nft_table:add(?FAMILY_INT, TableName, S) end,

    ChainFuns = lists:flatmap(fun(Chain) ->
        #{name := CN, hook := Hook, type := Type,
          priority := Prio, policy := Policy} = Chain,
        Rules = maps:get(rules, Chain, []),

        %% Chain creation
        ChainFun = fun(S) -> nft_chain:add(?FAMILY_INT, #{
            table    => TableName,
            name     => CN,
            hook     => Hook,
            type     => Type,
            priority => Prio,
            policy   => Policy
        }, S) end,

        %% Rule encoding — translate DSL keys to internal keys
        RuleFuns = lists:map(fun({Action, Opts}) ->
            InternalOpts = translate_opts(Opts),
            Compiled = erlkoenig_firewall_nft:compile_generic_rule(Action, InternalOpts),
            nft_encode:rule_fun(?FAMILY_ATOM, TableName, CN, Compiled)
        end, Rules),

        [ChainFun | RuleFuns]
    end, Chains),

    AllFuns = [CreateFun | ChainFuns],

    %% Build the batch binary (same as nfnl_server:apply_msgs but without socket)
    {Msgs, _Seqs, _LastSeq} = build_msgs(AllFuns, 1, [], []),
    nft_batch:wrap(Msgs, 0).

%%%===================================================================
%%% Internal — copied from nfnl_server (batch building without socket)
%%%===================================================================

%% Translate DSL option keys to internal keys used by compile_generic_rule.
%% Same mapping as erlkoenig_config:expand_nft_rule but without veth_of/replica_ips.
-spec translate_opts(map()) -> map().
translate_opts(Opts) ->
    maps:fold(fun
        (ct_state, States, Acc) -> Acc#{ct => hd(States)};
        (tcp_dport, Port, Acc) -> Acc#{tcp => Port};
        (udp_dport, Port, Acc) -> Acc#{udp => Port};
        (iifname, V, Acc) -> Acc#{iif => iolist_to_binary(V)};
        (oifname, V, Acc) -> Acc#{oif => iolist_to_binary(V)};
        (oifname_ne, V, Acc) -> Acc#{oif_neq => iolist_to_binary(V)};
        (ip_saddr, {A,B,C,D}, Acc) -> Acc#{saddr => {A,B,C,D,32}};
        (ip_saddr, {A,B,C,D,P}, Acc) -> Acc#{saddr => {A,B,C,D,P}};
        (ip_daddr, {A,B,C,D}, Acc) -> Acc#{daddr => {A,B,C,D,32}};
        (ip_daddr, {A,B,C,D,P}, Acc) -> Acc#{daddr => {A,B,C,D,P}};
        (ip_protocol, Proto, Acc) -> Acc#{protocol => Proto};
        (log_prefix, P, Acc) -> Acc#{log => P};
        (counter, C, Acc) -> Acc#{counter => iolist_to_binary(C)};
        (K, V, Acc) -> Acc#{K => V}
    end, #{}, Opts).

build_msgs([], Seq, MsgAcc, SeqAcc) ->
    {lists:reverse(MsgAcc), lists:reverse(SeqAcc), (Seq - 1) band 16#FFFFFFFF};
build_msgs([Fun | Rest], Seq, MsgAcc, SeqAcc) ->
    Msg = Fun(Seq),
    build_msgs(Rest, (Seq + 1) band 16#FFFFFFFF, [Msg | MsgAcc], [Seq | SeqAcc]).
