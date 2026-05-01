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
  BATCH_BEGIN + NEWTABLE + DELTABLE + NEWTABLE + NEWCHAIN*N + NEWRULE*M + BATCH_END

Reuses the existing nft_encode/nft_table/nft_chain/nft_batch modules.
""".

-export([build_batch/1, build_batch/2]).

%% translate_opts is the validation seam — exported under TEST so unit
%% tests can exercise the per-key translation and failure modes
%% without having to round-trip through nft_batch + netlink encoding.
-ifdef(TEST).
-export([translate_opts/1]).
-endif.

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
    build_batch(NftConfig, maps:get(table, NftConfig, <<"ct_container">>)).

-spec build_batch(map(), binary()) -> binary().
build_batch(#{chains := Chains} = _Config, TableName) ->
    %% Atomic replace in the container netns. The leading add makes the
    %% delete deterministic even on first apply; the second add installs
    %% the fresh table before chains and rules are appended.
    EnsureFun = fun(S) -> nft_table:add(?FAMILY_INT, TableName, S) end,
    DeleteFun = fun(S) -> nft_delete:table(?FAMILY_INT, TableName, S) end,
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
            Compiled = erlkoenig_ct_firewall:compile_generic_rule(Action, InternalOpts),
            nft_encode:rule_fun(?FAMILY_ATOM, TableName, CN, Compiled)
        end, Rules),

        [ChainFun | RuleFuns]
    end, Chains),

    AllFuns = [EnsureFun, DeleteFun, CreateFun | ChainFuns],

    %% Build the batch binary (same as nfnl_server:apply_msgs but without socket)
    {Msgs, _Seqs, _LastSeq} = build_msgs(AllFuns, 1, [], []),
    nft_batch:wrap(Msgs, 0).

%%%===================================================================
%%% Internal — copied from nfnl_server (batch building without socket)
%%%===================================================================

%% Translate DSL option keys to internal keys used by compile_generic_rule.
%% Same mapping as erlkoenig_config_nft:expand_nft_rule but without
%% replica_ips (cross-container ref unresolvable in own netns) and with
%% an explicit `veth_of` refusal guard for operator-supplied raw terms.
%%
%% Note: container-local nft runs in the container's netns and knows
%% ONLY its own IP.  Cross-container references
%% (`{:replica_ips, "backend", "api"}`) cannot be resolved here — the
%% target pod's IPs may not even exist yet when this container
%% spawns.  We fail loud rather than silently drop the constraint
%% (which would widen the rule from "only from backend api" to
%% "from any IP" — a Glasbox violation that turned a declared
%% security boundary into no boundary at all).
%%
%% Fix for the operator: move cross-container refs into the host
%% `nft_table` (lifts to the host netns, has full IpMap, resolves
%% replica_ips at load-time).
-spec translate_opts(map()) -> map().
translate_opts(Opts) ->
    maps:fold(fun
        (ct_state, States, Acc) when is_list(States), States =/= [] ->
            %% Downstream `compile_generic_rule' only recognises
            %% `ct => established', which maps to `nft_rules:ct_established_accept/0' —
            %% that expression already matches established OR related
            %% via a bitwise-OR mask, so the canonical DSL forms
            %% `[:established]' / `[:established, :related]' both
            %% resolve correctly. But `hd(States)' used to silently
            %% drop the tail and worse: a list starting with any OTHER
            %% atom (`[:new]', `[:invalid]', `[:new, :established]')
            %% produced a `ct => new'-style key that compile_generic_rule
            %% doesn't recognise → no ct filter at all → rule fires on
            %% ALL conntrack states, wider than the operator declared.
            %% Fail loud for unsupported state lists so the operator
            %% sees the limitation instead of a quietly-wider rule.
            case lists:all(fun(S) ->
                                S =:= established orelse S =:= related
                           end, States) of
                true ->
                    Acc#{ct => established};
                false ->
                    error({unsupported_ct_state,
                           #{states => States,
                             supported => [established, related],
                             hint => <<"container-local nft ct_state only "
                                       "supports [:established] and/or "
                                       "[:related]. For `new`/`invalid` "
                                       "matches, express them at host "
                                       "nft_table level or via a set-lookup "
                                       "pattern.">>}})
            end;
        (ct_state, States, _Acc) ->
            error({invalid_ct_state,
                   #{states => States,
                     hint => <<"ct_state must be a non-empty list">>}});
        (tcp_dport, Port, Acc) -> Acc#{tcp => Port};
        (udp_dport, Port, Acc) -> Acc#{udp => Port};
        %% Cross-container refs (veth_of / replica_ips) come BEFORE the
        %% plain iifname/oifname/ip_saddr/ip_daddr clauses — a tuple
        %% would otherwise reach iolist_to_binary/1 and raise a
        %% cryptic badarg instead of the documented
        %% unresolvable_*_in_container_nft hint. Operator readability
        %% matters: Glasbox means the error names the limitation.
        %% Note: post-6i, `veth_of' is also refused on the host path
        %% (`erlkoenig_config_nft:expand_nft_rule/4'); this guard
        %% covers operator-supplied raw container-nft terms that
        %% bypass the host expander.
        (Key, {veth_of, Pod, Ct}, _Acc)
            when Key =:= iifname; Key =:= oifname; Key =:= oifname_ne ->
            error({unresolvable_veth_of_in_container_nft,
                   #{key => Key, pod => Pod, container => Ct,
                     hint => <<"veth_of was removed post-6i; IPVLAN slaves "
                               "are not visible on the host. Use ip_saddr "
                               "or replica_ips instead.">>}});
        (Key, {replica_ips, Pod, Ct}, _Acc)
            when Key =:= ip_saddr; Key =:= ip_daddr ->
            error({unresolvable_replica_ips_in_container_nft,
                   #{key => Key, pod => Pod, container => Ct,
                     hint => <<"cross-container replica_ips refs must "
                               "live in host nft_table, not container-local "
                               "nft (SPEC-EK-023 §4)">>}});
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
        %% conn_limit sugar: `max:` + `over:` + `saddr:` — the DSL
        %% emits {:connlimit_drop, #{max: N}} for `conn_limit per_ip: N`.
        (max, N, Acc) when is_integer(N) -> Acc#{max => N};
        (over, N, Acc) when is_integer(N) -> Acc#{over => N};
        %% Fail loud on unknown keys — a typo like `ip_saddrr` would
        %% otherwise silently flow through and leave the rule weaker
        %% than the operator declared (Glasbox violation).
        (K, V, _Acc) ->
            error({unknown_container_nft_rule_opt,
                   #{key => K, value => V,
                     hint => <<"unknown container-local nft option — "
                               "check spelling against SPEC-EK-023 §3: "
                               "ct_state, tcp_dport, udp_dport, iifname, "
                               "oifname, oifname_ne, ip_saddr, ip_daddr, "
                               "ip_protocol, log_prefix, counter, max, over">>}})
    end, #{}, Opts).

build_msgs([], Seq, MsgAcc, SeqAcc) ->
    {lists:reverse(MsgAcc), lists:reverse(SeqAcc), (Seq - 1) band 16#FFFFFFFF};
build_msgs([Fun | Rest], Seq, MsgAcc, SeqAcc) ->
    Msg = Fun(Seq),
    build_msgs(Rest, (Seq + 1) band 16#FFFFFFFF, [Msg | MsgAcc], [Seq | SeqAcc]).
