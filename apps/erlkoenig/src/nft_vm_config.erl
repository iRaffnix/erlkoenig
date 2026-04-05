%%% @doc Config→VM Bridge: Loads .term firewall configs and builds VM-ready chain maps.
%%%
%%% Mirrors the rule dispatch from erlkoenig_nft_firewall:build_rule/4 but returns
%%% raw IR expressions instead of Netlink-encoded msg_funs. The IR expressions are
%%% the format that nft_vm:eval_chain/3 understands directly.
%%%
%%% Part of SPEC-NFT-013 WP-1.
-module(nft_vm_config).

-export([load/1, load_term/1, load_chain/2, load_chain/3]).
-export([set_map/1, vmap_map/1]).

%% @doc Load a .term config file and return a chain map.
%% Each chain name maps to a list of VM-ready rules (IR expression lists).
-spec load(file:filename()) ->
    {ok, #{binary() => [[nft_vm:expr()]]}} | {error, term()}.
load(TermFile) ->
    case file:consult(TermFile) of
        {ok, [Config]} when is_map(Config) ->
            {ok, build_chain_map(Config)};
        {ok, [Other]} ->
            {error, {bad_config_format, Other}};
        {ok, []} ->
            {error, empty_config};
        {error, Reason} ->
            {error, {file_error, TermFile, Reason}}
    end.

%% @doc Build chain map directly from an already-parsed config term.
-spec load_term(map()) -> #{binary() => [[nft_vm:expr()]]}.
load_term(Config) when is_map(Config) ->
    build_chain_map(Config).

%% @doc Load a specific chain from a .term config file.
-spec load_chain(file:filename(), binary()) ->
    {ok, [[nft_vm:expr()]]} | {error, term()}.
load_chain(TermFile, ChainName) ->
    case load(TermFile) of
        {ok, ChainMap} ->
            case maps:find(ChainName, ChainMap) of
                {ok, Rules} -> {ok, Rules};
                error -> {error, {unknown_chain, ChainName, maps:keys(ChainMap)}}
            end;
        {error, _} = Err ->
            Err
    end.

%% @doc Load a specific chain with its default policy.
-spec load_chain(file:filename(), binary(), atom()) ->
    {ok, [[nft_vm:expr()]], atom()} | {error, term()}.
load_chain(TermFile, ChainName, DefaultPolicy) ->
    case load(TermFile) of
        {ok, ChainMap} ->
            case maps:find(ChainName, ChainMap) of
                {ok, Rules} -> {ok, Rules, DefaultPolicy};
                error -> {error, {unknown_chain, ChainName, maps:keys(ChainMap)}}
            end;
        {error, _} = Err ->
            Err
    end.

%% @doc Extract set membership data from config for use with nft_vm_pkt:with_sets/2.
-spec set_map(map()) -> #{binary() => [binary()]}.
set_map(_Config) ->
    %% Sets in .term configs define names and types, not membership data.
    %% Membership comes from the scenario, not from the config.
    #{}.

%% @doc Extract vmap data from config for use with nft_vm_pkt:with_vmaps/2.
-spec vmap_map(map()) -> #{binary() => #{binary() => nft_vm:verdict()}}.
vmap_map(Config) ->
    Vmaps = maps:get(vmaps, Config, []),
    maps:from_list([build_vmap_entry(V) || V <- Vmaps]).

%% --- Internal ---

-spec build_chain_map(map()) -> #{binary() => [[nft_vm:expr()]]}.
build_chain_map(Config) ->
    Chains = maps:get(chains, Config, []),
    maps:from_list([
        {maps:get(name, Chain), build_chain_rules(Chain, Config)}
     || Chain <- Chains
    ]).

-spec build_chain_rules(map(), map()) -> [[nft_vm:expr()]].
build_chain_rules(Chain, Config) ->
    RuleSpecs = maps:get(rules, Chain, []),
    lists:append([wrap_rules(rule_to_vm(RuleSpec, Config)) || RuleSpec <- RuleSpecs]).

%% Most rule builders return a single rule (flat list of expression tuples).
%% A few (tcp_accept_limited, udp_accept_limited) return multiple rules
%% (list of lists). wrap_rules normalizes both to [[rule1], [rule2], ...].
-spec wrap_rules([nft_vm:expr()] | [[nft_vm:expr()]]) -> [[nft_vm:expr()]].
wrap_rules([]) -> [];
wrap_rules([First | _] = Rules) when is_list(First) ->
    %% Already a list of rules (multi-rule return)
    Rules;
wrap_rules([First | _] = Exprs) when is_tuple(First) ->
    %% Single rule (flat list of expressions)
    [Exprs].

%% Each clause mirrors erlkoenig_nft_firewall:build_rule/4 but returns
%% raw IR expressions instead of wrapping in encode_rule/3.

-spec rule_to_vm(term(), map()) -> [nft_vm:expr()] | [[nft_vm:expr()]].

%% --- Connection tracking & basic ---
rule_to_vm(ct_established_accept, _Config) ->
    nft_rules:ct_established_accept();
rule_to_vm(iif_accept, _Config) ->
    nft_rules:iif_accept();
rule_to_vm(icmp_accept, _Config) ->
    nft_rules:icmp_accept();
rule_to_vm({icmp_accept_named, Counter}, _Config) ->
    nft_rules:icmp_accept_named(ensure_binary(Counter));
rule_to_vm(icmpv6_accept, _Config) ->
    nft_rules:icmpv6_accept();
rule_to_vm(accept, _Config) ->
    [nft_expr_ir:accept()];
rule_to_vm(forward_established, _Config) ->
    nft_rules:forward_established();

%% --- TCP ---
rule_to_vm({tcp_accept, Port}, _Config) ->
    nft_rules:tcp_accept(Port);
rule_to_vm({tcp_accept, Port, Counter}, _Config) ->
    nft_rules:tcp_accept_named(Port, ensure_binary(Counter));
rule_to_vm({tcp_accept_limited, Port, Counter, LimitOpts}, _Config) ->
    %% Returns list of two rules
    nft_rules:tcp_accept_limited(Port, ensure_binary(Counter), LimitOpts);
rule_to_vm({tcp_reject, Port}, _Config) ->
    nft_rules:tcp_reject(Port);
rule_to_vm({tcp_port_range_accept, From, To}, _Config) ->
    nft_rules:tcp_port_range_accept(From, To);

%% --- UDP ---
rule_to_vm({udp_accept, Port}, _Config) ->
    nft_rules:udp_accept(Port);
rule_to_vm({udp_accept, Port, Counter}, _Config) ->
    nft_rules:udp_accept_named(Port, ensure_binary(Counter));
rule_to_vm({udp_accept_limited, Port, Counter, LimitOpts}, _Config) ->
    %% Returns list of two rules
    nft_rules:udp_accept_limited(Port, ensure_binary(Counter), LimitOpts);
rule_to_vm({udp_port_range_accept, From, To}, _Config) ->
    nft_rules:udp_port_range_accept(From, To);

%% --- Protocol ---
rule_to_vm({protocol_accept, Proto}, _Config) ->
    nft_rules:protocol_accept(Proto);

%% --- Set lookup ---
rule_to_vm({set_lookup_drop, SetName}, Config) ->
    SetType = set_type_from_config(Config, SetName),
    nft_rules:set_lookup_drop(ensure_binary(SetName), SetType);
rule_to_vm({set_lookup_drop, SetName, Counter}, Config) ->
    SetType = set_type_from_config(Config, SetName),
    nft_rules:set_lookup_drop_named(ensure_binary(SetName), ensure_binary(Counter), SetType);
rule_to_vm({set_lookup_accept, SetName}, Config) ->
    SetType = set_type_from_config(Config, SetName),
    nft_rules:set_lookup_accept(ensure_binary(SetName), SetType);
rule_to_vm({set_lookup_accept_tcp, SetName}, _Config) ->
    nft_rules:set_lookup_tcp_accept(ensure_binary(SetName));
rule_to_vm({set_lookup_udp_accept, SetName, Port}, Config) ->
    SetType = set_type_from_config(Config, SetName),
    nft_rules:set_lookup_udp_accept(ensure_binary(SetName), Port, SetType);

%% --- Logging ---
rule_to_vm({log_drop, Prefix}, _Config) ->
    nft_rules:log_drop(ensure_binary(Prefix));
rule_to_vm({log_drop, Prefix, Counter}, _Config) ->
    nft_rules:log_drop_named(ensure_binary(Prefix), ensure_binary(Counter));
rule_to_vm({log_drop_nflog, Prefix, Group, Counter}, _Config) ->
    nft_rules:log_drop_nflog(ensure_binary(Prefix), Group, ensure_binary(Counter));
rule_to_vm({log_reject, Prefix}, _Config) ->
    nft_rules:log_reject(ensure_binary(Prefix));
rule_to_vm({nflog_capture_udp, Port, Prefix, Group}, _Config) ->
    nft_rules:nflog_capture_udp(Port, ensure_binary(Prefix), Group);

%% --- Interface ---
rule_to_vm({iifname_accept, Name}, _Config) ->
    nft_rules:iifname_accept(ensure_binary(Name));
rule_to_vm({oifname_accept, Name}, _Config) ->
    nft_rules:oifname_accept(ensure_binary(Name));
rule_to_vm({oifname_neq_masq, Name}, _Config) ->
    nft_rules:oifname_neq_masq(ensure_binary(Name));

%% --- Jump / Flow control ---
rule_to_vm({jump, Target}, _Config) ->
    [nft_expr_ir:jump(ensure_binary(Target))];
rule_to_vm({iifname_jump, Name, Target}, _Config) ->
    nft_rules:iifname_jump(ensure_binary(Name), ensure_binary(Target));
rule_to_vm({iifname_oifname_jump, InIf, OutIf, Target}, _Config) ->
    nft_rules:iifname_oifname_jump(ensure_binary(InIf), ensure_binary(OutIf), ensure_binary(Target));
rule_to_vm({iifname_oifname_masq, InIf, OutIf}, _Config) ->
    nft_rules:iifname_oifname_masq(ensure_binary(InIf), ensure_binary(OutIf));

%% --- NAT ---
rule_to_vm(masq, _Config) ->
    nft_rules:masq_rule();
rule_to_vm({dnat, IP, Port}, _Config) ->
    {ok, Bin} = erlkoenig_nft_ip:normalize(IP),
    nft_rules:dnat_rule(Bin, Port);
rule_to_vm({tcp_dnat, MatchPort, DstIp, DstPort}, _Config) ->
    {ok, Bin} = erlkoenig_nft_ip:normalize(DstIp),
    nft_rules:tcp_dnat(MatchPort, Bin, DstPort);
rule_to_vm({snat, IP, Port}, _Config) ->
    {ok, Bin} = erlkoenig_nft_ip:normalize(IP),
    nft_rules:snat_rule(Bin, Port);

%% --- Conntrack mark ---
rule_to_vm({ct_mark_set, Value}, _Config) ->
    nft_rules:ct_mark_set(Value);
rule_to_vm({ct_mark_match, Value, Verdict}, _Config) ->
    nft_rules:ct_mark_match(Value, Verdict);

%% --- Advanced ---
rule_to_vm({notrack, Port, Proto}, _Config) ->
    nft_rules:notrack_rule(Port, Proto);
rule_to_vm({meter_limit, SetName, Port, Proto, Opts}, _Config) ->
    OptsMap = maps:from_list(Opts),
    nft_rules:meter_limit(ensure_binary(SetName), Port, Proto, OptsMap);
rule_to_vm({flow_offload, FlowtableName}, _Config) ->
    nft_rules:flow_offload(ensure_binary(FlowtableName));
rule_to_vm({osf_match, OsName, Verdict}, _Config) ->
    nft_rules:osf_match(ensure_binary(OsName), Verdict);
rule_to_vm({synproxy, Port, MSS, WScale, _Flags}, _Config) ->
    nft_rules:synproxy_filter_rule(Port, #{mss => MSS, wscale => WScale});
rule_to_vm(fib_rpf_drop, _Config) ->
    nft_rules:fib_rpf_drop();
rule_to_vm({queue_rule, Port, Proto, Opts}, _Config) ->
    OptsMap = maps:from_list(Opts),
    nft_rules:queue_rule(Port, Proto, OptsMap);
rule_to_vm({concat_set_lookup, SetName, Fields, Verdict}, _Config) ->
    nft_rules:concat_set_lookup(ensure_binary(SetName), Fields, Verdict);

%% --- Source/Dest IP ---
rule_to_vm({ip_saddr_accept, IP}, _Config) ->
    {ok, Bin} = erlkoenig_nft_ip:normalize(IP),
    nft_rules:ip_saddr_accept(Bin);
rule_to_vm({ip_saddr_drop, IP}, _Config) ->
    {ok, Bin} = erlkoenig_nft_ip:normalize(IP),
    nft_rules:ip_saddr_drop(Bin);

%% --- Connlimit ---
rule_to_vm({connlimit_drop, Count, Flags}, _Config) ->
    nft_rules:connlimit_drop(Count, Flags);

%% --- Vmap dispatch ---
rule_to_vm({vmap_dispatch, Proto, VmapName}, _Config) ->
    nft_rules:vmap_dispatch(Proto, ensure_binary(VmapName));

%% --- Catch-all: unknown rule type ---
rule_to_vm(Unknown, _Config) ->
    error({unknown_rule_type, Unknown}).

%% --- Helpers ---

-spec set_type_from_config(map(), term()) -> ipv4_addr | ipv6_addr.
set_type_from_config(Config, SetName) ->
    BinName = ensure_binary(SetName),
    Sets = maps:get(sets, Config, []),
    case lists:keyfind(BinName, 1, Sets) of
        {_, Type} -> Type;
        {_, Type, _} -> Type;
        false -> ipv4_addr
    end.

-spec build_vmap_entry(map()) -> {binary(), #{binary() => nft_vm:verdict()}}.
build_vmap_entry(#{name := Name, entries := Entries}) ->
    VmapData = maps:from_list([
        {normalize_vmap_key(K), normalize_verdict(V)}
     || {K, V} <- Entries
    ]),
    {ensure_binary(Name), VmapData}.

normalize_vmap_key(Port) when is_integer(Port) ->
    %% Port number as big-endian binary for VM lookup
    <<Port:16/big>>;
normalize_vmap_key(Bin) when is_binary(Bin) ->
    Bin.

normalize_verdict(accept) -> accept;
normalize_verdict(drop) -> drop;
normalize_verdict({jump, Target}) -> {jump, ensure_binary(Target)};
normalize_verdict({goto, Target}) -> {goto, ensure_binary(Target)}.

-spec ensure_binary(atom() | binary() | string()) -> binary().
ensure_binary(B) when is_binary(B) -> B;
ensure_binary(A) when is_atom(A) -> atom_to_binary(A);
ensure_binary(L) when is_list(L) -> list_to_binary(L).
