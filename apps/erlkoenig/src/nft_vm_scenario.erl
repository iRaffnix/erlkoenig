%%% @doc Scenario Runner: Evaluates .term configs against declarative test packets.
%%%
%%% Loads a scenario file, builds VM-ready rules via nft_vm_config, constructs
%%% packets via nft_vm_pkt, evaluates each against the chain, and reports
%%% PASS/FAIL per packet with optional trace on failure.
%%%
%%% Part of SPEC-NFT-013 WP-2.
-module(nft_vm_scenario).

-export([run_file/1, run/1, run/2]).
-export([format_results/1, format_results/2]).

-type packet_result() :: #{
    name := binary(),
    expected := atom(),
    actual := atom(),
    pass := boolean(),
    rule_index := non_neg_integer() | policy,
    trace := [nft_vm:trace_entry()]
}.

-type scenario_result() :: #{
    config := binary() | string(),
    chain := binary(),
    policy := atom(),
    results := [packet_result()],
    passed := non_neg_integer(),
    failed := non_neg_integer(),
    total := non_neg_integer()
}.

-export_type([packet_result/0, scenario_result/0]).

%% @doc Load and run a .scenario.term file.
-spec run_file(file:filename()) -> {ok, scenario_result()} | {error, term()}.
run_file(ScenarioFile) ->
    case file:consult(ScenarioFile) of
        {ok, [Scenario]} when is_map(Scenario) ->
            run(Scenario);
        {ok, [Other]} ->
            {error, {bad_scenario_format, Other}};
        {ok, []} ->
            {error, empty_scenario};
        {error, Reason} ->
            {error, {file_error, ScenarioFile, Reason}}
    end.

%% @doc Run a scenario term. Loads config, evaluates all packets.
-spec run(map()) -> {ok, scenario_result()} | {error, term()}.
run(Scenario) ->
    run(Scenario, #{}).

%% @doc Run a scenario with options. Options: verbose => true prints trace for all packets.
-spec run(map(), map()) -> {ok, scenario_result()} | {error, term()}.
run(Scenario, Opts) ->
    ConfigFile = maps:get(config, Scenario),
    ChainName = maps:get(chain, Scenario, <<"input">>),
    SetData = maps:get(sets, Scenario, #{}),
    Packets = maps:get(packets, Scenario),
    Policy = maps:get(policy, Scenario, drop),

    case nft_vm_config:load(ConfigFile) of
        {ok, ChainMap} ->
            case maps:find(ChainName, ChainMap) of
                {ok, Rules} ->
                    %% Extract vmaps if config has them
                    VmapData = load_vmaps(ConfigFile),
                    Results = [
                        eval_packet(PktSpec, Rules, SetData, VmapData, Policy)
                     || PktSpec <- Packets
                    ],
                    Passed = length([R || R <- Results, maps:get(pass, R)]),
                    Failed = length(Results) - Passed,
                    Result = #{
                        config => ConfigFile,
                        chain => ChainName,
                        policy => Policy,
                        results => Results,
                        passed => Passed,
                        failed => Failed,
                        total => length(Results)
                    },
                    case maps:get(print, Opts, false) of
                        true -> io:put_chars(format_results(Result));
                        false -> ok
                    end,
                    {ok, Result};
                error ->
                    {error, {unknown_chain, ChainName, maps:keys(ChainMap)}}
            end;
        {error, _} = Err ->
            Err
    end.

%% @doc Format results as human-readable string.
-spec format_results(scenario_result()) -> iolist().
format_results(Result) ->
    format_results(Result, #{}).

-spec format_results(scenario_result(), map()) -> iolist().
format_results(Result, Opts) ->
    #{config := Config, chain := Chain, policy := Policy,
      results := Results, passed := Passed, failed := Failed,
      total := Total} = Result,
    Sep = "==================================================\n",
    Verbose = maps:get(verbose, Opts, false),
    [
        Sep,
        io_lib:format("  nft_vm Scenario~n", []),
        io_lib:format("  Config: ~s~n", [Config]),
        io_lib:format("  Chain:  ~s (policy: ~p)~n", [Chain, Policy]),
        Sep,
        "\n",
        [format_packet_result(R, Verbose) || R <- Results],
        "\n",
        Sep,
        io_lib:format("  ~p packets: ~p passed, ~p failed~n", [Total, Passed, Failed]),
        Sep
    ].

%% --- Internal ---

-spec eval_packet(map(), [[nft_vm:expr()]], map(), map(), atom()) -> packet_result().
eval_packet(PktSpec, Rules, SetData, VmapData, Policy) ->
    Name = maps:get(name, PktSpec),
    Expected = maps:get(expect, PktSpec),
    Pkt = build_packet(PktSpec),
    %% Inject sets and vmaps
    Pkt1 = case maps:size(SetData) of
        0 -> Pkt;
        _ -> nft_vm_pkt:with_sets(Pkt, normalize_sets(SetData))
    end,
    Pkt2 = case maps:size(VmapData) of
        0 -> Pkt1;
        _ -> nft_vm_pkt:with_vmaps(Pkt1, VmapData)
    end,
    {RawVerdict, Trace} = nft_vm:eval_chain(Rules, Pkt2, Policy),
    Actual = normalize_verdict(RawVerdict),
    RuleIdx = find_matching_rule(Trace),
    #{
        name => Name,
        expected => Expected,
        actual => Actual,
        pass => (Actual =:= Expected),
        rule_index => RuleIdx,
        trace => Trace
    }.

-spec build_packet(map()) -> nft_vm:packet().
build_packet(#{proto := tcp} = Spec) ->
    IpOpts = ip_opts(Spec),
    TcpOpts = tcp_opts(Spec),
    Meta = meta_opts(Spec),
    nft_vm_pkt:tcp(IpOpts, TcpOpts, Meta);
build_packet(#{proto := udp} = Spec) ->
    IpOpts = ip_opts(Spec),
    UdpOpts = udp_opts(Spec),
    Meta = meta_opts(Spec),
    nft_vm_pkt:udp(IpOpts, UdpOpts, Meta);
build_packet(#{proto := icmp} = Spec) ->
    IpOpts = ip_opts(Spec),
    IcmpOpts = icmp_opts(Spec),
    Meta = meta_opts(Spec),
    nft_vm_pkt:icmp(IpOpts, IcmpOpts, Meta).

ip_opts(Spec) ->
    maps:from_list([
        {K, V} || {K, V} <- [
            {saddr, maps:get(saddr, Spec, {10,0,0,1})},
            {daddr, maps:get(daddr, Spec, {10,0,0,2})}
        ]
    ]).

tcp_opts(Spec) ->
    Base = #{dport => maps:get(dport, Spec, 80)},
    maybe_add(sport, Spec, maybe_add(flags, Spec, Base)).

udp_opts(Spec) ->
    Base = #{dport => maps:get(dport, Spec, 53)},
    maybe_add(sport, Spec, Base).

icmp_opts(Spec) ->
    #{type => maps:get(type, Spec, echo_request)}.

meta_opts(Spec) ->
    Candidates = [ct_state, iifname, oifname, mark],
    maps:from_list([
        {K, maps:get(K, Spec)} || K <- Candidates, maps:is_key(K, Spec)
    ]).

maybe_add(Key, Spec, Map) ->
    case maps:find(Key, Spec) of
        {ok, V} -> Map#{Key => V};
        error -> Map
    end.

%% Normalize set elements: tuples {A,B,C,D} → 4-byte binaries for VM lookup
-spec normalize_sets(map()) -> map().
normalize_sets(SetData) ->
    maps:map(fun(_SetName, Elements) ->
        [normalize_set_element(E) || E <- Elements]
    end, SetData).

normalize_set_element({A, B, C, D}) when A >= 0, A =< 255,
                                          B >= 0, B =< 255,
                                          C >= 0, C =< 255,
                                          D >= 0, D =< 255 ->
    <<A, B, C, D>>;
normalize_set_element(Bin) when is_binary(Bin) ->
    Bin;
normalize_set_element(Other) ->
    %% Best effort: try as string IP
    case erlkoenig_nft_ip:normalize(Other) of
        {ok, Bin} -> Bin;
        _ -> error({bad_set_element, Other})
    end.

-spec normalize_verdict(nft_vm:verdict()) -> atom().
normalize_verdict(accept) -> accept;
normalize_verdict(drop) -> drop;
normalize_verdict({jump, _}) -> jump;
normalize_verdict({goto, _}) -> goto;
normalize_verdict(Other) -> Other.

%% Find which rule index produced the final verdict.
%% Uses the trace structure: a `break` result ends the current rule's evaluation,
%% so each break→non-break transition marks a rule boundary.
-spec find_matching_rule([nft_vm:trace_entry()]) -> non_neg_integer() | policy.
find_matching_rule([]) ->
    policy;
find_matching_rule(Trace) ->
    %% Walk trace, count rule boundaries (break = rule didn't match, next = new rule)
    find_rule_in_trace(Trace, 1, false).

find_rule_in_trace([], _RuleIdx, _PrevWasBreak) ->
    policy;
find_rule_in_trace([Entry | Rest], RuleIdx, PrevWasBreak) ->
    Result = maps:get(result, Entry),
    case is_terminal(Result) of
        true ->
            %% This expression produced the final verdict
            case PrevWasBreak of
                true -> RuleIdx + 1;
                false -> RuleIdx
            end;
        false ->
            case Result of
                break ->
                    find_rule_in_trace(Rest, RuleIdx, true);
                _ ->
                    NextRule = case PrevWasBreak of
                        true -> RuleIdx + 1;
                        false -> RuleIdx
                    end,
                    find_rule_in_trace(Rest, NextRule, false)
            end
    end.

is_terminal({verdict, _}) -> true;
is_terminal(_) -> false.

-spec load_vmaps(file:filename()) -> map().
load_vmaps(ConfigFile) ->
    case file:consult(ConfigFile) of
        {ok, [Config]} when is_map(Config) ->
            nft_vm_config:vmap_map(Config);
        _ ->
            #{}
    end.

-spec format_packet_result(packet_result(), boolean()) -> iolist().
format_packet_result(Result, Verbose) ->
    #{name := Name, expected := Expected, actual := Actual,
      pass := Pass, rule_index := RuleIdx, trace := Trace} = Result,
    PassStr = case Pass of true -> "PASS"; false -> "FAIL" end,
    VerdictStr = string:uppercase(atom_to_list(Actual)),
    RuleStr = case RuleIdx of
        policy -> "default policy";
        N -> io_lib:format("rule ~p", [N])
    end,
    Line = io_lib:format("  ~-16s ~-8s (~s)~s ~s~n", [
        Name, VerdictStr, RuleStr,
        case Pass of
            true -> "";
            false -> io_lib:format(" expected: ~p", [Expected])
        end,
        PassStr
    ]),
    case Pass of
        true when not Verbose ->
            Line;
        _ ->
            %% Show trace on failure or when verbose
            [Line | format_trace(Trace)]
    end.

format_trace([]) -> [];
format_trace(Trace) ->
    ["    Trace:\n" |
     [io_lib:format("      [~p] ~s~n", [I, format_trace_entry(E)])
      || {I, E} <- lists:zip(lists:seq(1, length(Trace)), Trace)]].

format_trace_entry(#{expr := {Type, Opts}, result := Result}) ->
    TypeStr = atom_to_list(Type),
    ResultStr = case Result of
        ok -> "ok";
        break -> "BREAK";
        accept -> "ACCEPT";
        drop -> "DROP";
        {verdict, accept} -> "ACCEPT";
        {verdict, drop} -> "DROP";
        {verdict, Other2} -> io_lib:format("~p", [Other2]);
        Other -> io_lib:format("~p", [Other])
    end,
    Desc = case Type of
        meta -> io_lib:format("meta ~p", [maps:get(key, Opts, '?')]);
        cmp -> io_lib:format("cmp ~p reg~p", [maps:get(op, Opts, '?'), maps:get(sreg, Opts, '?')]);
        payload -> io_lib:format("payload ~pb @ ~p+~p", [
            maps:get(len, Opts, '?'), maps:get(base, Opts, '?'), maps:get(offset, Opts, '?')]);
        lookup -> io_lib:format("lookup in ~s", [maps:get(set, Opts, <<"?">>)]);
        immediate -> case maps:find(verdict, Opts) of
            {ok, V} -> io_lib:format("=> ~p", [V]);
            error -> io_lib:format("data", [])
        end;
        _ -> TypeStr
    end,
    io_lib:format("~-40s ~s", [Desc, ResultStr]).
