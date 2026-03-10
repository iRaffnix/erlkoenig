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

-module(erlkoenig_nft_firewall).
-moduledoc """
Firewall configuration owner and lifecycle manager.

A gen_server that reads the declarative firewall config from
priv/firewall.term, applies it via the shared erlkoenig_nft_srv Netlink
server, and starts per-counter watchers in erlkoenig_nft_watch_sup.

On termination, the nf_tables table is deleted so the firewall
is cleanly removed.

Rules are built as semantic terms (nft_expr_ir) that can be tested
in the nft_vm simulator, then encoded to Netlink via nft_encode.

The config format is documented in priv/firewall.term.

Runtime operations (ban, unban, status) are exposed via
gen_server calls. Use the erlkoenig_nft facade module instead of
calling this module directly.
""".

-behaviour(gen_server).

-export([start_link/0,
         start_link/1,
         ban/1,
         unban/1,
         rates/0,
         status/0,
         reload/0]).

-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2]).

%% --- Constants ---

-define(INET, 1).

%% --- Types ---

-type state() :: #{
    config := map(),
    table  := binary()
}.

%% --- Public API ---

-doc "Start the firewall with config from priv/firewall.term.".
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    case config_path() of
        {ok, Path} ->
            {ok, [Config]} = file:consult(Path),
            start_link(Config);
        {error, _} = Err ->
            Err
    end.

-doc "Start the firewall with an explicit config map.".
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Config) when is_map(Config) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Config, []).

-doc "Add an IP address to the blocklist (IPv4 or IPv6).".
-spec ban(inet:ip_address() | binary() | string()) -> ok | {error, term()}.
ban(IP) ->
    case erlkoenig_nft_ip:normalize(IP) of
        {ok, Bin} -> gen_server:call(?MODULE, {ban, Bin});
        Err -> Err
    end.

-doc "Remove an IP address from the blocklist (IPv4 or IPv6).".
-spec unban(inet:ip_address() | binary() | string()) -> ok | {error, term()}.
unban(IP) ->
    case erlkoenig_nft_ip:normalize(IP) of
        {ok, Bin} -> gen_server:call(?MODULE, {unban, Bin});
        Err -> Err
    end.

-doc "Get current rates for all watched counters.".
-spec rates() -> #{binary() => map()}.
rates() ->
    gen_server:call(?MODULE, rates).

-doc "Get firewall status.".
-spec status() -> map().
status() ->
    gen_server:call(?MODULE, status).

-doc """
Reload the firewall config from priv/firewall.term.

Stops all counter workers, re-applies the full config (clean slate),
and restarts counters. Existing connections are preserved (conntrack
state lives in the kernel).
""".
-spec reload() -> ok | {error, term()}.
reload() ->
    gen_server:call(?MODULE, reload, 10000).

%% --- gen_server callbacks ---

-spec init(map()) -> {ok, state()} | {stop, term()}.
init(Config) ->
    Table = maps:get(table, Config),
    case apply_config(Config) of
        ok ->
            start_counters(Config),
            logger:notice("[erlkoenig_nft] Firewall applied: table=~s", [Table]),
            {ok, #{config => Config, table => Table}};
        {error, Reason} ->
            {stop, {apply_failed, Reason}}
    end.

-spec handle_call(term(), {pid(), term()}, state()) ->
    {reply, term(), state()}.
handle_call({ban, IPBin}, _From, #{config := Config} = State) ->
    Result = apply_set_op(Config, IPBin, fun blocklist_name/2,
                          fun(T, S) -> nft_rules:ban_ip(T, S, IPBin) end,
                          "Banned ~s", [erlkoenig_nft_ip:format(IPBin)]),
    {reply, Result, State};

handle_call({unban, IPBin}, _From, #{config := Config} = State) ->
    Result = apply_set_op(Config, IPBin, fun blocklist_name/2,
                          fun(T, S) -> nft_rules:unban_ip(T, S, IPBin) end,
                          "Unbanned ~s", [erlkoenig_nft_ip:format(IPBin)]),
    {reply, Result, State};

handle_call(rates, _From, State) ->
    Rates = collect_rates(),
    {reply, Rates, State};

handle_call(status, _From, #{config := Config, table := Table} = State) ->
    Status = #{
        table   => Table,
        running => true,
        config  => Config,
        counters => counter_count()
    },
    {reply, Status, State};

handle_call(reload, _From, #{table := OldTable} = State) ->
    case config_path() of
        {ok, Path} ->
            case file:consult(Path) of
                {ok, [NewConfig]} ->
                    erlkoenig_nft_watch_sup:stop_counters(),
                    case apply_config(NewConfig) of
                        ok ->
                            NewTable = maps:get(table, NewConfig),
                            %% Delete old table if name changed
                            _ = case NewTable =/= OldTable of
                                true ->
                                    nfnl_server:apply_msgs(erlkoenig_nft_srv, [
                                        fun(S) -> nft_delete:table(?INET, OldTable, S) end
                                    ]);
                                false ->
                                    ok
                            end,
                            start_counters(NewConfig),
                            logger:notice("[erlkoenig_nft] Config reloaded: table=~s", [NewTable]),
                            {reply, ok, State#{config => NewConfig, table => NewTable}};
                        {error, _} = Err ->
                            %% Re-apply old config to recover
                            _ = apply_config(maps:get(config, State)),
                            start_counters(maps:get(config, State)),
                            logger:error("[erlkoenig_nft] Reload failed: ~p, rolled back", [Err]),
                            {reply, Err, State}
                    end;
                {error, Reason} ->
                    {reply, {error, {bad_config, Reason}}, State}
            end;
        {error, _} = Err ->
            {reply, Err, State}
    end;

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(_Msg, State) ->
    {noreply, State}.

-spec handle_info(term(), state()) -> {noreply, state()}.
handle_info(_Info, State) ->
    {noreply, State}.

-spec terminate(term(), state()) -> ok.
terminate(_Reason, #{table := Table}) ->
    logger:notice("[erlkoenig_nft] Tearing down firewall: table=~s", [Table]),
    erlkoenig_nft_watch_sup:stop_counters(),
    _ = nfnl_server:apply_msgs(erlkoenig_nft_srv, [
        fun(S) -> nft_delete:table(?INET, Table, S) end
    ]),
    ok.

%% --- Internal: Set operations (ban/unban/authorize/deauthorize) ---

-spec apply_set_op(map(), binary(), fun(), fun(), string(), list()) ->
    ok | {error, term()}.
apply_set_op(Config, IPBin, LookupFun, RuleFun, LogFmt, LogArgs) ->
    Table = maps:get(table, Config),
    case LookupFun(Config, IPBin) of
        {ok, SetName} ->
            Result = nfnl_server:apply_msgs(erlkoenig_nft_srv, [RuleFun(Table, SetName)]),
            case Result of
                ok -> logger:notice("[erlkoenig_nft] " ++ LogFmt, LogArgs);
                _  -> ok
            end,
            Result;
        {error, _} = Err ->
            Err
    end.

%% --- Internal: Apply Config ---

-spec apply_config(map()) -> ok | {error, term()}.
apply_config(Config) ->
    Table    = maps:get(table, Config),
    Sets     = maps:get(sets, Config, []),
    Counters = maps:get(counters, Config, []),
    Chains   = maps:get(chains, Config, []),

    %% Clean slate via Netlink (no os:cmd)
    _ = nfnl_server:apply_msgs(erlkoenig_nft_srv, [
        fun(S) -> nft_delete:table(?INET, Table, S) end
    ]),

    %% Build all messages
    Msgs = lists:flatten([
        %% Table
        [fun(S) -> nft_table:add(?INET, Table, S) end],

        %% Named counters
        [fun(S) -> nft_object:add_counter(?INET, Table, counter_name(C), S) end
         || C <- Counters],

        %% Sets
        [fun(S) -> nft_set:add(?INET,
            set_opts(Table, SetSpec, Idx), S) end
         || {Idx, SetSpec} <- with_index(Sets)],

        %% Chains + Rules
        [build_chain(Table, Chain, Config) || Chain <- Chains]
    ]),

    nfnl_server:apply_msgs(erlkoenig_nft_srv, Msgs).

%% --- Internal: Start Counters ---

-spec start_counters(map()) -> ok.
start_counters(Config) ->
    Table    = maps:get(table, Config),
    Counters = maps:get(counters, Config, []),
    Watch    = maps:get(watch, Config, undefined),

    case Watch of
        undefined ->
            ok;
        WatchConfig ->
            Interval   = maps:get(interval, WatchConfig, 2000),
            Thresholds = maps:get(thresholds, WatchConfig, []),

            lists:foreach(fun(Counter) ->
                Name = counter_name(Counter),
                CounterThresholds = build_thresholds(Name, Thresholds),
                erlkoenig_nft_watch_sup:start_counter(#{
                    name       => Name,
                    family     => ?INET,
                    table      => Table,
                    interval   => Interval,
                    thresholds => CounterThresholds
                })
            end, Counters)
    end.

%% --- Internal: Build chain messages ---

-spec build_chain(binary(), map(), map()) -> [fun()].
build_chain(Table, ChainConfig, Config) ->
    Name     = maps:get(name, ChainConfig),
    Hook     = maps:get(hook, ChainConfig),
    Type     = maps:get(type, ChainConfig, filter),
    Priority = maps:get(priority, ChainConfig, 0),
    Policy   = maps:get(policy, ChainConfig, accept),
    Rules    = maps:get(rules, ChainConfig, []),

    ChainMsg = fun(S) -> nft_chain:add(?INET, #{
        table => Table, name => Name,
        hook => Hook, type => Type,
        priority => Priority, policy => Policy
    }, S) end,

    RuleMsgs = lists:flatten([build_rule(Table, Name, Rule, Config) || Rule <- Rules]),
    [ChainMsg | RuleMsgs].

%% --- Internal: Build rule → semantic terms → msg_fun ---

-spec build_rule(binary(), binary(), term(), map()) -> fun() | [fun()].

%% Simple rules → single term list → single msg_fun
build_rule(Table, Chain, ct_established_accept, _Config) ->
    encode_rule(Table, Chain, nft_rules:ct_established_accept());
build_rule(Table, Chain, iif_accept, _Config) ->
    encode_rule(Table, Chain, nft_rules:iif_accept());

%% TCP/UDP with named counter
build_rule(Table, Chain, {tcp_accept, Port, Counter}, _Config) ->
    encode_rule(Table, Chain, nft_rules:tcp_accept_named(Port, counter_name(Counter)));
build_rule(Table, Chain, {udp_accept, Port, Counter}, _Config) ->
    encode_rule(Table, Chain, nft_rules:udp_accept_named(Port, counter_name(Counter)));

%% TCP with rate limit → returns list of two rules → list of msg_funs
build_rule(Table, Chain, {tcp_accept_limited, Port, Counter, LimitOpts}, _Config) ->
    RuleTerms = nft_rules:tcp_accept_limited(Port, counter_name(Counter), LimitOpts),
    [encode_rule(Table, Chain, R) || R <- RuleTerms];

%% TCP/UDP without counter
build_rule(Table, Chain, {tcp_accept, Port}, _Config) ->
    encode_rule(Table, Chain, nft_rules:tcp_accept(Port));
build_rule(Table, Chain, {udp_accept, Port}, _Config) ->
    encode_rule(Table, Chain, nft_rules:udp_accept(Port));

%% Protocol accept
build_rule(Table, Chain, {protocol_accept, Proto}, _Config) ->
    encode_rule(Table, Chain, nft_rules:protocol_accept(Proto));

%% Set lookup with named counter — resolve set type from config
build_rule(Table, Chain, {set_lookup_drop, SetName, Counter}, Config) ->
    SetType = set_type_from_config(Config, SetName),
    encode_rule(Table, Chain,
        nft_rules:set_lookup_drop_named(SetName, counter_name(Counter), SetType));

%% Set lookup without counter — resolve set type from config
build_rule(Table, Chain, {set_lookup_drop, SetName}, Config) ->
    SetType = set_type_from_config(Config, SetName),
    encode_rule(Table, Chain, nft_rules:set_lookup_drop(SetName, SetType));

%% Set lookup UDP accept (WireGuard SPA allowlist)
build_rule(Table, Chain, {set_lookup_udp_accept, SetName, Port}, Config) ->
    SetType = set_type_from_config(Config, SetName),
    encode_rule(Table, Chain, nft_rules:set_lookup_udp_accept(SetName, Port, SetType));

%% NFLOG capture + drop (SPA packet capture)
build_rule(Table, Chain, {nflog_capture_udp, Port, Prefix, Group}, _Config) ->
    encode_rule(Table, Chain, nft_rules:nflog_capture_udp(Port, Prefix, Group));

%% Log drop with named counter
build_rule(Table, Chain, {log_drop, Prefix, Counter}, _Config) ->
    encode_rule(Table, Chain, nft_rules:log_drop_named(Prefix, counter_name(Counter)));

build_rule(Table, Chain, {log_drop_nflog, Prefix, Group, Counter}, _Config) ->
    encode_rule(Table, Chain, nft_rules:log_drop_nflog(Prefix, Group, counter_name(Counter)));

%% Log drop without counter
build_rule(Table, Chain, {log_drop, Prefix}, _Config) ->
    encode_rule(Table, Chain, nft_rules:log_drop(Prefix));

%% Accept on named interface (e.g. <<"wg0">>, <<"br0">>)
build_rule(Table, Chain, {iifname_accept, Name}, _Config) ->
    encode_rule(Table, Chain, nft_rules:iifname_accept(Name));

%% TCP reject with RST
build_rule(Table, Chain, {tcp_reject, Port}, _Config) ->
    encode_rule(Table, Chain, nft_rules:tcp_reject(Port));

%% TCP/UDP port range accept
build_rule(Table, Chain, {tcp_port_range_accept, From, To}, _Config) ->
    encode_rule(Table, Chain, nft_rules:tcp_port_range_accept(From, To));
build_rule(Table, Chain, {udp_port_range_accept, From, To}, _Config) ->
    encode_rule(Table, Chain, nft_rules:udp_port_range_accept(From, To));

%% Rate-limited UDP accept
build_rule(Table, Chain, {udp_accept_limited, Port, Counter, LimitOpts}, _Config) ->
    RuleTerms = nft_rules:udp_accept_limited(Port, counter_name(Counter), LimitOpts),
    [encode_rule(Table, Chain, R) || R <- RuleTerms];

%% Accept/drop from specific source IP
build_rule(Table, Chain, {ip_saddr_accept, IP}, _Config) ->
    {ok, Bin} = erlkoenig_nft_ip:normalize(IP),
    encode_rule(Table, Chain, nft_rules:ip_saddr_accept(Bin));
build_rule(Table, Chain, {ip_saddr_drop, IP}, _Config) ->
    {ok, Bin} = erlkoenig_nft_ip:normalize(IP),
    encode_rule(Table, Chain, nft_rules:ip_saddr_drop(Bin));

%% Connection limit per IP
build_rule(Table, Chain, {connlimit_drop, Count, Flags}, _Config) ->
    encode_rule(Table, Chain, nft_rules:connlimit_drop(Count, Flags));

%% Log and reject (ICMP unreachable instead of silent drop)
build_rule(Table, Chain, {log_reject, Prefix}, _Config) ->
    encode_rule(Table, Chain, nft_rules:log_reject(Prefix));

%% Forward chain: accept established/related
build_rule(Table, Chain, forward_established, _Config) ->
    encode_rule(Table, Chain, nft_rules:forward_established());

%% NAT: masquerade outgoing traffic
build_rule(Table, Chain, masq, _Config) ->
    encode_rule(Table, Chain, nft_rules:masq_rule());

%% NAT: destination NAT to internal IP:Port
build_rule(Table, Chain, {dnat, IP, Port}, _Config) ->
    {ok, Bin} = erlkoenig_nft_ip:normalize(IP),
    encode_rule(Table, Chain, nft_rules:dnat_rule(Bin, Port)).

%% --- Internal: Encode a semantic rule to a msg_fun ---

-spec encode_rule(binary(), binary(), nft_rules:rule()) ->
    fun((non_neg_integer()) -> binary()).
encode_rule(Table, Chain, ExprTerms) ->
    nft_encode:rule_fun(inet, Table, Chain, ExprTerms).

%% --- Internal: Thresholds ---

-spec build_thresholds(binary(), [tuple()]) -> [map()].
build_thresholds(CounterName, Thresholds) ->
    lists:filtermap(fun({Id, Counter, Metric, Op, Value}) ->
        case counter_name(Counter) of
            CounterName ->
                {true, #{
                    id     => Id,
                    metric => Metric,
                    op     => Op,
                    value  => Value,
                    action => default_action(Id)
                }};
            _ ->
                false
        end
    end, Thresholds).

%% --- Internal: Helpers ---

-spec counter_name(atom() | binary()) -> binary().
counter_name(Name) when is_binary(Name) -> Name;
counter_name(Name) when is_atom(Name) -> atom_to_binary(Name).

-spec with_index([T]) -> [{pos_integer(), T}].
with_index(List) ->
    lists:zip(lists:seq(1, length(List)), List).

-spec blocklist_name(map(), binary()) -> {ok, binary()} | {error, no_matching_set}.
blocklist_name(Config, IPBin) ->
    Sets = maps:get(sets, Config, []),
    TargetType = case erlkoenig_nft_ip:version(IPBin) of
        v4 -> ipv4_addr;
        v6 -> ipv6_addr
    end,
    case [Name || S <- Sets, set_name(S) =/= undefined,
                  set_type(S) =:= TargetType,
                  Name <- [set_name(S)],
                  not is_allowlist(Name)] of
        [First | _] -> {ok, First};
        [] -> {error, no_matching_set}
    end.

-spec set_type_from_config(map(), binary()) -> ipv4_addr | ipv6_addr.
set_type_from_config(Config, SetName) ->
    Sets = maps:get(sets, Config, []),
    case lists:keyfind(SetName, 1, Sets) of
        {_, Type} -> Type;
        {_, Type, _} -> Type;
        false -> ipv4_addr
    end.

%% Extract name/type from 2-tuple or 3-tuple set specs
-spec set_name(tuple()) -> binary() | undefined.
set_name({Name, _Type}) -> Name;
set_name({Name, _Type, _Opts}) -> Name;
set_name(_) -> undefined.

-spec set_type(tuple()) -> atom().
set_type({_Name, Type}) -> Type;
set_type({_Name, Type, _Opts}) -> Type;
set_type(_) -> undefined.

-spec is_allowlist(binary()) -> boolean().
is_allowlist(Name) ->
    binary:match(Name, <<"allow">>) =/= nomatch.

-spec set_opts(binary(), tuple(), pos_integer()) -> nft_set:set_opts().
set_opts(Table, {SetName, SetType}, Idx) ->
    #{table => Table, name => SetName, type => SetType, id => Idx};
set_opts(Table, {SetName, SetType, Extra}, Idx) ->
    Base = #{table => Table, name => SetName, type => SetType, id => Idx},
    maps:merge(Base, Extra).

config_path() ->
    erlkoenig_nft_config:config_path().

-spec collect_rates() -> #{binary() => map()}.
collect_rates() ->
    Children = supervisor:which_children(erlkoenig_nft_watch_sup),
    lists:foldl(fun({_, Pid, _, _}, Acc) when is_pid(Pid) ->
        try gen_server:call(Pid, get_rates, 1000) of
            Rate when is_map(Rate) ->
                Name = maps:get(name, Rate, undefined),
                case Name of
                    undefined -> Acc;
                    _ -> Acc#{Name => Rate}
                end;
            _ ->
                Acc
        catch
            _:_ -> Acc
        end;
       (_, Acc) -> Acc
    end, #{}, Children).

-spec counter_count() -> non_neg_integer().
counter_count() ->
    length(supervisor:which_children(erlkoenig_nft_watch_sup)).

-spec default_action(term()) -> fun().
default_action(Id) ->
    fun(Name, Metric, Val, Thresh) ->
        logger:warning("[erlkoenig_nft:~p] ~s ~p=~.1f exceeds ~.1f",
                       [Id, Name, Metric, Val, Thresh])
    end.
