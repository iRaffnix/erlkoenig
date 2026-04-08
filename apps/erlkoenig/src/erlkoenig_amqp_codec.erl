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

-module(erlkoenig_amqp_codec).
-moduledoc """
Encode erlkoenig internal events to JSON for AMQP publishing.

Pure functional module — no processes, no state, no I/O.
Translates gen_event tuples into {RoutingKey, JsonBinary} pairs
with a versioned envelope.

Envelope format (v2, SPEC-EK-007):
  {
    "v": 2,
    "ts": "2026-04-05T18:00:00.000Z",
    "node": "erlkoenig@host",
    "key": "container.web-0-nginx.started",
    "payload": { ... }
  }

Routing key schema: <category>.<entity>.<event>
  - container.<name>.<event>  — lifecycle
  - stats.<name>.<metric>     — cgroup stats
  - firewall.<chain>.<event>  — drops, packets
  - conntrack.flow.<event>    — connection tracking
  - guard.threat.<event>      — ban/unban
  - control.<scope>.<action>  — manual operations
  - policy.<name>.<event>     — violations
""".

-export([encode/1]).

-ifdef(TEST).
-export([encode_payload/1, routing_key/1]).
-endif.

-spec encode(term()) -> {ok, binary(), iodata()} | skip.
encode(Event) ->
    case encode_payload(Event) of
        {ok, RoutingKey, Payload} ->
            Envelope = #{
                <<"v">> => 2,
                <<"ts">> => timestamp(),
                <<"node">> => atom_to_binary(node()),
                <<"key">> => RoutingKey,
                <<"payload">> => Payload
            },
            try
                {ok, RoutingKey, json:encode(Envelope)}
            catch _:Err ->
                logger:warning("erlkoenig_amqp_codec: encoding failed: ~p for ~p",
                               [Err, Event]),
                skip
            end;
        skip ->
            skip
    end.

%%====================================================================
%% Event → {RoutingKey, PayloadMap}
%% Routing key schema (v2): <category>.<entity>.<event>
%%====================================================================

-spec encode_payload(term()) -> {ok, binary(), map()} | skip.

%% ── Container lifecycle ─────────────────────────────────────────
%% Routing: container.<name>.<event>

encode_payload({container_started, Id, Name, Pid}) when is_pid(Pid) ->
    NameBin = ensure_binary(Name),
    {ok, <<"container.", NameBin/binary, ".started">>, #{
        <<"id">> => ensure_binary(Id),
        <<"name">> => NameBin,
        <<"os_pid">> => os_pid(Pid)
    }};

encode_payload({container_stopped, Id, Name, #{exit_code := Code, term_signal := Sig}}) ->
    NameBin = ensure_binary(Name),
    {ok, <<"container.", NameBin/binary, ".stopped">>, #{
        <<"id">> => ensure_binary(Id),
        <<"name">> => NameBin,
        <<"exit_code">> => Code,
        <<"signal">> => Sig
    }};

encode_payload({container_stopped, Id, Name, _}) ->
    NameBin = ensure_binary(Name),
    {ok, <<"container.", NameBin/binary, ".stopped">>, #{
        <<"id">> => ensure_binary(Id),
        <<"name">> => NameBin,
        <<"exit_code">> => null,
        <<"signal">> => null
    }};

encode_payload({container_failed, Id, Name, Reason}) ->
    NameBin = ensure_binary(Name),
    {ok, <<"container.", NameBin/binary, ".failed">>, #{
        <<"id">> => ensure_binary(Id),
        <<"name">> => NameBin,
        <<"reason">> => term_to_binary_string(Reason)
    }};

encode_payload({container_restarting, Id, Name, Count}) ->
    NameBin = ensure_binary(Name),
    {ok, <<"container.", NameBin/binary, ".restarting">>, #{
        <<"id">> => ensure_binary(Id),
        <<"name">> => NameBin,
        <<"attempt">> => Count
    }};

encode_payload({container_oom, Id, Name}) ->
    NameBin = ensure_binary(Name),
    {ok, <<"container.", NameBin/binary, ".oom">>, #{
        <<"id">> => ensure_binary(Id),
        <<"name">> => NameBin
    }};

encode_payload({container_unhealthy, Id, Name, FailCount}) ->
    NameBin = ensure_binary(Name),
    {ok, <<"container.", NameBin/binary, ".health">>, #{
        <<"id">> => ensure_binary(Id),
        <<"name">> => NameBin,
        <<"failures">> => FailCount
    }};

%% Legacy 2-arg form (backwards compat during transition)
encode_payload({container_unhealthy, Id, FailCount}) when is_integer(FailCount) ->
    IdBin = ensure_binary(Id),
    {ok, <<"container.", IdBin/binary, ".health">>, #{
        <<"id">> => IdBin,
        <<"failures">> => FailCount
    }};

%% ── Container stats (SPEC-EK-007) ──────────────────────────────
%% Routing: stats.<name>.<metric>

encode_payload({container_stats, _Id, Name, MetricType, Values}) when is_map(Values) ->
    NameBin = ensure_binary(Name),
    MetricBin = atom_to_binary(MetricType),
    Payload = Values#{<<"name">> => NameBin},
    {ok, <<"stats.", NameBin/binary, ".", MetricBin/binary>>,
     encode_map(Payload)};

%% ── Policy events ───────────────────────────────────────────────
%% Routing: policy.<name>.violation

encode_payload({policy_violation, Id, Name, {Type, Action}}) ->
    NameBin = ensure_binary(Name),
    {ok, <<"policy.", NameBin/binary, ".violation">>, #{
        <<"id">> => ensure_binary(Id),
        <<"name">> => NameBin,
        <<"violation_type">> => atom_to_binary(Type),
        <<"action">> => atom_to_binary(Action)
    }};

encode_payload({policy_violation, Id, Name, {Type, Detail, Action}}) ->
    NameBin = ensure_binary(Name),
    {ok, <<"policy.", NameBin/binary, ".violation">>, #{
        <<"id">> => ensure_binary(Id),
        <<"name">> => NameBin,
        <<"violation_type">> => atom_to_binary(Type),
        <<"action">> => atom_to_binary(Action),
        <<"detail">> => term_to_binary_string(Detail)
    }};

%% Legacy 3-arg policy (Id used as entity when no Name)
encode_payload({policy_violation, Id, Details}) ->
    IdBin = ensure_binary(Id),
    {ok, <<"policy.", IdBin/binary, ".violation">>, #{
        <<"id">> => IdBin,
        <<"detail">> => term_to_binary_string(Details)
    }};

%% ── Firewall events ────────────────────────────────────────────
%% Routing: firewall.<chain>.drop | firewall.<chain>.packet
%% Routing: control.<scope>.<action>

encode_payload({control_event, #{action := Action, status := Status, details := Details}}) ->
    ActionBin = atom_to_binary(Action),
    Scope = case Action of
        ban   -> <<"nft">>;
        unban -> <<"nft">>;
        reload -> <<"nft">>;
        set_add -> <<"set">>;
        set_del -> <<"set">>;
        _     -> <<"nft">>
    end,
    {ok, <<"control.", Scope/binary, ".", ActionBin/binary>>, #{
        <<"action">> => ActionBin,
        <<"status">> => atom_to_binary(Status),
        <<"details">> => encode_map(Details)
    }};

%% ── Conntrack events ────────────────────────────────────────────
%% Routing: conntrack.flow.<event>

encode_payload({ct_new, Event}) ->
    {ok, <<"conntrack.flow.new">>, encode_ct_flow(Event)};

encode_payload({ct_destroy, Event}) ->
    {ok, <<"conntrack.flow.destroy">>, encode_ct_flow(Event)};

encode_payload({ct_alert, {mode_switch, Mode}}) ->
    {ok, <<"conntrack.alert.mode">>, #{
        <<"mode">> => atom_to_binary(Mode)
    }};

%% ── NFLOG events (logged packets) ───────────────────────────────
%% Routing: firewall.<chain>.packet

encode_payload({nflog_event, #{prefix := Prefix} = Event}) when is_map(Event) ->
    ChainName = case binary:split(Prefix, <<"_drop">>) of
        [Name, _] -> Name;
        _         -> Prefix
    end,
    {ok, <<"firewall.", ChainName/binary, ".packet">>, encode_map(Event)};

encode_payload({nflog_event, Event}) when is_map(Event) ->
    {ok, <<"firewall.unknown.packet">>, encode_map(Event)};

encode_payload({nflog_event, Event}) ->
    {ok, <<"firewall.unknown.packet">>, #{<<"raw">> => term_to_binary_string(Event)}};

%% ── Counter events ─────────────────────────────────────────────
%% Routing: firewall.<chain>.drop

encode_payload({counter_event, Name, #{packets := Pkts} = Rate}) when Pkts > 0 ->
    ChainName = counter_to_chain(Name),
    {ok, <<"firewall.", ChainName/binary, ".drop">>, #{
        <<"chain">> => ChainName,
        <<"packets">> => Pkts,
        <<"pps">> => maps:get(pps, Rate, 0.0),
        <<"bytes">> => maps:get(bytes, Rate, 0),
        <<"bps">> => maps:get(bps, Rate, 0.0)
    }};
encode_payload({counter_event, _Name, _Rate}) ->
    skip;

encode_payload({threshold_event, Id, Name, Metric, Current, Threshold}) ->
    NameBin = ensure_binary(Name),
    {ok, <<"firewall.", NameBin/binary, ".threshold">>, #{
        <<"id">> => ensure_binary(Id),
        <<"name">> => NameBin,
        <<"metric">> => atom_to_binary(Metric),
        <<"current">> => Current,
        <<"threshold">> => Threshold
    }};

%% ── Guard events ───────────────────────────────────────────────
%% Routing: guard.threat.ban | guard.threat.unban

encode_payload({ct_guard_ban, #{ip := Ip, reason := Reason} = Details}) ->
    {ok, <<"guard.threat.ban">>, #{
        <<"ip">> => format_ip(Ip),
        <<"reason">> => atom_to_binary(Reason),
        <<"duration">> => maps:get(duration, Details, 0),
        <<"ban_count">> => maps:get(ban_count, Details, 1)
    }};

encode_payload({ct_guard_ban, Details}) when is_map(Details) ->
    {ok, <<"guard.threat.ban">>, encode_map(Details)};

encode_payload({ct_guard_honeypot, #{ip := Ip, port := Port} = Details}) ->
    {ok, <<"guard.threat.honeypot">>, #{
        <<"ip">> => format_ip(Ip),
        <<"port">> => Port,
        <<"duration">> => maps:get(duration, Details, 86400),
        <<"reason">> => <<"honeypot_port">>
    }};

encode_payload({ct_guard_slow_scan, #{ip := Ip, ports := Ports} = Details}) ->
    {ok, <<"guard.threat.slow_scan">>, #{
        <<"ip">> => format_ip(Ip),
        <<"ports">> => Ports,
        <<"window">> => maps:get(window, Details, 0),
        <<"reason">> => <<"slow_scan">>
    }};

encode_payload({ct_guard_unban, #{ip := Ip}}) ->
    {ok, <<"guard.threat.unban">>, #{
        <<"ip">> => format_ip(Ip)
    }};

encode_payload({ct_guard_unban, Details}) when is_map(Details) ->
    {ok, <<"guard.threat.unban">>, encode_map(Details)};

encode_payload({ct_guard_suspect, #{ip := Ip, ports := Ports}}) ->
    {ok, <<"guard.threat.suspect">>, #{
        <<"ip">> => format_ip(Ip),
        <<"ports">> => [P || P <- Ports, is_integer(P)],
        <<"reason">> => <<"suspect">>
    }};

encode_payload({ct_guard_ban_failed, #{ip := Ip, reason := Reason}}) ->
    {ok, <<"guard.threat.ban_failed">>, #{
        <<"ip">> => format_ip(Ip),
        <<"reason">> => atom_to_binary(Reason)
    }};

encode_payload({guard_stats, #{actors := Actors, bans := Bans,
                                events_seen := Events} = Stats}) ->
    {ok, <<"guard.stats.summary">>, #{
        <<"actors">> => Actors,
        <<"bans">> => Bans,
        <<"events_seen">> => Events,
        <<"tracked_events">> => maps:get(tracked_events, Stats, 0)
    }};

%% ── System events ──────────────────────────────────────────────
%% Routing: system.<scope>.<event>

encode_payload({config_loaded, File, Config}) ->
    Pods = length(maps:get(pods, Config, [])),
    Zones = length(maps:get(zones, Config, [])),
    Tables = length(maps:get(nft_tables, Config, [])),
    {ok, <<"system.config.loaded">>, #{
        <<"file">> => ensure_binary(File),
        <<"pods">> => Pods,
        <<"zones">> => Zones,
        <<"nft_tables">> => Tables
    }};

encode_payload({config_failed, File, {error, Reason}}) ->
    {ok, <<"system.config.failed">>, #{
        <<"file">> => ensure_binary(File),
        <<"reason">> => term_to_binary_string(Reason)
    }};

encode_payload({firewall_applied, Table}) ->
    {ok, <<"system.firewall.applied">>, #{
        <<"table">> => ensure_binary(Table)
    }};

encode_payload({firewall_failed, Table, Reason}) ->
    {ok, <<"system.firewall.failed">>, #{
        <<"table">> => ensure_binary(Table),
        <<"reason">> => term_to_binary_string(Reason)
    }};

encode_payload({log_drop, Name, Count, Bytes}) ->
    {ok, <<"system.log.overflow">>, #{
        <<"name">> => ensure_binary(Name),
        <<"dropped_count">> => Count,
        <<"dropped_bytes">> => Bytes
    }};

encode_payload({log_disconnected, Name}) ->
    {ok, <<"system.log.disconnected">>, #{
        <<"name">> => ensure_binary(Name)
    }};

encode_payload({signature_verified, Id, Name, Meta}) ->
    NameBin = ensure_binary(Name),
    {ok, <<"security.", NameBin/binary, ".verified">>, #{
        <<"id">> => ensure_binary(Id),
        <<"name">> => NameBin,
        <<"signer">> => ensure_binary(maps:get(signer_cn, Meta, <<>>))
    }};

encode_payload({signature_rejected, Id, Name, Reason}) ->
    NameBin = ensure_binary(Name),
    {ok, <<"security.", NameBin/binary, ".rejected">>, #{
        <<"id">> => ensure_binary(Id),
        <<"name">> => NameBin,
        <<"reason">> => term_to_binary_string(Reason)
    }};

%% ── BPF process metrics (fork/exec/exit/oom from C runtime) ─────
%% Routing: metrics.<name>.<type>

encode_payload({container_metrics, Id, Name, #{type := Type} = M}) ->
    NameBin = ensure_binary(Name),
    TypeBin = atom_to_binary(Type),
    Payload = #{
        <<"id">> => ensure_binary(Id),
        <<"name">> => NameBin,
        <<"type">> => TypeBin
    },
    Payload2 = case maps:find(timestamp_ns, M) of
        {ok, Ts} -> Payload#{<<"timestamp_ns">> => Ts};
        error -> Payload
    end,
    Payload3 = case maps:find(comm, M) of
        {ok, Comm} -> Payload2#{<<"comm">> => ensure_binary(Comm)};
        error -> Payload2
    end,
    {ok, <<"metrics.", NameBin/binary, ".", TypeBin/binary>>, Payload3};

%% Legacy 3-arg form (no name)
encode_payload({container_metrics, Id, #{type := Type}}) ->
    IdBin = ensure_binary(Id),
    TypeBin = atom_to_binary(Type),
    {ok, <<"metrics.", IdBin/binary, ".", TypeBin/binary>>, #{
        <<"id">> => IdBin,
        <<"type">> => TypeBin
    }};

encode_payload({container_metrics, _Id, _}) ->
    skip;

%% Unknown
encode_payload(Event) ->
    logger:debug("erlkoenig_amqp_codec: skipping unknown event: ~p", [Event]),
    skip.

-ifdef(TEST).
routing_key(Event) ->
    case encode_payload(Event) of
        {ok, Key, _} -> Key;
        skip -> skip
    end.
-endif.

%%====================================================================
%% Helpers
%%====================================================================

%% Counter names like "forward_drop" → chain name "forward"
-spec counter_to_chain(term()) -> binary().
counter_to_chain(Name) ->
    NameBin = ensure_binary(Name),
    case binary:split(NameBin, <<"_drop">>) of
        [Chain, _] -> Chain;
        _          -> NameBin
    end.

-spec timestamp() -> binary().
timestamp() ->
    Now = os:system_time(millisecond),
    Secs = Now div 1000,
    Ms = Now rem 1000,
    {{Y, Mo, D}, {H, Mi, S}} = calendar:system_time_to_universal_time(Secs, second),
    iolist_to_binary(io_lib:format("~4..0B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0B.~3..0BZ",
                                   [Y, Mo, D, H, Mi, S, Ms])).

-spec ensure_binary(term()) -> binary().
ensure_binary(B) when is_binary(B) ->
    case unicode:characters_to_binary(B) of
        B -> B;
        _ -> safe_binary(B)
    end;
ensure_binary(A) when is_atom(A) -> atom_to_binary(A);
ensure_binary(L) when is_list(L) -> unicode:characters_to_binary(L);
ensure_binary(T) -> term_to_binary_string(T).

-spec term_to_binary_string(term()) -> binary().
term_to_binary_string(B) when is_binary(B) ->
    case unicode:characters_to_binary(B) of
        B -> B;
        _ -> safe_binary(B)
    end;
term_to_binary_string(A) when is_atom(A) -> atom_to_binary(A);
term_to_binary_string(T) -> iolist_to_binary(io_lib:format("~p", [T])).

-spec encode_ct_flow(term()) -> map().
encode_ct_flow(Event) when is_map(Event) ->
    M = #{},
    M1 = case maps:find(src, Event) of
        {ok, SrcIp} -> M#{<<"src">> => format_ip(SrcIp)};
        _ -> M
    end,
    M2 = case maps:find(dst, Event) of
        {ok, DstIp} -> M1#{<<"dst">> => format_ip(DstIp)};
        _ -> M1
    end,
    M3 = case maps:find(sport, Event) of
        {ok, SP} -> M2#{<<"sport">> => SP};
        _ -> M2
    end,
    M4 = case maps:find(dport, Event) of
        {ok, DP} -> M3#{<<"dport">> => DP};
        _ -> M3
    end,
    M5 = case maps:find(proto, Event) of
        {ok, 6}  -> M4#{<<"proto">> => <<"tcp">>};
        {ok, 17} -> M4#{<<"proto">> => <<"udp">>};
        {ok, 1}  -> M4#{<<"proto">> => <<"icmp">>};
        {ok, P}  -> M4#{<<"proto">> => P};
        _ -> M4
    end,
    case maps:find(timeout, Event) of
        {ok, T} -> M5#{<<"timeout">> => T};
        _ -> M5
    end;
encode_ct_flow(Event) ->
    #{<<"raw">> => term_to_binary_string(Event)}.

-spec encode_map(map()) -> map().
encode_map(M) when is_map(M) ->
    maps:fold(fun(K, V, Acc) ->
        Key = ensure_binary(K),
        Val = case is_ip_key(K) of
            true  -> format_ip(V);
            false -> encode_value(V)
        end,
        Acc#{Key => Val}
    end, #{}, M);
encode_map(_) ->
    #{}.

is_ip_key(ip) -> true;
is_ip_key(src) -> true;
is_ip_key(dst) -> true;
is_ip_key(ip_raw) -> true;
is_ip_key(<<"ip">>) -> true;
is_ip_key(<<"src">>) -> true;
is_ip_key(<<"dst">>) -> true;
is_ip_key(_) -> false.

-spec encode_value(term()) -> term().
encode_value(V) when is_atom(V) -> atom_to_binary(V);
encode_value(V) when is_integer(V) -> V;
encode_value(V) when is_float(V) -> V;
encode_value(V) when is_map(V) -> encode_map(V);
encode_value(<<_,_,_,_>> = V) ->
    %% 4-byte binary: likely an IPv4 address if not valid UTF-8
    case unicode:characters_to_binary(V) of
        V -> V;
        _ -> format_ip(V)
    end;
encode_value(V) when is_binary(V) ->
    case unicode:characters_to_binary(V) of
        V -> V;
        _ -> safe_binary(V)
    end;
encode_value(V) -> term_to_binary_string(V).

%% Encode non-UTF-8 binary as hex string
-spec safe_binary(binary()) -> binary().
safe_binary(Bin) ->
    iolist_to_binary([io_lib:format("~2.16.0B", [B]) || <<B>> <= Bin]).

-spec format_ip(binary() | tuple() | term()) -> binary().
format_ip(<<A,B,C,D>>) ->
    iolist_to_binary(io_lib:format("~B.~B.~B.~B", [A,B,C,D]));
format_ip({A,B,C,D}) ->
    iolist_to_binary(io_lib:format("~B.~B.~B.~B", [A,B,C,D]));
format_ip(Bin) when is_binary(Bin) ->
    Bin;
format_ip(Other) ->
    term_to_binary_string(Other).

-spec os_pid(pid()) -> integer() | null.
os_pid(Pid) ->
    try
        case erlang:process_info(Pid, dictionary) of
            {dictionary, Dict} ->
                case proplists:get_value('$os_pid', Dict) of
                    undefined -> null;
                    OsPid -> OsPid
                end;
            _ -> null
        end
    catch _:_ -> null
    end.
