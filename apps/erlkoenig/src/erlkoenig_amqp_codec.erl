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

Envelope format (v1):
  {
    "v": 1,
    "ts": "2026-04-04T12:34:56.789Z",
    "node": "erlkoenig@host",
    "routing_key": "container.started",
    "payload": { ... }
  }
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
                <<"v">> => 1,
                <<"ts">> => timestamp(),
                <<"node">> => atom_to_binary(node()),
                <<"routing_key">> => RoutingKey,
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
%%====================================================================

-spec encode_payload(term()) -> {ok, binary(), map()} | skip.

%% ── Lifecycle events ─────────────────────────────────────────────
%% Routing: container.<event>.<name>
%% Name is the canonical container name from the DSL (e.g. "web-0-nginx").

encode_payload({container_started, Id, Name, Pid}) when is_pid(Pid) ->
    NameBin = ensure_binary(Name),
    {ok, <<"container.started.", NameBin/binary>>, #{
        <<"id">> => ensure_binary(Id),
        <<"name">> => NameBin,
        <<"os_pid">> => os_pid(Pid)
    }};

encode_payload({container_stopped, Id, Name, #{exit_code := Code, term_signal := Sig}}) ->
    NameBin = ensure_binary(Name),
    {ok, <<"container.stopped.", NameBin/binary>>, #{
        <<"id">> => ensure_binary(Id),
        <<"name">> => NameBin,
        <<"exit_code">> => Code,
        <<"signal">> => Sig
    }};

encode_payload({container_stopped, Id, Name, _}) ->
    NameBin = ensure_binary(Name),
    {ok, <<"container.stopped.", NameBin/binary>>, #{
        <<"id">> => ensure_binary(Id),
        <<"name">> => NameBin,
        <<"exit_code">> => null,
        <<"signal">> => null
    }};

encode_payload({container_failed, Id, Name, Reason}) ->
    NameBin = ensure_binary(Name),
    {ok, <<"container.failed.", NameBin/binary>>, #{
        <<"id">> => ensure_binary(Id),
        <<"name">> => NameBin,
        <<"reason">> => term_to_binary_string(Reason)
    }};

encode_payload({container_restarting, Id, Name, Count}) ->
    NameBin = ensure_binary(Name),
    {ok, <<"container.restarting.", NameBin/binary>>, #{
        <<"id">> => ensure_binary(Id),
        <<"name">> => NameBin,
        <<"attempt">> => Count
    }};

encode_payload({container_oom, Id, Name}) ->
    NameBin = ensure_binary(Name),
    {ok, <<"container.oom.", NameBin/binary>>, #{
        <<"id">> => ensure_binary(Id),
        <<"name">> => NameBin
    }};

encode_payload({container_unhealthy, Id, FailCount}) ->
    IdBin = ensure_binary(Id),
    {ok, <<"container.unhealthy.", IdBin/binary>>, #{
        <<"id">> => IdBin,
        <<"failures">> => FailCount
    }};

%% ── Metrics events ──────────────────────────────────────────────
%% Routing: metrics.<type>.<id>

encode_payload({container_metrics, Id, #{type := Type} = M}) ->
    IdBin = ensure_binary(Id),
    TypeBin = atom_to_binary(Type),
    RoutingKey = <<"metrics.", TypeBin/binary, ".", IdBin/binary>>,
    Payload = #{
        <<"id">> => IdBin,
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
    {ok, RoutingKey, Payload3};

encode_payload({container_metrics, Id, _}) ->
    IdBin = ensure_binary(Id),
    {ok, <<"metrics.unknown.", IdBin/binary>>, #{
        <<"id">> => IdBin,
        <<"type">> => <<"unknown">>
    }};

%% ── Policy events ───────────────────────────────────────────────
%% Routing: policy.violation.<id>

encode_payload({policy_violation, Id, {Type, Action}}) ->
    IdBin = ensure_binary(Id),
    {ok, <<"policy.violation.", IdBin/binary>>, #{
        <<"id">> => IdBin,
        <<"violation_type">> => atom_to_binary(Type),
        <<"action">> => atom_to_binary(Action)
    }};

encode_payload({policy_violation, Id, {Type, Detail, Action}}) ->
    IdBin = ensure_binary(Id),
    {ok, <<"policy.violation.", IdBin/binary>>, #{
        <<"id">> => IdBin,
        <<"violation_type">> => atom_to_binary(Type),
        <<"action">> => atom_to_binary(Action),
        <<"detail">> => term_to_binary_string(Detail)
    }};

encode_payload({policy_violation, Id, Details}) ->
    IdBin = ensure_binary(Id),
    {ok, <<"policy.violation.", IdBin/binary>>, #{
        <<"id">> => IdBin,
        <<"detail">> => term_to_binary_string(Details)
    }};

%% ── Firewall control events ──────────────────────────────────────

encode_payload({control_event, #{action := Action, status := Status, details := Details}}) ->
    ActionBin = atom_to_binary(Action),
    {ok, <<"nft.control.", ActionBin/binary>>, #{
        <<"action">> => atom_to_binary(Action),
        <<"status">> => atom_to_binary(Status),
        <<"details">> => encode_map(Details)
    }};

%% ── Conntrack events ────────────────────────────────────────────

encode_payload({ct_new, Event}) ->
    {ok, <<"nft.ct.new">>, encode_ct_flow(Event)};

encode_payload({ct_destroy, Event}) ->
    {ok, <<"nft.ct.destroy">>, encode_ct_flow(Event)};

encode_payload({ct_alert, {mode_switch, Mode}}) ->
    {ok, <<"nft.ct.alert">>, #{
        <<"type">> => <<"mode_switch">>,
        <<"mode">> => atom_to_binary(Mode)
    }};

%% ── NFLOG events (logged packets) ───────────────────────────────

encode_payload({nflog_event, #{prefix := Prefix} = Event}) when is_map(Event) ->
    %% Container drop events have prefix = counter name (e.g. "web-0-nginx_drop")
    %% Route as nft.drop.<container-name> for per-container filtering
    RoutingKey = case binary:split(Prefix, <<"_drop">>) of
        [ContainerName, _] ->
            <<"nft.drop.", ContainerName/binary>>;
        _ ->
            <<"nft.nflog.", Prefix/binary>>
    end,
    %% NFLOG events already have string IPs (not raw binaries)
    {ok, RoutingKey, encode_map(Event)};

encode_payload({nflog_event, Event}) when is_map(Event) ->
    {ok, <<"nft.nflog">>, encode_map(Event)};

encode_payload({nflog_event, Event}) ->
    {ok, <<"nft.nflog">>, #{<<"raw">> => term_to_binary_string(Event)}};

%% ── Counter / threshold events ──────────────────────────────────

encode_payload({counter_event, Name, #{packets := Pkts} = Rate}) when Pkts > 0 ->
    NameBin = ensure_binary(Name),
    {ok, <<"nft.counter.", NameBin/binary>>, #{
        <<"name">> => NameBin,
        <<"packets">> => Pkts,
        <<"pps">> => maps:get(pps, Rate, 0.0),
        <<"bytes">> => maps:get(bytes, Rate, 0),
        <<"bps">> => maps:get(bps, Rate, 0.0)
    }};
encode_payload({counter_event, _Name, _Rate}) ->
    %% Skip zero-rate counters (no drops = no event)
    skip;

encode_payload({threshold_event, Id, Name, Metric, Current, Threshold}) ->
    {ok, <<"nft.threshold">>, #{
        <<"id">> => ensure_binary(Id),
        <<"name">> => ensure_binary(Name),
        <<"metric">> => atom_to_binary(Metric),
        <<"current">> => Current,
        <<"threshold">> => Threshold
    }};

%% ── Guard events (ct_guard_events pg group) ─────────────────────

encode_payload({ct_guard_ban, #{ip := Ip, reason := Reason} = Details}) ->
    IpStr = format_ip(Ip),
    {ok, <<"nft.guard.ban.", IpStr/binary>>, #{
        <<"ip">> => format_ip(Ip),
        <<"reason">> => atom_to_binary(Reason),
        <<"duration">> => maps:get(duration, Details, 0)
    }};

encode_payload({ct_guard_ban, Details}) when is_map(Details) ->
    {ok, <<"nft.guard.ban">>, encode_map(Details)};

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
        {ok, <<A,B,C,D>>} ->
            M#{<<"src">> => iolist_to_binary(io_lib:format("~B.~B.~B.~B", [A,B,C,D]))};
        _ -> M
    end,
    M2 = case maps:find(dst, Event) of
        {ok, <<E,F,G,H>>} ->
            M1#{<<"dst">> => iolist_to_binary(io_lib:format("~B.~B.~B.~B", [E,F,G,H]))};
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
