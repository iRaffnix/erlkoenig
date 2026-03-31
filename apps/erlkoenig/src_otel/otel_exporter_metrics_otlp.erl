%%
%% Shim for OTLP metric export.
%%
%% The opentelemetry_exporter v1.10.0 references this module in
%% opentelemetry_exporter:export(metrics, ...) but does not ship it.
%% This module fills the gap until upstream adds it.
%%
%% Follows the same pattern as otel_exporter_traces_otlp.
%%

-module(otel_exporter_metrics_otlp).

-export([export/3]).

-include_lib("kernel/include/logger.hrl").

export(Metrics, Resource, State) ->
    case extract_endpoint(State) of
        {ok, Scheme, Host, Port, Path0, Headers, Compression, SSLOptions, HttpcProfile} ->
            %% Replace /v1/traces with /v1/metrics in the endpoint path
            Path = metrics_path(Path0),
            case
                uri_string:normalize(#{
                    scheme => Scheme,
                    host => Host,
                    port => Port,
                    path => Path
                })
            of
                {error, _Type, _Error} ->
                    error;
                Address ->
                    ToProtoMod = to_proto_mod(),
                    ProtoMap = ToProtoMod:to_proto(Metrics, Resource),
                    PbMod = pb_mod(),
                    ExporterMod = exporter_mod(),
                    Body = PbMod:encode_msg(ProtoMap, export_metrics_service_request),
                    ExporterMod:export_http(
                        Address, Headers, Body, Compression, SSLOptions, HttpcProfile
                    )
            end;
        error ->
            {error, no_endpoint}
    end.

%% --- Internal ---

metrics_path(Path) when is_list(Path) ->
    case lists:suffix("v1/traces", Path) of
        true ->
            lists:sublist(Path, length(Path) - length("v1/traces")) ++ "v1/metrics";
        false ->
            case lists:suffix("v1/metrics", Path) of
                true -> Path;
                false -> Path ++ "/v1/metrics"
            end
    end;
metrics_path(Path) when is_binary(Path) ->
    list_to_binary(metrics_path(binary_to_list(Path))).

%% Dynamic module references to avoid xref warnings — these modules
%% are only available in the prod release (opentelemetry_exporter dep).
to_proto_mod() -> otel_otlp_metrics.
pb_mod() -> opentelemetry_exporter_metrics_service_pb.
exporter_mod() -> otel_exporter_otlp.

extract_endpoint(State) ->
    try
        %% The state is a record from otel_exporter_traces_otlp.
        %% Record fields: channel, httpc_profile, protocol, channel_pid,
        %%                headers, compression, grpc_metadata, endpoints
        %% We use element/N since the record definition is private.
        HttpcProfile = element(3, State),
        Headers = element(6, State),
        Compression = element(7, State),
        Endpoints = element(9, State),
        case Endpoints of
            [
                #{
                    scheme := Scheme,
                    host := Host,
                    port := Port,
                    path := Path,
                    ssl_options := SSLOptions
                }
                | _
            ] ->
                {ok, Scheme, Host, Port, Path, Headers, Compression, SSLOptions, HttpcProfile};
            _ ->
                error
        end
    catch
        _:_ -> error
    end.
