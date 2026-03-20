%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_ctl).
-moduledoc """
Unix socket control server.

Listens on /run/erlkoenig/ctl.sock for management commands.
Each connection is handled in a spawned process.
All commands are logged to erlkoenig_audit.
""".

-behaviour(gen_server).

-export([start_link/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(DEFAULT_SOCK, "/run/erlkoenig/ctl.sock").
-define(MAX_CONNS, 5).

-record(state, {
    listen_sock :: gen_tcp:socket() | undefined,
    path        :: string(),
    conns = 0   :: non_neg_integer()
}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    proc_lib:set_label(erlkoenig_ctl),
    Path = application:get_env(erlkoenig_core, ctl_socket, ?DEFAULT_SOCK),
    %% Remove stale socket file
    _ = file:delete(Path),
    case gen_tcp:listen(0, [
        binary,
        {ifaddr, {local, Path}},
        {packet, 4},
        {active, false},
        {reuseaddr, true}
    ]) of
        {ok, LSock} ->
            %% Set permissions: owner + group read/write
            _ = os:cmd("chmod 0660 " ++ Path),
            logger:info("[ctl] Listening on ~s", [Path]),
            erlkoenig_audit:log(#{
                type => ctl_started,
                subject => <<"ctl">>,
                result => ok,
                details => #{socket => list_to_binary(Path)}
            }),
            %% Start accepting
            self() ! accept,
            {ok, #state{listen_sock = LSock, path = Path}};
        {error, Reason} ->
            logger:error("[ctl] Cannot listen on ~s: ~p", [Path, Reason]),
            %% Start without socket — system still runs, just no CLI
            logger:warning("[ctl] Running without control socket"),
            {ok, #state{path = Path}}
    end.

handle_call(_Request, _From, State) ->
    {reply, {error, unknown}, State}.

handle_cast({conn_done, _Pid}, #state{conns = N} = State) ->
    self() ! accept,
    {noreply, State#state{conns = max(0, N - 1)}};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(accept, #state{listen_sock = undefined} = State) ->
    {noreply, State};
handle_info(accept, #state{listen_sock = _LSock, conns = N} = State) when N >= ?MAX_CONNS ->
    %% Too many connections — wait until one finishes
    {noreply, State};
handle_info(accept, #state{listen_sock = LSock, conns = N} = State) ->
    case gen_tcp:accept(LSock, 100) of
        {ok, Sock} ->
            Pid = spawn_link(fun() -> handle_connection(Sock) end),
            gen_tcp:controlling_process(Sock, Pid),
            %% Continue accepting
            self() ! accept,
            {noreply, State#state{conns = N + 1}};
        {error, timeout} ->
            %% No pending connection — try again later
            erlang:send_after(100, self(), accept),
            {noreply, State};
        {error, closed} ->
            {noreply, State};
        {error, Reason} ->
            logger:error("[ctl] accept error: ~p", [Reason]),
            erlang:send_after(1000, self(), accept),
            {noreply, State}
    end;

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{listen_sock = undefined, path = Path}) ->
    _ = file:delete(Path),
    ok;
terminate(_Reason, #state{listen_sock = LSock, path = Path}) ->
    gen_tcp:close(LSock),
    _ = file:delete(Path),
    ok.

%%%===================================================================
%%% Connection handler (runs in spawned process)
%%%===================================================================

handle_connection(Sock) ->
    %% Get peer credentials (uid/pid) via socket option
    PeerInfo = get_peer_cred(Sock),
    conn_loop(Sock, PeerInfo).

conn_loop(Sock, PeerInfo) ->
    case gen_tcp:recv(Sock, 0, 30_000) of
        {ok, Data} ->
            case erlkoenig_ctl_proto:decode_request(Data) of
                {ok, {ReqId, Cmd, Payload}} ->
                    {Status, RespPayload} = try
                        dispatch(Cmd, Payload, PeerInfo)
                    catch
                        Class:Reason:Stack ->
                            logger:error("[ctl] dispatch ~p crashed: ~p:~p~n~p",
                                        [Cmd, Class, Reason, Stack]),
                            {error, iolist_to_binary(
                                io_lib:format("internal error: ~p", [Reason]))}
                    end,
                    Resp = erlkoenig_ctl_proto:encode_response(ReqId, Status, RespPayload),
                    _ = gen_tcp:send(Sock, Resp),
                    conn_loop(Sock, PeerInfo);
                {error, Reason} ->
                    Resp = erlkoenig_ctl_proto:encode_response(0, error,
                        iolist_to_binary(io_lib:format("~p", [Reason]))),
                    _ = gen_tcp:send(Sock, Resp)
            end;
        {error, closed} ->
            ok;
        {error, timeout} ->
            ok;
        {error, _} ->
            ok
    end,
    _ = gen_tcp:close(Sock),
    gen_server:cast(?MODULE, {conn_done, self()}).

%%%===================================================================
%%% Command dispatch
%%%===================================================================

dispatch(spawn, Payload, PeerInfo) ->
    maybe
        {ok, BinaryPath, OptsJson} ?= parse_spawn_payload(Payload),
        Opts = decode_spawn_opts(OptsJson),
        erlkoenig_audit:log(#{
            type => ctl_spawn,
            subject => BinaryPath,
            result => ok,
            details => maps:merge(PeerInfo, #{opts => OptsJson})
        }),
        {ok, Pid} ?= erlkoenig_sup:start_container(BinaryPath, Opts),
        {ok, iolist_to_binary(io_lib:format("~p", [Pid]))}
    else
        {error, Reason} ->
            {error, iolist_to_binary(io_lib:format("~p", [Reason]))}
    end;

dispatch(stop, Payload, PeerInfo) ->
    {ContainerId, _} = erlkoenig_ctl_proto:decode_str(Payload),
    maybe
        {ok, Pid} ?= erlkoenig_core:find_by_id(ContainerId),
        erlkoenig_audit:log(#{
            type => ctl_stop,
            subject => ContainerId,
            result => ok,
            details => PeerInfo
        }),
        ok ?= erlkoenig_core:stop(Pid),
        {ok, <<"stopped">>}
    else
        {error, not_found} ->
            {error, <<"container not found">>};
        {error, Reason} ->
            {error, iolist_to_binary(io_lib:format("~p", [Reason]))}
    end;

dispatch(ps, _Payload, _PeerInfo) ->
    Containers = erlkoenig_core:list(),
    Json = encode_container_list(Containers),
    {ok, Json};

dispatch(inspect, Payload, _PeerInfo) ->
    {ContainerId, _} = erlkoenig_ctl_proto:decode_str(Payload),
    case erlkoenig_core:find_by_id(ContainerId) of
        {ok, Pid} ->
            Info = erlkoenig_core:inspect(Pid),
            {ok, iolist_to_binary(io_lib:format("~p", [Info]))};
        {error, not_found} ->
            {error, <<"container not found">>}
    end;

dispatch(audit, Payload, _PeerInfo) ->
    Opts = case Payload of
        <<>> -> #{};
        _ -> decode_audit_opts(Payload)
    end,
    case erlkoenig_audit:query(Opts) of
        {ok, Lines} ->
            {ok, iolist_to_binary(lists:join($\n, Lines))};
        {error, Reason} ->
            {error, iolist_to_binary(io_lib:format("~p", [Reason]))}
    end;

dispatch(status, _Payload, _PeerInfo) ->
    Info = #{
        node => node(),
        uptime => erlang:statistics(wall_clock),
        memory => erlang:memory(total),
        process_count => erlang:system_info(process_count),
        pki_mode => erlkoenig_pki:mode()
    },
    {ok, iolist_to_binary(io_lib:format("~p", [Info]))};

%% --- Ingestion commands (ETF payloads) ---

dispatch(push, Payload, PeerInfo) ->
    PushInfo = binary_to_term(Payload),
    #{name := Name, binary := BinaryData} = PushInfo,
    Tags = maps:get(tags, PushInfo, []),
    Files = maps:get(files, PushInfo, []),
    Signature = maps:get(signature, PushInfo, undefined),

    erlkoenig_audit:log(#{
        type => ctl_push,
        subject => Name,
        result => ok,
        details => maps:merge(PeerInfo, #{
            binary_size => byte_size(BinaryData),
            tags => Tags,
            files_count => length(Files),
            signed => Signature =/= undefined
        })
    }),

    %% Verify signature if present (optional — erlkoenig_sig may not be loaded)
    case Signature of
        undefined -> ok;
        SigData ->
            try
                TrustRoots = application:get_env(erlkoenig_core, trust_roots, []),
                case erlkoenig_sig:verify_binary(BinaryData, SigData, TrustRoots) of
                    ok -> ok;
                    {error, SigReason} -> throw({signature_error, SigReason})
                end
            catch
                error:undef ->
                    %% erlkoenig_sig not available — skip verification in Phase 1
                    logger:warning("[ctl] push: signature provided but erlkoenig_sig not available, skipping verification"),
                    ok
            end
    end,

    %% Store binary + files via erlkoenig_ingest (if available)
    %% or fall back to direct artifact_store registration
    BinaryHash = crypto:hash(sha256, BinaryData),
    Result = try
        StorePid = whereis(erlkoenig_fuse_store),
        case StorePid of
            undefined -> throw(fuse_store_not_available);
            _ ->
                {ok, IngestResult} = erlkoenig_ingest:ingest_binary(
                    BinaryData, <<"app">>, StorePid),
                #{manifest := Manifest} = IngestResult,

                %% Ingest extra files
                lists:foreach(fun({FilePath, FileData}) ->
                    erlkoenig_ingest:ingest_inline(FileData, FilePath, StorePid)
                end, Files),

                ManifestHash = maps:get(hash, Manifest),
                {ok, ManifestHash}
        end
    catch
        error:undef ->
            %% erlkoenig_ingest not available — store metadata only
            logger:warning("[ctl] push: erlkoenig_ingest not available, storing metadata only"),
            {ok, BinaryHash};
        throw:fuse_store_not_available ->
            logger:warning("[ctl] push: fuse_store not running, storing metadata only"),
            {ok, BinaryHash}
    end,

    case Result of
        {ok, Hash} ->
            ok = erlkoenig_artifact_store:register(Name, #{
                manifest_hash => Hash,
                binary_hash => BinaryHash,
                binary_size => byte_size(BinaryData),
                signature => Signature,
                pushed_at => erlang:system_time(second),
                tags => Tags,
                files => [{P, byte_size(D)} || {P, D} <- Files]
            }),
            RespTerm = #{manifest_hash => Hash, name => Name},
            {ok, term_to_binary(RespTerm)};
        {error, Reason} ->
            {error, iolist_to_binary(io_lib:format("~p", [Reason]))}
    end;

dispatch(artifacts, Payload, _PeerInfo) ->
    Opts = case Payload of
        <<>> -> #{};
        _    -> binary_to_term(Payload)
    end,
    AllArtifacts = erlkoenig_artifact_store:list(),
    Filtered = case maps:get(tag, Opts, undefined) of
        undefined -> AllArtifacts;
        Tag ->
            [A || A <- AllArtifacts,
                  lists:member(Tag, maps:get(tags, A, []))]
    end,
    {ok, term_to_binary(Filtered)};

dispatch(artifact_info, Payload, _PeerInfo) ->
    Name = binary_to_term(Payload),
    case erlkoenig_artifact_store:lookup(Name) of
        {ok, Info} ->
            {ok, term_to_binary(Info)};
        {error, not_found} ->
            {error, <<"not found">>}
    end;

dispatch(artifact_tag, Payload, PeerInfo) ->
    {Name, Tag} = binary_to_term(Payload),
    erlkoenig_audit:log(#{
        type => ctl_artifact_tag,
        subject => Name,
        result => ok,
        details => maps:merge(PeerInfo, #{tag => Tag})
    }),
    ok = erlkoenig_artifact_store:tag(Name, Tag),
    {ok, <<"ok">>};

dispatch(artifact_delete, Payload, PeerInfo) ->
    Name = binary_to_term(Payload),
    erlkoenig_audit:log(#{
        type => ctl_artifact_delete,
        subject => Name,
        result => ok,
        details => PeerInfo
    }),
    ok = erlkoenig_artifact_store:delete(Name),
    {ok, <<"ok">>}.

%%%===================================================================
%%% Helpers
%%%===================================================================

parse_spawn_payload(Payload) ->
    try
        {BinaryPath, Rest} = erlkoenig_ctl_proto:decode_str(Payload),
        {OptsJson, _} = erlkoenig_ctl_proto:decode_str(Rest),
        {ok, BinaryPath, OptsJson}
    catch
        _:_ -> {error, invalid_spawn_payload}
    end.

decode_spawn_opts(<<"{}">>) -> #{};
decode_spawn_opts(Json) ->
    %% Minimal extraction of known fields from JSON.
    %% No full parser — extract ip, args, signature by pattern matching.
    Opts0 = #{},
    Opts1 = case extract_json_string(Json, <<"ip">>) of
        {ok, Ip} ->
            case parse_ip(Ip) of
                {ok, IpTuple} -> Opts0#{ip => IpTuple};
                _ -> Opts0
            end;
        _ -> Opts0
    end,
    Opts2 = case extract_json_array(Json, <<"args">>) of
        {ok, Args} -> Opts1#{args => Args};
        _ -> Opts1
    end,
    Opts3 = case extract_json_string(Json, <<"signature">>) of
        {ok, <<"required">>} -> Opts2;  %% use convention: <binary>.sig
        {ok, SigPath} -> Opts2#{sig_path => SigPath};
        _ -> Opts2
    end,
    Opts3.

%% Extract a string value from JSON: "key":"value"
extract_json_string(Json, Key) ->
    Pattern = <<"\"", Key/binary, "\":\"">>,
    case binary:match(Json, Pattern) of
        {Pos, Len} ->
            Start = Pos + Len,
            Rest = binary:part(Json, Start, byte_size(Json) - Start),
            case binary:match(Rest, <<"\"">> ) of
                {EndPos, _} ->
                    {ok, binary:part(Rest, 0, EndPos)};
                nomatch -> error
            end;
        nomatch -> error
    end.

%% Extract a string array: "key":["a","b"]
extract_json_array(Json, Key) ->
    Pattern = <<"\"", Key/binary, "\":[">>,
    case binary:match(Json, Pattern) of
        {Pos, Len} ->
            Start = Pos + Len,
            Rest = binary:part(Json, Start, byte_size(Json) - Start),
            case binary:match(Rest, <<"]">>) of
                {EndPos, _} ->
                    Inner = binary:part(Rest, 0, EndPos),
                    Items = [unquote(I) || I <- binary:split(Inner, <<",">>, [global]),
                                           I =/= <<>>],
                    {ok, Items};
                nomatch -> error
            end;
        nomatch -> error
    end.

unquote(<<"\"", Rest/binary>>) ->
    case binary:match(Rest, <<"\"">>) of
        {Pos, _} -> binary:part(Rest, 0, Pos);
        nomatch -> Rest
    end;
unquote(Bin) -> Bin.

parse_ip(Bin) ->
    try
        Parts = binary:split(Bin, <<".">>, [global]),
        [A, B, C, D] = [binary_to_integer(P) || P <- Parts],
        {ok, {A, B, C, D}}
    catch
        _:_ -> error
    end.

decode_audit_opts(Payload) ->
    try
        {Json, _} = erlkoenig_ctl_proto:decode_str(Payload),
        #{raw_query => Json}
    catch
        _:_ -> #{}
    end.

encode_container_list(Containers) when is_list(Containers) ->
    Lines = [iolist_to_binary(io_lib:format("~p", [C])) || C <- Containers],
    iolist_to_binary(lists:join($\n, Lines)).

get_peer_cred(Sock) ->
    %% SO_PEERCRED gives us uid, gid, pid of the connecting process.
    %% This is Linux-specific (SOL_SOCKET=1, SO_PEERCRED=17).
    case inet:getopts(Sock, [raw]) of
        _ ->
            %% gen_tcp on local sockets doesn't expose peercred directly.
            %% Use port_command workaround or just log socket info.
            #{peer => local}
    end.
