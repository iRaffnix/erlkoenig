%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_ctl_proto).
-moduledoc """
Control socket wire protocol -- encode/decode.

Binary format (all big-endian):
  Request:  RequestId:32 | Cmd:8 | Payload
  Response: RequestId:32 | Status:8 | Payload

Status: 0 = ok, 1 = error

Transport uses {packet, 4} (4-byte length prefix).
""".

-export([decode_request/1, encode_response/3]).
-export([encode_request/3, decode_response/1]).  %% for CLI/testing
-export([encode_str/1, decode_str/1]).

%% Command IDs
-define(CMD_SPAWN,   16#01).
-define(CMD_STOP,    16#02).
-define(CMD_PS,      16#03).
-define(CMD_INSPECT, 16#04).
-define(CMD_AUDIT,   16#06).
-define(CMD_STATUS,  16#07).
%% Ingestion commands (payload is ETF-encoded)
-define(CMD_PUSH,             16#10).
-define(CMD_ARTIFACTS,        16#11).
-define(CMD_ARTIFACT_INFO,    16#12).
-define(CMD_ARTIFACT_TAG,     16#13).
-define(CMD_ARTIFACT_DELETE,  16#14).

-define(STATUS_OK,    0).
-define(STATUS_ERROR, 1).

-type cmd() :: spawn | stop | ps | inspect | audit | status
             | push | artifacts | artifact_info | artifact_tag | artifact_delete.
-type request() :: {RequestId :: non_neg_integer(), cmd(), Payload :: binary()}.
-type response() :: {RequestId :: non_neg_integer(), ok | error, Payload :: binary()}.

%%%===================================================================
%%% Decode (server-side)
%%%===================================================================

-spec decode_request(binary()) -> {ok, request()} | {error, term()}.
decode_request(<<ReqId:32/big, CmdByte:8, Payload/binary>>) ->
    case cmd_from_byte(CmdByte) of
        {ok, Cmd} -> {ok, {ReqId, Cmd, Payload}};
        error     -> {error, {unknown_command, CmdByte}}
    end;
decode_request(_) ->
    {error, invalid_request}.

%%%===================================================================
%%% Encode (server-side)
%%%===================================================================

-spec encode_response(non_neg_integer(), ok | error, binary()) -> binary().
encode_response(ReqId, ok, Payload) ->
    <<ReqId:32/big, ?STATUS_OK:8, Payload/binary>>;
encode_response(ReqId, error, Payload) ->
    <<ReqId:32/big, ?STATUS_ERROR:8, Payload/binary>>.

%%%===================================================================
%%% Encode (client-side, for CLI/tests)
%%%===================================================================

-spec encode_request(non_neg_integer(), cmd(), binary()) -> binary().
encode_request(ReqId, Cmd, Payload) ->
    <<ReqId:32/big, (cmd_to_byte(Cmd)):8, Payload/binary>>.

-spec decode_response(binary()) -> {ok, response()} | {error, term()}.
decode_response(<<ReqId:32/big, ?STATUS_OK:8, Payload/binary>>) ->
    {ok, {ReqId, ok, Payload}};
decode_response(<<ReqId:32/big, ?STATUS_ERROR:8, Payload/binary>>) ->
    {ok, {ReqId, error, Payload}};
decode_response(_) ->
    {error, invalid_response}.

%%%===================================================================
%%% Payload helpers
%%%===================================================================

-spec encode_str(binary()) -> binary().
encode_str(Bin) when is_binary(Bin) ->
    Len = byte_size(Bin),
    <<Len:16/big, Bin/binary>>.

-spec decode_str(binary()) -> {binary(), binary()}.
decode_str(<<Len:16/big, Str:Len/binary, Rest/binary>>) ->
    {Str, Rest}.

%%%===================================================================
%%% Internal
%%%===================================================================

cmd_from_byte(?CMD_SPAWN)           -> {ok, spawn};
cmd_from_byte(?CMD_STOP)            -> {ok, stop};
cmd_from_byte(?CMD_PS)              -> {ok, ps};
cmd_from_byte(?CMD_INSPECT)         -> {ok, inspect};
cmd_from_byte(?CMD_AUDIT)           -> {ok, audit};
cmd_from_byte(?CMD_STATUS)          -> {ok, status};
cmd_from_byte(?CMD_PUSH)            -> {ok, push};
cmd_from_byte(?CMD_ARTIFACTS)       -> {ok, artifacts};
cmd_from_byte(?CMD_ARTIFACT_INFO)   -> {ok, artifact_info};
cmd_from_byte(?CMD_ARTIFACT_TAG)    -> {ok, artifact_tag};
cmd_from_byte(?CMD_ARTIFACT_DELETE) -> {ok, artifact_delete};
cmd_from_byte(_)                    -> error.

cmd_to_byte(spawn)           -> ?CMD_SPAWN;
cmd_to_byte(stop)            -> ?CMD_STOP;
cmd_to_byte(ps)              -> ?CMD_PS;
cmd_to_byte(inspect)         -> ?CMD_INSPECT;
cmd_to_byte(audit)           -> ?CMD_AUDIT;
cmd_to_byte(status)          -> ?CMD_STATUS;
cmd_to_byte(push)            -> ?CMD_PUSH;
cmd_to_byte(artifacts)       -> ?CMD_ARTIFACTS;
cmd_to_byte(artifact_info)   -> ?CMD_ARTIFACT_INFO;
cmd_to_byte(artifact_tag)    -> ?CMD_ARTIFACT_TAG;
cmd_to_byte(artifact_delete) -> ?CMD_ARTIFACT_DELETE.
