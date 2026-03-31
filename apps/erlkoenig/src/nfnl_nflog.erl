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

-module(nfnl_nflog).
-moduledoc """
Shared NFLOG socket setup for Netlink NETFILTER receivers.

Opens an AF_NETLINK socket, binds to an NFLOG group, and configures
copy mode. Used by erlkoenig_nft_nflog.
""".

-export([open/2, open/1]).

-include("nft_constants.hrl").

%% --- Constants ---

-define(AF_NETLINK, 16).
-define(NETLINK_NETFILTER, 12).
-define(RECV_TIMEOUT, 1000).

%% --- Public API ---

-doc "Open an NFLOG socket bound to Group with default copy range (128 bytes).".
-spec open(non_neg_integer()) -> {ok, socket:socket()} | {error, term()}.
open(Group) ->
    open(Group, 128).

-doc "Open an NFLOG socket bound to Group with the given CopyRange.".
-spec open(non_neg_integer(), non_neg_integer()) -> {ok, socket:socket()} | {error, term()}.
open(Group, CopyRange) ->
    maybe
        {ok, Sock} ?= socket:open(?AF_NETLINK, raw, ?NETLINK_NETFILTER),
        SaData = <<0:16, 0:32/native, 0:32/native, 0:32/native>>,
        Addr = #{family => ?AF_NETLINK, addr => SaData},
        ok ?=
            case socket:bind(Sock, Addr) of
                ok ->
                    ok;
                {error, _} = BindErr ->
                    _ = socket:close(Sock),
                    BindErr
            end,
        ok = send_config_cmd(Sock, ?NFULNL_CFG_CMD_PF_BIND, 0, 2),
        ok = send_config_cmd(Sock, ?NFULNL_CFG_CMD_BIND, Group, 0),
        ok = send_config_mode(Sock, Group, ?NFULNL_COPY_PACKET, CopyRange),
        {ok, Sock}
    else
        {error, _} = Err -> Err
    end.

%% --- Internal ---

-spec send_config_cmd(socket:socket(), non_neg_integer(), non_neg_integer(), non_neg_integer()) ->
    ok | {error, term()}.
send_config_cmd(Sock, Cmd, Group, PF) ->
    NfGenMsg = <<PF:8, 0:8, Group:16/big>>,
    CmdAttr = nfnl_attr:encode(?NFULA_CFG_CMD, <<Cmd:8>>),
    Payload = <<NfGenMsg/binary, CmdAttr/binary>>,
    send_config(Sock, Payload).

-spec send_config_mode(socket:socket(), non_neg_integer(), non_neg_integer(), non_neg_integer()) ->
    ok | {error, term()}.
send_config_mode(Sock, Group, CopyMode, CopyRange) ->
    NfGenMsg = <<0:8, 0:8, Group:16/big>>,
    ModeAttr = nfnl_attr:encode(?NFULA_CFG_MODE, <<CopyRange:32/big, CopyMode:8, 0:8>>),
    Payload = <<NfGenMsg/binary, ModeAttr/binary>>,
    send_config(Sock, Payload).

-spec send_config(socket:socket(), binary()) -> ok | {error, term()}.
send_config(Sock, Payload) ->
    Type = (?NFNL_SUBSYS_ULOG bsl 8) bor ?NFULNL_MSG_CONFIG,
    Flags = ?NLM_F_REQUEST bor ?NLM_F_ACK,
    Seq = erlang:system_time(second) band 16#FFFFFFFF,
    Len = 16 + byte_size(Payload),
    Msg =
        <<Len:32/little, Type:16/little, Flags:16/little, Seq:32/little, 0:32/little,
            Payload/binary>>,
    case socket:send(Sock, Msg) of
        ok ->
            case socket:recv(Sock, 0, ?RECV_TIMEOUT) of
                {ok, _} ->
                    ok;
                {error, Reason} ->
                    logger:warning("[nfnl_nflog] config recv failed: ~p", [Reason]),
                    {error, Reason}
            end;
        Err ->
            Err
    end.
