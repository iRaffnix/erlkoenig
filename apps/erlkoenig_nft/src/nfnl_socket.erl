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

-module(nfnl_socket).
-moduledoc """
Raw Netlink socket for nf_tables communication.

Opens an AF_NETLINK/NETLINK_NETFILTER socket using the OTP `socket`
module and provides send/recv operations for talking to the kernel.

Requires CAP_NET_ADMIN (typically root). The socket is not wrapped
in a gen_server yet — that comes later when we add event monitoring
via multicast groups.
""".

-export([open/0,
         send/2,
         recv/1,
         recv/2,
         close/1]).

%% --- Constants ---

-define(AF_NETLINK, 16).
-define(NETLINK_NETFILTER, 12).
-define(DEFAULT_RECV_TIMEOUT, 5000).

%% --- Public API ---

-doc """
Open a Netlink socket bound to NETLINK_NETFILTER.

Returns `{ok, Socket}` or `{error, Reason}`.
The socket is bound with pid=0, letting the kernel assign our port ID.
""".
-spec open() -> {ok, socket:socket()} | {error, atom()}.
open() ->
    case socket:open(?AF_NETLINK, raw, ?NETLINK_NETFILTER) of
        {ok, Sock} ->
            case socket:bind(Sock, sockaddr(0, 0)) of
                ok ->
                    {ok, Sock};
                {error, _} = Err ->
                    _ = socket:close(Sock),
                    Err
            end;
        {error, _} = Err ->
            Err
    end.

-doc "Send a binary message to the kernel (pid 0).".
-spec send(socket:socket(), binary()) -> ok | {error, atom()}.
send(Sock, Data) when is_binary(Data) ->
    case socket:sendto(Sock, Data, sockaddr(0, 0)) of
        {ok, _} -> ok;
        ok      -> ok;
        {error, _} = Err -> Err
    end.

-doc "Receive a message with the default timeout (5s).".
-spec recv(socket:socket()) -> {ok, binary()} | {error, atom()}.
recv(Sock) ->
    recv(Sock, ?DEFAULT_RECV_TIMEOUT).

-doc "Receive a message with a custom timeout in milliseconds.".
-spec recv(socket:socket(), timeout()) -> {ok, binary()} | {error, atom()}.
recv(Sock, Timeout) ->
    socket:recv(Sock, 0, Timeout).

-doc "Close the socket. Always returns ok.".
-spec close(socket:socket()) -> ok.
close(Sock) ->
    _ = socket:close(Sock),
    ok.

%% --- Internal ---

-spec sockaddr(non_neg_integer(), non_neg_integer()) -> map().
sockaddr(Pid, Groups) ->
    #{family => ?AF_NETLINK,
      addr   => <<?AF_NETLINK:16/native, 0:16,
                   Pid:32/native, Groups:32/native>>}.
