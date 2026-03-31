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

-module(erlkoenig_steering).
-moduledoc """
BPF steering client for erlkoenig_ebpfd.

Speaks the TLV wire protocol over a Unix domain socket to the
erlkoenig_ebpfd daemon. Used by erlkoenig_ct to register/deregister
container routes and services during the container lifecycle.

All operations are best-effort: if ebpfd is not running, functions
return {error, not_running} and the caller continues without
BPF steering. This is intentional — steering is an optimization,
not a requirement.

Wire protocol: {packet, 4} framing, Tag:8 | Ver:8 | TLV attrs.
See erlkoenig_ebpfd/include/ek_ebpfd_proto.h for the spec.
""".

-export([
    add_route/2,
    del_route/1,
    add_service/3,
    del_service/3,
    set_backends/4,
    get_status/0,
    list_routes/0,
    list_services/0,
    list_backends/3
]).

%% -- Protocol constants -------------------------------------------

-define(PROTO_VERSION, 1).
-define(DEFAULT_SOCKET, "/run/erlkoenig/ebpfd.sock").
-define(CONNECT_TIMEOUT, 2000).
-define(RECV_TIMEOUT, 5000).

%% Commands
-define(CMD_ADD_ROUTE,     16#01).
-define(CMD_DEL_ROUTE,     16#02).
-define(CMD_LIST_ROUTES,   16#03).
-define(CMD_GET_STATUS,    16#04).
-define(CMD_ADD_SERVICE,   16#05).
-define(CMD_DEL_SERVICE,   16#06).
-define(CMD_SET_BACKENDS,  16#07).
-define(CMD_LIST_SERVICES, 16#08).
-define(CMD_LIST_BACKENDS, 16#09).

%% Replies
-define(REPLY_OK,          16#81).
-define(REPLY_ERROR,       16#82).
-define(REPLY_ROUTE,       16#83).
-define(REPLY_ROUTE_END,   16#84).
-define(REPLY_STATUS,      16#85).
-define(REPLY_SERVICE,     16#86).
-define(REPLY_SERVICE_END, 16#87).
-define(REPLY_BACKEND,     16#88).
-define(REPLY_BACKEND_END, 16#89).

%% Attribute types
-define(ATTR_IPV4,          16#0001).
-define(ATTR_IFINDEX,       16#0002).
-define(ATTR_ERRNO,         16#0003).
-define(ATTR_MESSAGE,       16#0004).
-define(ATTR_ROUTE_COUNT,   16#0005).
-define(ATTR_PROTO,         16#0007).
-define(ATTR_PORT,          16#0008).
-define(ATTR_SVC_ID,        16#0009).
-define(ATTR_SVC_COUNT,     16#000A).
-define(ATTR_BACKEND_COUNT, 16#000B).

%% -- Public API ---------------------------------------------------

-doc """
Register a container's IP in the BPF route map.
Called after container network setup.
""".
-spec add_route(inet:ip4_address(), non_neg_integer()) ->
    ok | {error, term()}.
add_route(Ip, IfIndex) ->
    send_command(?CMD_ADD_ROUTE, [
        attr_ipv4(Ip),
        attr_u32(?ATTR_IFINDEX, IfIndex)
    ]).

-doc "Remove a container's IP from the BPF route map.".
-spec del_route(inet:ip4_address()) -> ok | {error, term()}.
del_route(Ip) ->
    send_command(?CMD_DEL_ROUTE, [attr_ipv4(Ip)]).

-doc """
Register an L4 DSR service (VIP:port/proto).
Returns {ok, SvcId} on success.
""".
-spec add_service(inet:ip4_address(), 0..65535, tcp | udp) ->
    {ok, non_neg_integer()} | {error, term()}.
add_service(Vip, Port, Proto) ->
    case send_recv(?CMD_ADD_SERVICE, [
        attr_ipv4(Vip),
        attr_u16(?ATTR_PORT, Port),
        attr_u8(?ATTR_PROTO, proto_to_int(Proto))
    ]) of
        {ok, ?REPLY_OK, Attrs} ->
            {ok, maps:get(svc_id, Attrs, 0)};
        {error, _} = Err ->
            Err
    end.

-doc "Remove an L4 DSR service.".
-spec del_service(inet:ip4_address(), 0..65535, tcp | udp) ->
    ok | {error, term()}.
del_service(Vip, Port, Proto) ->
    send_command(?CMD_DEL_SERVICE, [
        attr_ipv4(Vip),
        attr_u16(?ATTR_PORT, Port),
        attr_u8(?ATTR_PROTO, proto_to_int(Proto))
    ]).

-doc """
Set the backend pool for a service.
Backends is a list of interface indices.
""".
-spec set_backends(inet:ip4_address(), 0..65535, tcp | udp,
                   [non_neg_integer()]) ->
    ok | {error, term()}.
set_backends(Vip, Port, Proto, IfIndices) ->
    Attrs = [
        attr_ipv4(Vip),
        attr_u16(?ATTR_PORT, Port),
        attr_u8(?ATTR_PROTO, proto_to_int(Proto))
        | [attr_u32(?ATTR_IFINDEX, Idx) || Idx <- IfIndices]
    ],
    send_command(?CMD_SET_BACKENDS, Attrs).

-doc "Get daemon status (route count, service count, interface).".
-spec get_status() -> {ok, map()} | {error, term()}.
get_status() ->
    case send_recv(?CMD_GET_STATUS, []) of
        {ok, ?REPLY_STATUS, Attrs} -> {ok, Attrs};
        {error, _} = Err -> Err
    end.

-doc "List all routes in the BPF route map.".
-spec list_routes() -> {ok, [map()]} | {error, term()}.
list_routes() ->
    send_streaming(?CMD_LIST_ROUTES, [], ?REPLY_ROUTE, ?REPLY_ROUTE_END).

-doc "List all registered services.".
-spec list_services() -> {ok, [map()]} | {error, term()}.
list_services() ->
    send_streaming(?CMD_LIST_SERVICES, [], ?REPLY_SERVICE, ?REPLY_SERVICE_END).

-doc "List backends for a service.".
-spec list_backends(inet:ip4_address(), 0..65535, tcp | udp) ->
    {ok, [map()]} | {error, term()}.
list_backends(Vip, Port, Proto) ->
    send_streaming(?CMD_LIST_BACKENDS, [
        attr_ipv4(Vip),
        attr_u16(?ATTR_PORT, Port),
        attr_u8(?ATTR_PROTO, proto_to_int(Proto))
    ], ?REPLY_BACKEND, ?REPLY_BACKEND_END).

%% -- Connection ---------------------------------------------------

-spec connect() -> {ok, gen_tcp:socket()} | {error, term()}.
connect() ->
    Path = application:get_env(erlkoenig, ebpfd_socket, ?DEFAULT_SOCKET),
    case gen_tcp:connect({local, Path}, 0,
                         [binary, {packet, 4}, {active, false}],
                         ?CONNECT_TIMEOUT) of
        {ok, Sock} ->
            {ok, Sock};
        {error, enoent} ->
            {error, not_running};
        {error, econnrefused} ->
            {error, not_running};
        {error, _} = Err ->
            Err
    end.

%% -- Send/Receive -------------------------------------------------

-spec send_command(byte(), [binary()]) -> ok | {error, term()}.
send_command(Tag, AttrBins) ->
    case send_recv(Tag, AttrBins) of
        {ok, ?REPLY_OK, _Attrs} -> ok;
        {error, _} = Err -> Err
    end.

-spec send_recv(byte(), [binary()]) ->
    {ok, byte(), map()} | {error, term()}.
send_recv(Tag, AttrBins) ->
    case connect() of
        {ok, Sock} ->
            try
                Msg = encode_msg(Tag, AttrBins),
                ok = gen_tcp:send(Sock, Msg),
                case gen_tcp:recv(Sock, 0, ?RECV_TIMEOUT) of
                    {ok, Reply} ->
                        decode_reply(Reply);
                    {error, _} = Err ->
                        Err
                end
            after
                gen_tcp:close(Sock)
            end;
        {error, _} = Err ->
            Err
    end.

-spec send_streaming(byte(), [binary()], byte(), byte()) ->
    {ok, [map()]} | {error, term()}.
send_streaming(Tag, AttrBins, ItemTag, EndTag) ->
    case connect() of
        {ok, Sock} ->
            try
                Msg = encode_msg(Tag, AttrBins),
                ok = gen_tcp:send(Sock, Msg),
                collect_stream(Sock, ItemTag, EndTag, [])
            after
                gen_tcp:close(Sock)
            end;
        {error, _} = Err ->
            Err
    end.

collect_stream(Sock, ItemTag, EndTag, Acc) ->
    case gen_tcp:recv(Sock, 0, ?RECV_TIMEOUT) of
        {ok, <<EndTag, _Ver, _Rest/binary>>} ->
            {ok, lists:reverse(Acc)};
        {ok, <<ItemTag, _Ver, Rest/binary>>} ->
            Attrs = decode_attrs(Rest),
            collect_stream(Sock, ItemTag, EndTag, [Attrs | Acc]);
        {ok, <<?REPLY_ERROR, _Ver, Rest/binary>>} ->
            Attrs = decode_attrs(Rest),
            {error, maps:get(message, Attrs, <<"unknown error">>)};
        {ok, _Other} ->
            {error, unexpected_reply};
        {error, _} = Err ->
            Err
    end.

%% -- Encoding -----------------------------------------------------

encode_msg(Tag, AttrBins) ->
    Payload = iolist_to_binary(AttrBins),
    <<Tag, ?PROTO_VERSION, Payload/binary>>.

attr_ipv4({A, B, C, D}) ->
    <<?ATTR_IPV4:16/big, 4:16/big, A, B, C, D>>.

attr_u8(Type, Val) ->
    <<Type:16/big, 1:16/big, Val:8>>.

attr_u16(Type, Val) ->
    <<Type:16/big, 2:16/big, Val:16/big>>.

attr_u32(Type, Val) ->
    <<Type:16/big, 4:16/big, Val:32/big>>.

%% -- Decoding -----------------------------------------------------

decode_reply(<<?REPLY_OK, _Ver, Rest/binary>>) ->
    {ok, ?REPLY_OK, decode_attrs(Rest)};
decode_reply(<<?REPLY_ERROR, _Ver, Rest/binary>>) ->
    Attrs = decode_attrs(Rest),
    Errno = maps:get(errno, Attrs, 0),
    Msg = maps:get(message, Attrs, <<"unknown error">>),
    {error, {ebpfd_error, Errno, Msg}};
decode_reply(<<?REPLY_STATUS, _Ver, Rest/binary>>) ->
    {ok, ?REPLY_STATUS, decode_attrs(Rest)};
decode_reply(<<Tag, _Ver, Rest/binary>>) ->
    {ok, Tag, decode_attrs(Rest)};
decode_reply(_) ->
    {error, bad_reply}.

decode_attrs(Bin) ->
    decode_attrs(Bin, #{}).

decode_attrs(<<>>, Acc) ->
    Acc;
decode_attrs(<<Type:16/big, Len:16/big, Rest/binary>>, Acc)
  when byte_size(Rest) >= Len ->
    <<Value:Len/binary, Tail/binary>> = Rest,
    Key = attr_key(Type),
    Decoded = decode_attr_value(Type, Value),
    Acc2 = case Key of
        ifindex ->
            %% Multiple IFINDEX attrs → collect as list
            case maps:find(ifindex, Acc) of
                {ok, List} when is_list(List) ->
                    Acc#{ifindex => List ++ [Decoded]};
                {ok, Single} ->
                    Acc#{ifindex => [Single, Decoded]};
                error ->
                    Acc#{ifindex => Decoded}
            end;
        _ ->
            Acc#{Key => Decoded}
    end,
    decode_attrs(Tail, Acc2);
decode_attrs(_, Acc) ->
    Acc.

attr_key(?ATTR_IPV4) -> ipv4;
attr_key(?ATTR_IFINDEX) -> ifindex;
attr_key(?ATTR_ERRNO) -> errno;
attr_key(?ATTR_MESSAGE) -> message;
attr_key(?ATTR_ROUTE_COUNT) -> route_count;
attr_key(?ATTR_PROTO) -> proto;
attr_key(?ATTR_PORT) -> port;
attr_key(?ATTR_SVC_ID) -> svc_id;
attr_key(?ATTR_SVC_COUNT) -> svc_count;
attr_key(?ATTR_BACKEND_COUNT) -> backend_count;
attr_key(Other) -> {unknown, Other}.

decode_attr_value(?ATTR_IPV4, <<A, B, C, D>>) -> {A, B, C, D};
decode_attr_value(?ATTR_IFINDEX, <<V:32/big>>) -> V;
decode_attr_value(?ATTR_ERRNO, <<V:32/big-signed>>) -> V;
decode_attr_value(?ATTR_MESSAGE, Bin) -> Bin;
decode_attr_value(?ATTR_ROUTE_COUNT, <<V:32/big>>) -> V;
decode_attr_value(?ATTR_PROTO, <<6>>) -> tcp;
decode_attr_value(?ATTR_PROTO, <<17>>) -> udp;
decode_attr_value(?ATTR_PROTO, <<V>>) -> V;
decode_attr_value(?ATTR_PORT, <<V:16/big>>) -> V;
decode_attr_value(?ATTR_SVC_ID, <<V:32/big>>) -> V;
decode_attr_value(?ATTR_SVC_COUNT, <<V:32/big>>) -> V;
decode_attr_value(?ATTR_BACKEND_COUNT, <<V:32/big>>) -> V;
decode_attr_value(_, Bin) -> Bin.

%% -- Helpers ------------------------------------------------------

proto_to_int(tcp) -> 6;
proto_to_int(udp) -> 17.
