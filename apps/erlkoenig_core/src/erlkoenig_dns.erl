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

%%%-------------------------------------------------------------------
%% @doc erlkoenig_dns - Built-in DNS server for container service discovery.
%%
%% Listens on the bridge IP (10.0.0.1:53) for DNS queries.
%% Resolves *.erlkoenig names to container IPs, forwards everything
%% else to an upstream DNS server.
%%
%% Container names are registered/unregistered via register/2 and
%% unregister/1. erlkoenig_ct calls these during lifecycle transitions.
%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_dns).

-behaviour(gen_server).

-export([start_link/0, start_link/1,
         register/2,
         unregister/1,
         lookup/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(DNS_PORT, 53).
%% Legacy default, now overridable via zone config
-define(BRIDGE_IP, {10, 0, 0, 1}).

%% DNS constants
-define(TYPE_A,     1).
-define(TYPE_PTR,  12).
-define(CLASS_IN,   1).
-define(RCODE_OK,       0).
-define(RCODE_NXDOMAIN, 3).

-define(UPSTREAM_TIMEOUT, 5000).

-record(state, {
    socket   :: gen_udp:socket() | undefined,
    tab      :: ets:tid(),          %% {name, FqName, Ip} + {ip, Ip, FqName}
    upstream :: inet:ip4_address(),
    domain   :: binary(),
    ttl      :: non_neg_integer(),
    pending  :: #{non_neg_integer() => {inet:ip_address(), inet:port_number(),
                                        gen_udp:socket(), reference()}}
}).

%% =================================================================
%% API
%% =================================================================

-spec start_link() -> gen_server:start_ret().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-spec register(binary(), inet:ip4_address()) -> ok.
register(Name, Ip) ->
    gen_server:call(?MODULE, {register, Name, Ip}).

-spec unregister(binary()) -> ok.
unregister(Name) ->
    gen_server:call(?MODULE, {unregister, Name}).

-spec lookup(binary()) -> {ok, inet:ip4_address()} | not_found.
lookup(Name) ->
    gen_server:call(?MODULE, {lookup, Name}).

%% =================================================================
%% gen_server callbacks
%% =================================================================

init([]) ->
    do_init(default, application:get_env(erlkoenig_core, gateway, {10, 0, 0, 1}));

init({zone, #{zone := ZoneName, gateway := Gateway} = _Config}) ->
    do_init(ZoneName, Gateway).

do_init(ZoneName, BindIp) ->
    Upstream = application:get_env(erlkoenig_core, dns_upstream, {8, 8, 8, 8}),
    Domain   = list_to_binary(
                 application:get_env(erlkoenig_core, dns_domain, "erlkoenig")),
    TTL      = application:get_env(erlkoenig_core, dns_ttl, 5),
    Tab      = ets:new(dns_records, [bag, protected]),
    case gen_udp:open(?DNS_PORT, [binary, {ip, BindIp},
                                  {active, true}, {reuseaddr, true}]) of
        {ok, Socket} ->
            register_zone_service(ZoneName),
            {ok, #state{socket   = Socket,
                        tab      = Tab,
                        upstream = Upstream,
                        domain   = Domain,
                        ttl      = TTL,
                        pending  = #{}}};
        {error, Reason} ->
            {stop, {dns_bind_failed, Reason}}
    end.

register_zone_service(ZoneName) ->
    try erlkoenig_zone:register_service(ZoneName, dns, self())
    catch _:_ -> ok
    end.

%% @doc Start with legacy config (single default zone).
start_link(Config) when is_map(Config) ->
    gen_server:start_link(?MODULE, {zone, Config}, []).

handle_call({register, Name, Ip}, _From, #state{tab = Tab, domain = Domain} = State) ->
    FqName = <<Name/binary, ".", Domain/binary>>,
    ets:insert(Tab, [{name, FqName, Ip}, {ip, Ip, FqName}]),
    {reply, ok, State};

handle_call({unregister, Name}, _From, #state{tab = Tab, domain = Domain} = State) ->
    FqName = <<Name/binary, ".", Domain/binary>>,
    case ets:match_object(Tab, {name, FqName, '_'}) of
        [{name, _, Ip}] ->
            ets:delete_object(Tab, {name, FqName, Ip}),
            ets:delete_object(Tab, {ip, Ip, FqName});
        [] ->
            ok
    end,
    {reply, ok, State};

handle_call({lookup, Name}, _From, #state{tab = Tab, domain = Domain} = State) ->
    FqName = case binary:match(Name, <<".">>) of
        nomatch -> <<Name/binary, ".", Domain/binary>>;
        _       -> Name
    end,
    case ets:match_object(Tab, {name, FqName, '_'}) of
        [{name, _, Ip}] -> {reply, {ok, Ip}, State};
        []              -> {reply, not_found, State}
    end;

handle_call(_Req, _From, State) ->
    {reply, {error, unknown}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({udp, Socket, SrcIp, SrcPort, Packet}, State) when Socket =:= State#state.socket ->
    State2 = handle_dns_query(SrcIp, SrcPort, Packet, State),
    {noreply, State2};

handle_info({udp, _UpSock, _Ip, _Port, Reply}, State) ->
    %% Upstream DNS reply — forward back to original client
    State2 = handle_upstream_reply(Reply, State),
    {noreply, State2};

handle_info({upstream_timeout, Id}, #state{pending = Pending} = State) ->
    case maps:take(Id, Pending) of
        {{_SrcIp, _SrcPort, UpSock, _TRef}, Pending2} ->
            _ = gen_udp:close(UpSock),
            {noreply, State#state{pending = Pending2}};
        error ->
            {noreply, State}
    end;

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{socket = Socket, pending = Pending}) ->
    maps:foreach(fun(_Id, {_Ip, _Port, UpSock, TRef}) ->
        _ = erlang:cancel_timer(TRef),
        _ = gen_udp:close(UpSock)
    end, Pending),
    case Socket of
        undefined -> ok;
        _         -> gen_udp:close(Socket)
    end.

%% =================================================================
%% DNS Query Handling
%% =================================================================

-spec handle_dns_query(inet:ip_address(), inet:port_number(), binary(), #state{}) -> #state{}.
handle_dns_query(SrcIp, SrcPort, Packet, State) ->
    case decode_query(Packet) of
        {ok, Id, Name, QType} ->
            case is_internal_name(Name, State#state.domain) of
                true ->
                    Reply = resolve_internal(Id, Name, QType, Packet, State),
                    _ = gen_udp:send(State#state.socket, SrcIp, SrcPort, Reply),
                    State;
                false ->
                    forward_upstream(Id, SrcIp, SrcPort, Packet, State)
            end;
        {error, _} ->
            State
    end.

-spec resolve_internal(non_neg_integer(), binary(), non_neg_integer(), binary(), #state{}) -> binary().
resolve_internal(Id, Name, ?TYPE_A, Packet, #state{tab = Tab, ttl = TTL}) ->
    case ets:match_object(Tab, {name, Name, '_'}) of
        [{name, _, {A, B, C, D}}] ->
            encode_a_reply(Id, Packet, Name, A, B, C, D, TTL);
        [] ->
            encode_nxdomain(Id, Packet)
    end;
resolve_internal(Id, Name, ?TYPE_PTR, Packet, #state{tab = Tab}) ->
    case ptr_to_ip(Name) of
        {ok, Ip} ->
            case ets:match_object(Tab, {ip, Ip, '_'}) of
                [{ip, _, PtrName}] ->
                    encode_ptr_reply(Id, Packet, PtrName);
                [] ->
                    encode_nxdomain(Id, Packet)
            end;
        error ->
            encode_nxdomain(Id, Packet)
    end;
resolve_internal(Id, _Name, _QType, Packet, _State) ->
    encode_nxdomain(Id, Packet).

-spec forward_upstream(non_neg_integer(), inet:ip_address(), inet:port_number(),
                       binary(), #state{}) -> #state{}.
forward_upstream(Id, SrcIp, SrcPort, Packet, State) ->
    #state{upstream = Upstream, pending = Pending} = State,
    case gen_udp:open(0, [binary, {active, true}]) of
        {ok, UpSock} ->
            _ = gen_udp:send(UpSock, Upstream, ?DNS_PORT, Packet),
            TRef = erlang:send_after(?UPSTREAM_TIMEOUT, self(), {upstream_timeout, Id}),
            Pending2 = Pending#{Id => {SrcIp, SrcPort, UpSock, TRef}},
            State#state{pending = Pending2};
        {error, _} ->
            State
    end.

-spec handle_upstream_reply(binary(), #state{}) -> #state{}.
handle_upstream_reply(Reply, State) ->
    case Reply of
        <<Id:16, _/binary>> ->
            case maps:take(Id, State#state.pending) of
                {{SrcIp, SrcPort, UpSock, TRef}, Pending2} ->
                    _ = erlang:cancel_timer(TRef),
                    _ = gen_udp:send(State#state.socket, SrcIp, SrcPort, Reply),
                    _ = gen_udp:close(UpSock),
                    State#state{pending = Pending2};
                error ->
                    State
            end;
        _ ->
            State
    end.

%% =================================================================
%% DNS Codec
%% =================================================================

-spec decode_query(binary()) -> {ok, non_neg_integer(), binary(), non_neg_integer()} | {error, term()}.
decode_query(<<Id:16, Flags:16, QdCount:16, _AnCount:16,
               _NsCount:16, _ArCount:16, Rest/binary>>) ->
    IsQuery = (Flags band 16#8000) =:= 0,
    case IsQuery andalso QdCount >= 1 of
        true ->
            case decode_name(Rest, <<Id:16, Flags:16, QdCount:16,
                                     0:16, 0:16, 0:16, Rest/binary>>) of
                {ok, Name, <<QType:16, ?CLASS_IN:16, _/binary>>} ->
                    {ok, Id, Name, QType};
                {ok, _Name, _Rest2} ->
                    {error, unsupported_class};
                {error, Reason} ->
                    {error, Reason}
            end;
        false ->
            {error, not_a_query}
    end;
decode_query(_) ->
    {error, too_short}.

-spec decode_name(binary(), binary()) -> {ok, binary(), binary()} | {error, term()}.
decode_name(Bin, FullPacket) ->
    decode_name(Bin, FullPacket, []).

decode_name(<<0, Rest/binary>>, _Packet, Acc) ->
    Name = lists:join(<<".">>, lists:reverse(Acc)),
    {ok, iolist_to_binary(Name), Rest};
decode_name(<<3:2, Offset:14, Rest/binary>>, Packet, Acc) ->
    %% Pointer (compression)
    case Packet of
        _ when byte_size(Packet) > Offset ->
            <<_:Offset/binary, Pointed/binary>> = Packet,
            case decode_name(Pointed, Packet, Acc) of
                {ok, Name, _} -> {ok, Name, Rest};
                Error         -> Error
            end;
        _ ->
            {error, bad_pointer}
    end;
decode_name(<<Len, Label:Len/binary, Rest/binary>>, Packet, Acc) when Len > 0, Len =< 63 ->
    decode_name(Rest, Packet, [string:lowercase(Label) | Acc]);
decode_name(_, _, _) ->
    {error, bad_name}.

-spec encode_name(binary()) -> binary().
encode_name(Name) ->
    Labels = binary:split(Name, <<".">>, [global]),
    encode_labels(Labels).

-spec encode_labels([binary()]) -> binary().
encode_labels([]) ->
    <<0>>;
encode_labels([<<>> | Rest]) ->
    encode_labels(Rest);
encode_labels([Label | Rest]) ->
    Len = byte_size(Label),
    <<Len, Label/binary, (encode_labels(Rest))/binary>>.

-spec encode_a_reply(non_neg_integer(), binary(), binary(),
                     byte(), byte(), byte(), byte(), non_neg_integer()) -> binary().
encode_a_reply(Id, QueryPacket, _Name, A, B, C, D, TTL) ->
    %% Extract question section from query
    <<_:16, _:16, _QdCount:16, _:48, QSection/binary>> = QueryPacket,
    {ok, _QName, <<_QType:16, _QClass:16, _/binary>> = AfterName} =
        decode_name(QSection, QueryPacket),
    QSectionLen = byte_size(QSection) - byte_size(AfterName) + 4,
    <<Question:QSectionLen/binary, _/binary>> = QSection,

    %% Header: response, authoritative, no recursion available
    Flags = 16#8400,
    Header = <<Id:16, Flags:16, 1:16, 1:16, 0:16, 0:16>>,

    %% Answer: name pointer to question, type A, class IN
    Answer = <<16#C0, 12,                  %% pointer to name at offset 12
               ?TYPE_A:16, ?CLASS_IN:16,
               TTL:32,
               4:16,                       %% rdlength
               A, B, C, D>>,

    <<Header/binary, Question/binary, Answer/binary>>.

-spec encode_nxdomain(non_neg_integer(), binary()) -> binary().
encode_nxdomain(Id, QueryPacket) ->
    <<_:16, _:16, _QdCount:16, _:48, QSection/binary>> = QueryPacket,
    {ok, _QName, <<_QType:16, _QClass:16, _/binary>> = AfterName} =
        decode_name(QSection, QueryPacket),
    QSectionLen = byte_size(QSection) - byte_size(AfterName) + 4,
    <<Question:QSectionLen/binary, _/binary>> = QSection,

    Flags = 16#8403,  %% response + authoritative + NXDOMAIN
    Header = <<Id:16, Flags:16, 1:16, 0:16, 0:16, 0:16>>,
    <<Header/binary, Question/binary>>.

-spec encode_ptr_reply(non_neg_integer(), binary(), binary()) -> binary().
encode_ptr_reply(Id, QueryPacket, PtrName) ->
    <<_:16, _:16, _QdCount:16, _:48, QSection/binary>> = QueryPacket,
    {ok, _QName, <<_QType:16, _QClass:16, _/binary>> = AfterName} =
        decode_name(QSection, QueryPacket),
    QSectionLen = byte_size(QSection) - byte_size(AfterName) + 4,
    <<Question:QSectionLen/binary, _/binary>> = QSection,

    Flags = 16#8400,
    Header = <<Id:16, Flags:16, 1:16, 1:16, 0:16, 0:16>>,
    RData = encode_name(PtrName),
    RDLen = byte_size(RData),
    Answer = <<16#C0, 12,
               ?TYPE_PTR:16, ?CLASS_IN:16,
               5:32,          %% TTL
               RDLen:16,
               RData/binary>>,
    <<Header/binary, Question/binary, Answer/binary>>.

%% =================================================================
%% Helpers
%% =================================================================

-spec is_internal_name(binary(), binary()) -> boolean().
is_internal_name(Name, Domain) ->
    Suffix = <<".", Domain/binary>>,
    case binary:longest_common_suffix([Name, Suffix]) of
        Len when Len =:= byte_size(Suffix) -> true;
        _ -> Name =:= Domain
    end.

-spec ptr_to_ip(binary()) -> {ok, inet:ip4_address()} | error.
ptr_to_ip(Name) ->
    case binary:split(Name, <<".in-addr.arpa">>) of
        [Reversed, <<>>] ->
            Parts = binary:split(Reversed, <<".">>, [global]),
            case [binary_to_integer(P) || P <- lists:reverse(Parts)] of
                [A, B, C, D] when A >= 0, A =< 255,
                                  B >= 0, B =< 255,
                                  C >= 0, C =< 255,
                                  D >= 0, D =< 255 ->
                    {ok, {A, B, C, D}};
                _ -> error
            end;
        _ -> error
    end.
