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

-module(erlkoenig_netlink).
-moduledoc """
Low-level Netlink protocol for Erlang.

This module speaks the Linux Netlink protocol directly, using
Erlang's socket module with AF_NETLINK (integer 16).

Why not shell out to ip(8)?
  - No fork/exec overhead
  - Proper error handling (not string parsing)
  - Composable from Erlang

Why not a NIF?
  - socket:open(16, raw, 0) works since OTP 22
  - Erlang binary pattern matching is ideal for netlink parsing
  - No C dependency for networking code

Netlink basics:
  Every message has a 16-byte header (nlmsghdr), followed by
  a type-specific struct (ifinfomsg, ifaddrmsg, rtmsg), followed
  by TLV attributes (NLA = netlink attribute).

  All integers are NATIVE endian (little-endian on x86/ARM).
  This is a kernel ABI that has not changed since Linux 2.6.

Reference: man 7 netlink, man 7 rtnetlink
""".

-export([open/0,
         close/1,
         request/2]).

%% Message builders
-export([msg_create_ipvlan/5,
         msg_set_netns_by_pid/3,
         msg_set_up/2,
         msg_add_addr/4,
         msg_add_default_route/2,
         msg_delete_link/2,
         msg_get_link/2]).

%% Response parsing
-export([recv_ifindex/1]).

%% Helpers
-export([next_seq/0]).

%%%===================================================================
%%% Netlink Constants
%%%
%%% These come from linux/netlink.h, linux/rtnetlink.h, linux/if_link.h.
%%% They have been stable since Linux 2.6 (2003).
%%%===================================================================

%% Address families
-define(AF_NETLINK,    16).
-define(AF_INET,        2).

%% Netlink protocols
-define(NETLINK_ROUTE,  0).

%% Message types (rtnetlink)
-define(RTM_NEWLINK,   16).
-define(RTM_DELLINK,   17).
-define(RTM_GETLINK,   18).
-define(RTM_NEWADDR,   20).
-define(RTM_NEWROUTE,  24).

%% Netlink message types
-define(NLMSG_ERROR,    2).
-define(NLMSG_DONE,     3).

%% Request flags
-define(NLM_F_REQUEST,  16#0001).
-define(NLM_F_ACK,      16#0004).
-define(NLM_F_CREATE,   16#0400).
-define(NLM_F_EXCL,     16#0200).

%% Interface flags (from linux/if.h)
-define(IFF_UP,         16#0001).

%% IFLA attribute types (from linux/if_link.h)
-define(IFLA_IFNAME,       3).
-define(IFLA_LINK,         5).
-define(IFLA_MASTER,      10).
-define(IFLA_LINKINFO,    18).
-define(IFLA_NET_NS_PID,  19).

%% IFLA_LINKINFO nested attributes
-define(IFLA_INFO_KIND,    1).
-define(IFLA_INFO_DATA,    2).

%% ipvlan-specific (from linux/if_link.h, IFLA_IPVLAN_* offsets inside INFO_DATA)
-define(IFLA_IPVLAN_MODE,  1).
-define(IPVLAN_MODE_L2,    0).
-define(IPVLAN_MODE_L3,    1).
-define(IPVLAN_MODE_L3S,   2).

%% IFA attribute types (from linux/if_addr.h)
-define(IFA_ADDRESS,       1).
-define(IFA_LOCAL,         2).

%% Route attribute types (from linux/rtnetlink.h)
-define(RTA_GATEWAY,       5).

%% Route table/protocol/scope/type constants
-define(RT_TABLE_MAIN,   254).
-define(RTPROT_BOOT,       3).
-define(RT_SCOPE_UNIVERSE, 0).
-define(RTN_UNICAST,       1).

%%%===================================================================
%%% Socket Operations
%%%===================================================================

-doc """
Open a netlink route socket.

AF_NETLINK (16) is passed as integer because Erlang's socket
module doesn't have a named atom for it. This works since OTP 22.
""".
-spec open() -> {ok, socket:socket()} | {error, term()}.
open() ->
    socket:open(?AF_NETLINK, raw, ?NETLINK_ROUTE).

-doc "Close a netlink socket.".
-spec close(socket:socket()) -> ok.
close(Sock) ->
    socket:close(Sock).

-doc """
Send a netlink message and wait for the kernel's ACK.

Every netlink message with NLM_F_ACK set will receive an
NLMSG_ERROR response. Error code 0 means success.

For RTM_GETLINK, the response is a RTM_NEWLINK message
(not NLMSG_ERROR), so use recv_response/1 instead.
""".
-spec request(socket:socket(), iodata()) -> ok | {error, term()}.
request(Sock, Msg) ->
    case socket:send(Sock, Msg) of
        ok    -> recv_ack(Sock);
        Error -> Error
    end.

%%%===================================================================
%%% Message Builders
%%%
%%% Each function builds a complete netlink message (header + payload).
%%% The caller sends it with request/2 or socket:send/2.
%%%
%%% All messages follow the same structure:
%%%
%%%   +-- nlmsghdr (16 bytes) ----+
%%%   | len | type | flags | seq  |
%%%   +---------------------------+
%%%   +-- type-specific struct ---+
%%%   | ifinfomsg / ifaddrmsg ... |
%%%   +---------------------------+
%%%   +-- NLA attributes ---------+
%%%   | type | len | data | pad   |
%%%   +---------------------------+
%%%===================================================================

-doc """
Create an IPVLAN slave attached to a parent device.

  RTM_NEWLINK + IFLA_IFNAME + IFLA_LINK(parent)
              + IFLA_LINKINFO{KIND="ipvlan", DATA{IPVLAN_MODE}}
              + optional IFLA_NET_NS_PID

SlaveName:      name for the new interface (e.g. <<"ipv.echo">>)
ParentIfindex:  ifindex of the parent device (e.g. eth0)
Mode:           l2 | l3 | l3s (L3S = per-slave conntrack/netfilter)
NetnsPid:       OS PID whose netns to create the slave in,
                or `undefined` to create in the current netns.

When NetnsPid is set, the kernel creates the slave directly in
the target network namespace — no separate move needed.
""".
-spec msg_create_ipvlan(integer(), binary(), integer(),
                        l2 | l3 | l3s, non_neg_integer() | undefined) -> binary().
msg_create_ipvlan(Seq, SlaveName, ParentIfindex, Mode, NetnsPid) ->
    ModeInt = case Mode of
        l2  -> ?IPVLAN_MODE_L2;
        l3  -> ?IPVLAN_MODE_L3;
        l3s -> ?IPVLAN_MODE_L3S
    end,
    Attrs = [
        nla(?IFLA_IFNAME, nul_terminate(SlaveName)),
        nla(?IFLA_LINK,   <<ParentIfindex:32/native>>),
        nla(?IFLA_LINKINFO, [
            nla(?IFLA_INFO_KIND, <<"ipvlan">>),
            nla(?IFLA_INFO_DATA, [
                nla(?IFLA_IPVLAN_MODE, <<ModeInt:16/native>>)
            ])
        ])
    ] ++ netns_attr(NetnsPid),
    build_link_msg(?RTM_NEWLINK, create_flags(), Seq, _Ifindex = 0,
                   _IfFlags = 0, _IfChange = 0, Attrs).

netns_attr(undefined) -> [];
netns_attr(Pid) when is_integer(Pid) ->
    [nla(?IFLA_NET_NS_PID, <<Pid:32/native>>)].

-doc """
Move an interface into another network namespace.

  RTM_NEWLINK + IFLA_NET_NS_PID

IfIndex: index of the interface to move (from msg_get_link).
Pid: OS PID of the target process (not Erlang pid).
""".
-spec msg_set_netns_by_pid(integer(), integer(), non_neg_integer()) -> binary().
msg_set_netns_by_pid(Seq, IfIndex, Pid) ->
    Attrs = [
        nla(?IFLA_NET_NS_PID, <<Pid:32/native>>)
    ],
    build_link_msg(?RTM_NEWLINK, ack_flags(), Seq, IfIndex,
                   _IfFlags = 0, _IfChange = 0, Attrs).

-doc """
Set an interface UP.

  RTM_NEWLINK with ifi_flags=IFF_UP, ifi_change=IFF_UP

ifi_change is a bitmask that tells the kernel which flags to modify.
Setting both flags and change to IFF_UP means: "set UP, don't touch
anything else".
""".
-spec msg_set_up(integer(), integer()) -> binary().
msg_set_up(Seq, IfIndex) ->
    build_link_msg(?RTM_NEWLINK, ack_flags(), Seq, IfIndex,
                   _IfFlags = ?IFF_UP, _IfChange = ?IFF_UP, []).

-doc """
Add an IPv4 address to an interface.

  RTM_NEWADDR + IFA_LOCAL + IFA_ADDRESS

Ip: {A, B, C, D} tuple.
Prefixlen: subnet mask as prefix length (e.g. 24 for /24).
""".
-spec msg_add_addr(integer(), integer(), tuple(), integer()) -> binary().
msg_add_addr(Seq, IfIndex, {A, B, C, D}, Prefixlen) ->
    AddrBin = <<A:8, B:8, C:8, D:8>>,

    %% ifaddrmsg: family(1), prefixlen(1), flags(1), scope(1), index(4)
    Ifaddr = <<(?AF_INET):8, Prefixlen:8, 0:8, 0:8, IfIndex:32/native>>,

    LocalAttr = nla(?IFA_LOCAL, AddrBin),
    AddrAttr = nla(?IFA_ADDRESS, AddrBin),

    Payload = iolist_to_binary([Ifaddr, LocalAttr, AddrAttr]),
    Len = 16 + byte_size(Payload),
    Flags = create_flags(),
    <<Len:32/native, ?RTM_NEWADDR:16/native, Flags:16/native,
      Seq:32/native, 0:32/native, Payload/binary>>.

-doc """
Add a default route (0.0.0.0/0) via a gateway.

  RTM_NEWROUTE + RTA_GATEWAY
""".
-spec msg_add_default_route(integer(), tuple()) -> binary().
msg_add_default_route(Seq, {A, B, C, D}) ->
    %% rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type, flags
    Rtmsg = <<(?AF_INET):8,
              0:8,                       %% dst_len=0 means default route
              0:8,                       %% src_len
              0:8,                       %% tos
              ?RT_TABLE_MAIN:8,
              ?RTPROT_BOOT:8,
              ?RT_SCOPE_UNIVERSE:8,
              ?RTN_UNICAST:8,
              0:32/native>>,             %% rtm_flags

    GwAttr = nla(?RTA_GATEWAY, <<A:8, B:8, C:8, D:8>>),
    Payload = iolist_to_binary([Rtmsg, GwAttr]),
    Len = 16 + byte_size(Payload),
    Flags = create_flags(),
    <<Len:32/native, ?RTM_NEWROUTE:16/native, Flags:16/native,
      Seq:32/native, 0:32/native, Payload/binary>>.

-doc """
Delete a network interface.

  RTM_DELLINK
""".
-spec msg_delete_link(integer(), integer()) -> binary().
msg_delete_link(Seq, IfIndex) ->
    build_link_msg(?RTM_DELLINK, ack_flags(), Seq, IfIndex,
                   _IfFlags = 0, _IfChange = 0, []).

-doc """
Request information about an interface by name.

  RTM_GETLINK + IFLA_IFNAME

Response is a RTM_NEWLINK message (not NLMSG_ERROR).
Parse with parse_newlink/1.
""".
-spec msg_get_link(integer(), binary()) -> binary().
msg_get_link(Seq, Name) ->
    Attrs = [
        nla(?IFLA_IFNAME, nul_terminate(Name))
    ],
    %% No NLM_F_ACK for GET requests. The kernel responds with
    %% RTM_NEWLINK directly (or NLMSG_ERROR on failure).
    build_link_msg(?RTM_GETLINK, ?NLM_F_REQUEST, Seq, _Ifindex = 0,
                   _IfFlags = 0, _IfChange = 0, Attrs).

%%%===================================================================
%%% Response Parsing
%%%===================================================================

-doc """
Receive and parse an ACK response.

Netlink ACK = NLMSG_ERROR with error code 0.
Any other error code is a failure (negated errno).
""".
-spec recv_ack(socket:socket()) -> ok | {error, term()}.
recv_ack(Sock) ->
    case socket:recv(Sock, 0, 5000) of
        {ok, Data} -> parse_ack(Data);
        Error      -> Error
    end.

-doc "Receive a RTM_NEWLINK response and extract the interface index.".
-spec recv_ifindex(socket:socket()) -> {ok, integer()} | {error, term()}.
recv_ifindex(Sock) ->
    case socket:recv(Sock, 0, 5000) of
        {ok, Data} -> parse_newlink_ifindex(Data);
        Error      -> Error
    end.

%%%===================================================================
%%% Internal: Parsing
%%%===================================================================

-spec parse_ack(binary()) -> ok | {ok, integer()} | {error, term()}.
parse_ack(<<_Len:32/native, ?NLMSG_ERROR:16/native, _Flags:16/native,
            _Seq:32/native, _Pid:32/native,
            0:32/native-signed, _Rest/binary>>) ->
    ok;
parse_ack(<<_Len:32/native, ?NLMSG_ERROR:16/native, _Flags:16/native,
            _Seq:32/native, _Pid:32/native,
            Errno:32/native-signed, _Rest/binary>>) ->
    {error, {netlink_error, -Errno}};
parse_ack(<<_Len:32/native, ?RTM_NEWLINK:16/native, _/binary>> = Data) ->
    %% RTM_GETLINK returns RTM_NEWLINK, not NLMSG_ERROR.
    %% This happens when the caller expected an ACK but got data.
    parse_newlink_ifindex(Data);
parse_ack(<<_Len:32/native, Type:16/native, _/binary>>) ->
    {error, {unexpected_type, Type}};
parse_ack(<<>>) ->
    {error, empty_response};
parse_ack(_) ->
    {error, malformed}.

-spec parse_newlink_ifindex(binary()) -> {ok, integer()} | {error, term()}.
parse_newlink_ifindex(<<_Len:32/native, ?RTM_NEWLINK:16/native,
                        _Flags:16/native, _Seq:32/native, _Pid:32/native,
                        _Family:8, _Pad:8, _Type:16/native,
                        Index:32/native-signed,
                        _IfFlags:32/native, _Change:32/native,
                        _Attrs/binary>>) ->
    {ok, Index};
parse_newlink_ifindex(<<_Len:32/native, ?NLMSG_ERROR:16/native,
                        _Flags:16/native, _Seq:32/native, _Pid:32/native,
                        Errno:32/native-signed, _Rest/binary>>) ->
    {error, {netlink_error, -Errno}};
parse_newlink_ifindex(_) ->
    {error, not_a_newlink}.

%%%===================================================================
%%% Internal: Message Building
%%%===================================================================

-doc """
Build a RTM_*LINK message with ifinfomsg header.

All link operations (create, delete, modify) use the same structure:
  nlmsghdr + ifinfomsg + NLA attributes
""".
-spec build_link_msg(integer(), integer(), integer(), integer(),
                     integer(), integer(), [binary()]) -> binary().
build_link_msg(Type, Flags, Seq, IfIndex, IfFlags, IfChange, Attrs) ->
    Ifinfo = ifinfomsg(IfIndex, IfFlags, IfChange),
    AttrsBin = iolist_to_binary(Attrs),
    Payload = <<Ifinfo/binary, AttrsBin/binary>>,
    Len = 16 + byte_size(Payload),
    <<Len:32/native, Type:16/native, Flags:16/native,
      Seq:32/native, 0:32/native,
      Payload/binary>>.

-doc """
Build an ifinfomsg struct (16 bytes).

struct ifinfomsg {
    unsigned char  ifi_family;    -- AF_UNSPEC (0) for most ops
    unsigned char  __ifi_pad;
    unsigned short ifi_type;      -- ARPHRD_* (0 = unspecified)
    int            ifi_index;     -- interface index (0 = new)
    unsigned int   ifi_flags;     -- IFF_UP, IFF_RUNNING, etc.
    unsigned int   ifi_change;    -- bitmask of flags to change
};
""".
-spec ifinfomsg(integer(), integer(), integer()) -> binary().
ifinfomsg(Index, Flags, Change) ->
    <<0:8,                       %% ifi_family  (AF_UNSPEC)
      0:8,                       %% padding
      0:16/native,               %% ifi_type    (unspecified)
      Index:32/native-signed,    %% ifi_index
      Flags:32/native,           %% ifi_flags
      Change:32/native>>.        %% ifi_change

-doc """
Build a netlink attribute (NLA).

struct nlattr {
    __u16 nla_len;   -- length including header (4 bytes)
    __u16 nla_type;  -- attribute type
    char  data[];    -- payload, padded to 4-byte alignment
};

Data can be binary or iolist (for nested attributes).
""".
-spec nla(integer(), binary() | iolist()) -> binary().
nla(Type, Data) when is_binary(Data) ->
    Len = 4 + byte_size(Data),
    Pad = nla_padding(Len),
    <<Len:16/native, Type:16/native, Data/binary, 0:(Pad * 8)>>;
nla(Type, DataList) when is_list(DataList) ->
    DataBin = iolist_to_binary(DataList),
    nla(Type, DataBin).

-spec nla_padding(non_neg_integer()) -> 0..3.
nla_padding(Len) ->
    (4 - (Len rem 4)) rem 4.

-spec nul_terminate(binary()) -> binary().
nul_terminate(Bin) ->
    <<Bin/binary, 0>>.

-spec create_flags() -> integer().
create_flags() -> ?NLM_F_REQUEST bor ?NLM_F_ACK bor ?NLM_F_CREATE bor ?NLM_F_EXCL.

-spec ack_flags() -> integer().
ack_flags()    -> ?NLM_F_REQUEST bor ?NLM_F_ACK.

-doc """
Generate a unique sequence number for netlink messages.

The kernel echoes the sequence number in responses, which lets
us match requests to responses (important when multiple
requests are in flight).
""".
next_seq() ->
    try persistent_term:get(erlkoenig_nl_seq) of
        N ->
            persistent_term:put(erlkoenig_nl_seq, N + 1),
            N + 1
    catch
        error:badarg ->
            persistent_term:put(erlkoenig_nl_seq, 1),
            1
    end.
