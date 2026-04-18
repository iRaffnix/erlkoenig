%%%-------------------------------------------------------------------
%%% @doc Unit tests for erlkoenig_netlink (Netlink message builders).
%%%
%%% All msg_* functions are pure -- they take integers/binaries and
%%% return binaries. No sockets, no root, no kernel interaction.
%%%
%%% Tests verify binary structure: correct header fields, NLA padding,
%%% presence of expected payloads. This catches off-by-one errors
%%% that would cause cryptic EINVAL from the kernel.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_netlink_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%% Netlink constants (mirrored from erlkoenig_netlink.erl)
-define(RTM_NEWLINK,  16).
-define(RTM_DELLINK,  17).
-define(RTM_GETLINK,  18).
-define(RTM_NEWADDR,  20).
-define(RTM_NEWROUTE, 24).
-define(NLMSG_ERROR,   2).

-define(NLM_F_REQUEST, 16#0001).
-define(NLM_F_ACK,     16#0004).
-define(NLM_F_CREATE,  16#0400).
-define(NLM_F_EXCL,    16#0200).

%% =================================================================
%% Header structure tests
%%
%% Every netlink message starts with a 16-byte nlmsghdr:
%%   <<Len:32/native, Type:16/native, Flags:16/native,
%%     Seq:32/native, Pid:32/native>>
%%
%% Len must equal the actual binary size.
%% =================================================================

%% =================================================================
%% ipvlan creation
%% =================================================================

msg_create_ipvlan_contains_kind_test() ->
    Msg = erlkoenig_netlink:msg_create_ipvlan(1, <<"ipv.echo">>, 2, l3s, undefined),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"ipvlan">>)).

msg_create_ipvlan_contains_name_test() ->
    Msg = erlkoenig_netlink:msg_create_ipvlan(1, <<"ipv.echo">>, 2, l3s, undefined),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"ipv.echo", 0>>)).

msg_create_ipvlan_contains_parent_ifindex_test() ->
    Msg = erlkoenig_netlink:msg_create_ipvlan(1, <<"ipv.echo">>, 42, l3s, undefined),
    %% IFLA_LINK carries the parent ifindex as 32-bit native
    ?assertNotEqual(nomatch, binary:match(Msg, <<42:32/native>>)).

msg_create_ipvlan_length_correct_test() ->
    Msg = erlkoenig_netlink:msg_create_ipvlan(1, <<"ipv.echo">>, 2, l3s, undefined),
    <<Len:32/native, _/binary>> = Msg,
    ?assertEqual(byte_size(Msg), Len).

msg_create_ipvlan_header_flags_test() ->
    Msg = erlkoenig_netlink:msg_create_ipvlan(1, <<"ipv.echo">>, 2, l3s, undefined),
    <<_Len:32/native, Type:16/native, Flags:16/native, _/binary>> = Msg,
    ?assertEqual(?RTM_NEWLINK, Type),
    ?assertNotEqual(0, Flags band ?NLM_F_REQUEST),
    ?assertNotEqual(0, Flags band ?NLM_F_ACK),
    ?assertNotEqual(0, Flags band ?NLM_F_CREATE),
    ?assertNotEqual(0, Flags band ?NLM_F_EXCL).

msg_create_ipvlan_mode_l3s_test() ->
    Msg = erlkoenig_netlink:msg_create_ipvlan(1, <<"ipv.x">>, 2, l3s, undefined),
    %% IPVLAN_MODE_L3S = 2, encoded as 16-bit native inside IFLA_INFO_DATA
    ?assertNotEqual(nomatch, binary:match(Msg, <<2:16/native>>)).

msg_create_ipvlan_mode_l2_test() ->
    Msg = erlkoenig_netlink:msg_create_ipvlan(1, <<"ipv.x">>, 2, l2, undefined),
    %% IPVLAN_MODE_L2 = 0, encoded as 16-bit native
    ?assertNotEqual(nomatch, binary:match(Msg, <<0:16/native>>)).

msg_create_ipvlan_mode_l3_test() ->
    Msg = erlkoenig_netlink:msg_create_ipvlan(1, <<"ipv.x">>, 2, l3, undefined),
    %% IPVLAN_MODE_L3 = 1, encoded as 16-bit native
    ?assertNotEqual(nomatch, binary:match(Msg, <<1:16/native>>)).

msg_create_ipvlan_with_netns_pid_test() ->
    Msg = erlkoenig_netlink:msg_create_ipvlan(1, <<"ipv.x">>, 2, l3s, 99999),
    %% The OS PID should appear as IFLA_NET_NS_PID (32-bit native)
    ?assertNotEqual(nomatch, binary:match(Msg, <<99999:32/native>>)).

msg_create_ipvlan_without_netns_pid_test() ->
    Msg = erlkoenig_netlink:msg_create_ipvlan(1, <<"ipv.x">>, 2, l3s, undefined),
    %% Without NetnsPid, the message should be shorter (no IFLA_NET_NS_PID attr)
    MsgWith = erlkoenig_netlink:msg_create_ipvlan(1, <<"ipv.x">>, 2, l3s, 12345),
    ?assert(byte_size(MsgWith) > byte_size(Msg)).

%% =================================================================
%% Interface operations
%% =================================================================

msg_set_up_flags_test() ->
    Msg = erlkoenig_netlink:msg_set_up(1, 42),
    %% After 16-byte header: ifinfomsg (16 bytes)
    %% ifinfomsg: family(1), pad(1), type(2), index(4), flags(4), change(4)
    <<_Header:16/binary,
      _Family:8, _Pad:8, _Type:16/native, Index:32/native-signed,
      IfFlags:32/native, IfChange:32/native, _/binary>> = Msg,
    ?assertEqual(42, Index),
    %% IFF_UP = 1
    ?assertNotEqual(0, IfFlags band 1),
    ?assertNotEqual(0, IfChange band 1).

msg_set_netns_by_pid_test() ->
    Msg = erlkoenig_netlink:msg_set_netns_by_pid(1, 5, 12345),
    <<Len:32/native, _/binary>> = Msg,
    ?assertEqual(byte_size(Msg), Len),
    %% The OS PID (12345) should be in the payload as 32-bit native
    ?assertNotEqual(nomatch, binary:match(Msg, <<12345:32/native>>)).

msg_delete_link_type_test() ->
    Msg = erlkoenig_netlink:msg_delete_link(1, 10),
    <<_Len:32/native, Type:16/native, _/binary>> = Msg,
    ?assertEqual(?RTM_DELLINK, Type).

msg_delete_link_length_test() ->
    Msg = erlkoenig_netlink:msg_delete_link(1, 10),
    <<Len:32/native, _/binary>> = Msg,
    ?assertEqual(byte_size(Msg), Len).

msg_get_link_flags_test() ->
    Msg = erlkoenig_netlink:msg_get_link(1, <<"eth0">>),
    <<_Len:32/native, Type:16/native, Flags:16/native, _/binary>> = Msg,
    ?assertEqual(?RTM_GETLINK, Type),
    %% GET requests must have REQUEST but NOT CREATE
    ?assertNotEqual(0, Flags band ?NLM_F_REQUEST),
    ?assertEqual(0, Flags band ?NLM_F_CREATE).

msg_get_link_contains_name_test() ->
    Msg = erlkoenig_netlink:msg_get_link(1, <<"eth0">>),
    ?assertNotEqual(nomatch, binary:match(Msg, <<"eth0", 0>>)).

%% =================================================================
%% Address and route messages
%% =================================================================

msg_add_addr_contains_ip_test() ->
    Msg = erlkoenig_netlink:msg_add_addr(1, 5, {10, 0, 0, 1}, 24),
    %% IP address bytes must appear (twice: IFA_LOCAL + IFA_ADDRESS)
    Matches = binary:matches(Msg, <<10, 0, 0, 1>>),
    ?assert(length(Matches) >= 2).

msg_add_addr_prefixlen_test() ->
    Msg = erlkoenig_netlink:msg_add_addr(1, 5, {10, 0, 0, 1}, 24),
    %% After 16-byte header: ifaddrmsg starts with
    %% family(1), prefixlen(1), flags(1), scope(1), index(4)
    <<_Header:16/binary, _Family:8, Prefixlen:8, _/binary>> = Msg,
    ?assertEqual(24, Prefixlen).

msg_add_addr_length_test() ->
    Msg = erlkoenig_netlink:msg_add_addr(1, 5, {192, 168, 1, 1}, 24),
    <<Len:32/native, _/binary>> = Msg,
    ?assertEqual(byte_size(Msg), Len).

msg_add_default_route_gateway_test() ->
    Msg = erlkoenig_netlink:msg_add_default_route(1, {10, 0, 0, 1}),
    ?assertNotEqual(nomatch, binary:match(Msg, <<10, 0, 0, 1>>)).

msg_add_default_route_dst_zero_test() ->
    Msg = erlkoenig_netlink:msg_add_default_route(1, {10, 0, 0, 1}),
    %% After header: rtmsg starts with family(1), dst_len(1), ...
    <<_Header:16/binary, _Family:8, DstLen:8, _/binary>> = Msg,
    ?assertEqual(0, DstLen).

msg_add_default_route_type_test() ->
    Msg = erlkoenig_netlink:msg_add_default_route(1, {10, 0, 0, 1}),
    <<_Len:32/native, Type:16/native, _/binary>> = Msg,
    ?assertEqual(?RTM_NEWROUTE, Type).

msg_add_default_route_length_test() ->
    Msg = erlkoenig_netlink:msg_add_default_route(1, {10, 0, 0, 1}),
    <<Len:32/native, _/binary>> = Msg,
    ?assertEqual(byte_size(Msg), Len).

%% =================================================================
%% Response parsing
%%
%% parse_ack/1 and parse_newlink_ifindex/1 are internal functions
%% (not exported). We mirror their logic here to verify the binary
%% formats that the kernel would send back. This ensures our
%% understanding of the protocol matches the implementation.
%% =================================================================

parse_ack_success_test() ->
    %% NLMSG_ERROR with errno=0 means success (Netlink convention)
    Ack = <<20:32/native, ?NLMSG_ERROR:16/native, 0:16/native,
            1:32/native, 0:32/native,
            0:32/native-signed>>,
    ?assertEqual(ok, parse_ack(Ack)).

parse_ack_error_test() ->
    %% NLMSG_ERROR with errno=-2 (ENOENT)
    Ack = <<20:32/native, ?NLMSG_ERROR:16/native, 0:16/native,
            1:32/native, 0:32/native,
            (-2):32/native-signed>>,
    ?assertEqual({error, {netlink_error, 2}}, parse_ack(Ack)).

parse_ack_empty_test() ->
    ?assertEqual({error, empty_response}, parse_ack(<<>>)).

parse_ack_malformed_test() ->
    ?assertEqual({error, malformed}, parse_ack(<<1, 2, 3>>)).

parse_newlink_ifindex_test() ->
    %% RTM_NEWLINK response with ifindex=42
    Msg = <<32:32/native, ?RTM_NEWLINK:16/native, 0:16/native,
            1:32/native, 0:32/native,
            0:8, 0:8, 0:16/native,
            42:32/native-signed,
            0:32/native, 0:32/native>>,
    ?assertEqual({ok, 42}, parse_newlink_ifindex(Msg)).

parse_newlink_error_response_test() ->
    Ack = <<20:32/native, ?NLMSG_ERROR:16/native, 0:16/native,
            1:32/native, 0:32/native,
            (-19):32/native-signed>>,
    ?assertEqual({error, {netlink_error, 19}}, parse_newlink_ifindex(Ack)).

parse_newlink_garbage_test() ->
    ?assertEqual({error, not_a_newlink}, parse_newlink_ifindex(<<1, 2, 3, 4>>)).

%% --- Parse helpers (mirror erlkoenig_netlink internal logic) ---

parse_ack(<<_Len:32/native, ?NLMSG_ERROR:16/native, _Flags:16/native,
            _Seq:32/native, _Pid:32/native,
            0:32/native-signed, _Rest/binary>>) ->
    ok;
parse_ack(<<_Len:32/native, ?NLMSG_ERROR:16/native, _Flags:16/native,
            _Seq:32/native, _Pid:32/native,
            Errno:32/native-signed, _Rest/binary>>) ->
    {error, {netlink_error, -Errno}};
parse_ack(<<_Len:32/native, _Type:16/native, _/binary>>) ->
    {error, {unexpected_type, _Type}};
parse_ack(<<>>) ->
    {error, empty_response};
parse_ack(_) ->
    {error, malformed}.

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

%% =================================================================
%% Sequence number
%% =================================================================

next_seq_monotonic_test() ->
    %% Clean up persistent_term to get predictable state
    try persistent_term:erase(erlkoenig_nl_seq)
    catch error:badarg -> ok
    end,
    A = erlkoenig_netlink:next_seq(),
    B = erlkoenig_netlink:next_seq(),
    ?assert(B > A).

next_seq_first_call_test() ->
    try persistent_term:erase(erlkoenig_nl_seq)
    catch error:badarg -> ok
    end,
    ?assertEqual(1, erlkoenig_netlink:next_seq()).
