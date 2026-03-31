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

-module(erlkoenig_proto).
-moduledoc """
Erlkoenig wire protocol encode/decode.

Transport: Erlang Port with {packet, 4} or Unix Domain Socket.
Wire format: Tag:8 | Version:8 | [TLV Attributes]
TLV: Type:16/big | Len:16/big | Value:Len/binary

The C runtime (erlkoenig_rt) parses all commands as TLV.
Replies from the C runtime use a simpler positional format.
""".

%% Decode
-export([decode/1,
         tag_name/1]).

%% Protocol version
-export([protocol_version/0,
         encode_handshake/0,
         check_handshake_reply/1]).

%% Encode commands (TLV format)
-export([encode_cmd_spawn/1,
         encode_cmd_go/0,
         encode_cmd_kill/1,
         encode_cmd_net_setup/4,
         encode_cmd_write_file/3,
         encode_cmd_query_status/0,
         encode_cmd_stdin/1,
         encode_cmd_resize/2,
         encode_cmd_device_filter/1,
         encode_cmd_device_filter/2,
         encode_cmd_metrics_start/1,
         encode_cmd_metrics_stop/0,
         spawn_flag_pty/0]).

%% Legacy API (delegates to map-based encode_cmd_spawn/1)
-export([encode_cmd_spawn/6,
         encode_cmd_spawn/7,
         encode_cmd_spawn/8,
         encode_cmd_spawn/9,
         encode_cmd_spawn/10,
         encode_cmd_spawn/11,
         encode_volumes/1,
         volume_opts/1]).

%% -- Protocol version ---------------------------------------------

-define(PROTOCOL_VERSION, 1).
-define(NODE_CERT_HASH_LEN, 32).

%% -- Tags ---------------------------------------------------------

-define(TAG_REPLY_OK,            16#01).
-define(TAG_REPLY_ERROR,         16#02).
-define(TAG_REPLY_CONTAINER_PID, 16#03).
-define(TAG_REPLY_READY,         16#04).
-define(TAG_REPLY_EXITED,        16#05).
-define(TAG_REPLY_STATUS,        16#06).
-define(TAG_REPLY_STDOUT,        16#07).
-define(TAG_REPLY_STDERR,        16#08).
-define(TAG_REPLY_METRICS_EVENT, 16#09).

-define(TAG_CMD_SPAWN,           16#10).
-define(TAG_CMD_GO,              16#11).
-define(TAG_CMD_KILL,            16#12).
-define(TAG_CMD_CGROUP_SET,      16#13).
-define(TAG_CMD_QUERY_STATUS,    16#14).
-define(TAG_CMD_NET_SETUP,       16#15).
-define(TAG_CMD_WRITE_FILE,      16#16).
-define(TAG_CMD_STDIN,           16#17).
-define(TAG_CMD_RESIZE,          16#18).
-define(TAG_CMD_DEVICE_FILTER,   16#19).
-define(TAG_CMD_METRICS_START,   16#1A).
-define(TAG_CMD_METRICS_STOP,    16#1B).

%% -- TLV Attribute Types (from erlkoenig_proto.h) -----------------

-define(EK_ATTR_PATH,        1).   %% bytes, required
-define(EK_ATTR_UID,         2).   %% uint32
-define(EK_ATTR_GID,         3).   %% uint32
-define(EK_ATTR_CAPS,        4).   %% uint64
-define(EK_ATTR_ARG,         5).   %% bytes, repeated
-define(EK_ATTR_FLAGS,       6).   %% uint32
-define(EK_ATTR_ENV,         7).   %% bytes "key\0val", repeated
-define(EK_ATTR_ROOTFS_MB,   8).   %% uint32
-define(EK_ATTR_SECCOMP,     9).   %% uint8
-define(EK_ATTR_DNS_IP,      10).  %% uint32
-define(EK_ATTR_VOLUME,      11).  %% bytes, repeated
-define(EK_ATTR_MEMORY_MAX,  12).  %% uint64
-define(EK_ATTR_PIDS_MAX,    13).  %% uint32
-define(EK_ATTR_CPU_WEIGHT,  14).  %% uint32
-define(EK_ATTR_IMAGE_PATH,  15).  %% bytes

%% NET_SETUP attributes (per-command numbering)
-define(EK_ATTR_IFNAME,       1).  %% bytes
-define(EK_ATTR_CONTAINER_IP, 2).  %% uint32
-define(EK_ATTR_GATEWAY_IP,   3).  %% uint32
-define(EK_ATTR_PREFIXLEN,    4).  %% uint8

%% WRITE_FILE attributes
-define(EK_ATTR_FILE_PATH,    1).  %% bytes
-define(EK_ATTR_CONTENT,      2).  %% bytes
-define(EK_ATTR_FILE_MODE,    3).  %% uint16

%% KILL attribute
-define(EK_ATTR_SIGNAL,       1).  %% uint8

-define(SPAWN_FLAG_PTY,       16#01).

-type tag_name() :: reply_ok | reply_error | reply_container_pid
                  | reply_ready | reply_exited | reply_status
                  | reply_stdout | reply_stderr | reply_metrics_event
                  | cmd_spawn | cmd_go | cmd_kill | cmd_cgroup_set
                  | cmd_query_status | cmd_net_setup | cmd_write_file
                  | cmd_stdin | cmd_resize | cmd_device_filter
                  | cmd_metrics_start | cmd_metrics_stop | unknown.

-export_type([tag_name/0]).

-spec tag_name(byte()) -> tag_name().
tag_name(?TAG_REPLY_OK)            -> reply_ok;
tag_name(?TAG_REPLY_ERROR)         -> reply_error;
tag_name(?TAG_REPLY_CONTAINER_PID) -> reply_container_pid;
tag_name(?TAG_REPLY_READY)         -> reply_ready;
tag_name(?TAG_REPLY_EXITED)        -> reply_exited;
tag_name(?TAG_REPLY_STATUS)        -> reply_status;
tag_name(?TAG_REPLY_STDOUT)        -> reply_stdout;
tag_name(?TAG_REPLY_STDERR)        -> reply_stderr;
tag_name(?TAG_REPLY_METRICS_EVENT) -> reply_metrics_event;
tag_name(?TAG_CMD_SPAWN)           -> cmd_spawn;
tag_name(?TAG_CMD_GO)              -> cmd_go;
tag_name(?TAG_CMD_KILL)            -> cmd_kill;
tag_name(?TAG_CMD_CGROUP_SET)      -> cmd_cgroup_set;
tag_name(?TAG_CMD_QUERY_STATUS)    -> cmd_query_status;
tag_name(?TAG_CMD_NET_SETUP)       -> cmd_net_setup;
tag_name(?TAG_CMD_WRITE_FILE)      -> cmd_write_file;
tag_name(?TAG_CMD_STDIN)           -> cmd_stdin;
tag_name(?TAG_CMD_RESIZE)          -> cmd_resize;
tag_name(?TAG_CMD_DEVICE_FILTER)   -> cmd_device_filter;
tag_name(?TAG_CMD_METRICS_START)   -> cmd_metrics_start;
tag_name(?TAG_CMD_METRICS_STOP)    -> cmd_metrics_stop;
tag_name(_)                        -> unknown.

%% =================================================================
%% Protocol handshake
%% =================================================================

-spec protocol_version() -> pos_integer().
protocol_version() -> ?PROTOCOL_VERSION.

-spec encode_handshake() -> binary().
encode_handshake() ->
    <<?PROTOCOL_VERSION:8>>.

-spec check_handshake_reply(binary()) -> ok | {error, term()}.
check_handshake_reply(<<?PROTOCOL_VERSION:8, _Rest/binary>>) ->
    ok;
check_handshake_reply(<<V:8, _/binary>>) when V =:= 2 ->
    %% v2 with node cert hash — accept
    ok;
check_handshake_reply(<<Got:8, _/binary>>) ->
    {error, {protocol_mismatch, ?PROTOCOL_VERSION, Got}};
check_handshake_reply(_) ->
    {error, {protocol_mismatch, ?PROTOCOL_VERSION, unknown}}.

%% =================================================================
%% TLV encoding helpers
%% =================================================================

-spec tlv(non_neg_integer(), binary()) -> binary().
tlv(Type, Value) ->
    <<Type:16/big, (byte_size(Value)):16/big, Value/binary>>.

tlv_u8(Type, Val)  -> tlv(Type, <<Val:8>>).
tlv_u16(Type, Val) -> tlv(Type, <<Val:16/big>>).
tlv_u32(Type, Val) -> tlv(Type, <<Val:32/big>>).
tlv_u64(Type, Val) -> tlv(Type, <<Val:64/big>>).
tlv_str(Type, Bin) -> tlv(Type, Bin).

msg(Tag, Attrs) ->
    Payload = iolist_to_binary(Attrs),
    <<Tag:8, ?PROTOCOL_VERSION:8, Payload/binary>>.

%% =================================================================
%% Encode commands (Erlang -> C) — TLV format
%% =================================================================

-doc """
Encode CMD_SPAWN from a map of options.

Required keys: path (binary)
Optional keys: args, env, uid, gid, seccomp, rootfs_mb, caps_keep,
               dns_ip, flags, volumes, image_path, memory_max,
               pids_max, cpu_weight
""".
-spec encode_cmd_spawn(map()) -> binary().
encode_cmd_spawn(Opts) when is_map(Opts) ->
    Path = maps:get(path, Opts, maps:get(binary, Opts, <<"/app">>)),
    Attrs = [
        tlv_str(?EK_ATTR_PATH, iolist_to_binary(Path))
    ],

    %% Image path (EROFS)
    Attrs1 = case maps:find(image_path, Opts) of
        {ok, Img} when is_binary(Img), byte_size(Img) > 0 ->
            Attrs ++ [tlv_str(?EK_ATTR_IMAGE_PATH, Img)];
        {ok, Img} when is_list(Img) ->
            Attrs ++ [tlv_str(?EK_ATTR_IMAGE_PATH, iolist_to_binary(Img))];
        _ -> Attrs
    end,

    %% UID / GID
    Uid = maps:get(uid, Opts, 65534),
    Gid = maps:get(gid, Opts, 65534),
    Attrs2 = Attrs1 ++ [tlv_u32(?EK_ATTR_UID, Uid), tlv_u32(?EK_ATTR_GID, Gid)],

    %% Seccomp profile
    Seccomp = seccomp_to_int(maps:get(seccomp, Opts, 0)),
    Attrs3 = if Seccomp > 0 -> Attrs2 ++ [tlv_u8(?EK_ATTR_SECCOMP, Seccomp)];
                true -> Attrs2
             end,

    %% Capabilities
    Attrs4 = case maps:get(caps_keep, Opts, 0) of
        0 -> Attrs3;
        Caps -> Attrs3 ++ [tlv_u64(?EK_ATTR_CAPS, Caps)]
    end,

    %% Args (repeated)
    Args = maps:get(args, Opts, []),
    Attrs5 = Attrs4 ++ [tlv_str(?EK_ATTR_ARG, iolist_to_binary(A)) || A <- Args],

    %% Env (each as "key\0val")
    Env = maps:get(env, Opts, []),
    Attrs6 = Attrs5 ++ lists:map(fun({K, V}) ->
        KB = iolist_to_binary(K),
        VB = iolist_to_binary(V),
        tlv_str(?EK_ATTR_ENV, <<KB/binary, 0, VB/binary>>)
    end, Env),

    %% Rootfs size
    Attrs7 = case maps:get(rootfs_mb, Opts, 0) of
        0 -> Attrs6;
        Mb -> Attrs6 ++ [tlv_u32(?EK_ATTR_ROOTFS_MB, Mb)]
    end,

    %% DNS IP
    Attrs8 = case maps:get(dns_ip, Opts, 0) of
        0 -> Attrs7;
        DnsIp -> Attrs7 ++ [tlv_u32(?EK_ATTR_DNS_IP, DnsIp)]
    end,

    %% Flags
    Attrs9 = case maps:get(flags, Opts, 0) of
        0 -> Attrs8;
        Flags -> Attrs8 ++ [tlv_u32(?EK_ATTR_FLAGS, Flags)]
    end,

    %% Memory max
    Attrs10 = case maps:get(memory_max, Opts, 0) of
        0 -> Attrs9;
        Mem -> Attrs9 ++ [tlv_u64(?EK_ATTR_MEMORY_MAX, Mem)]
    end,

    %% PIDs max
    Attrs11 = case maps:get(pids_max, Opts, 0) of
        0 -> Attrs10;
        Pids -> Attrs10 ++ [tlv_u32(?EK_ATTR_PIDS_MAX, Pids)]
    end,

    %% CPU weight
    Attrs12 = case maps:get(cpu_weight, Opts, 0) of
        0 -> Attrs11;
        Cpu -> Attrs11 ++ [tlv_u32(?EK_ATTR_CPU_WEIGHT, Cpu)]
    end,

    %% Volumes (each as TLV: "host_path\0container_path\0opts_u32")
    Volumes = maps:get(volumes, Opts, []),
    Attrs13 = Attrs12 ++ lists:map(fun(#{host := H, container := C} = V) ->
        Opt = maps:get(opts, V, 0),
        HB = iolist_to_binary(H),
        CB = iolist_to_binary(C),
        tlv_str(?EK_ATTR_VOLUME, <<HB/binary, 0, CB/binary, 0, Opt:32/big>>)
    end, Volumes),

    msg(?TAG_CMD_SPAWN, Attrs13).

seccomp_to_int(none)    -> 0;
seccomp_to_int(default) -> 1;
seccomp_to_int(strict)  -> 2;
seccomp_to_int(network) -> 3;
seccomp_to_int(N) when is_integer(N) -> N;
seccomp_to_int(#{profile := P}) -> seccomp_to_int(P);
seccomp_to_int(_) -> 0.

%% =================================================================
%% Legacy encode_cmd_spawn/6..11 — delegate to map-based API
%% =================================================================

encode_cmd_spawn(Path, Args, Env, Uid, Gid, SeccompProfile) ->
    encode_cmd_spawn(#{path => Path, args => Args, env => Env,
                       uid => Uid, gid => Gid, seccomp => SeccompProfile}).

encode_cmd_spawn(Path, Args, Env, Uid, Gid, SeccompProfile, RootfsSizeMB) ->
    encode_cmd_spawn(#{path => Path, args => Args, env => Env,
                       uid => Uid, gid => Gid, seccomp => SeccompProfile,
                       rootfs_mb => RootfsSizeMB}).

encode_cmd_spawn(Path, Args, Env, Uid, Gid, SeccompProfile, RootfsSizeMB, CapsKeep) ->
    encode_cmd_spawn(#{path => Path, args => Args, env => Env,
                       uid => Uid, gid => Gid, seccomp => SeccompProfile,
                       rootfs_mb => RootfsSizeMB, caps_keep => CapsKeep}).

encode_cmd_spawn(Path, Args, Env, Uid, Gid, SeccompProfile, RootfsSizeMB, CapsKeep, DnsIp) ->
    encode_cmd_spawn(#{path => Path, args => Args, env => Env,
                       uid => Uid, gid => Gid, seccomp => SeccompProfile,
                       rootfs_mb => RootfsSizeMB, caps_keep => CapsKeep,
                       dns_ip => DnsIp}).

encode_cmd_spawn(Path, Args, Env, Uid, Gid, SeccompProfile, RootfsSizeMB, CapsKeep, DnsIp, Flags) ->
    encode_cmd_spawn(#{path => Path, args => Args, env => Env,
                       uid => Uid, gid => Gid, seccomp => SeccompProfile,
                       rootfs_mb => RootfsSizeMB, caps_keep => CapsKeep,
                       dns_ip => DnsIp, flags => Flags}).

encode_cmd_spawn(Path, Args, Env, Uid, Gid, SeccompProfile, RootfsSizeMB, CapsKeep, DnsIp, Flags, Volumes) ->
    WireVols = [#{host => H, container => C, opts => O}
                || #{host := H, container := C, opts := O} <- Volumes],
    encode_cmd_spawn(#{path => Path, args => Args, env => Env,
                       uid => Uid, gid => Gid, seccomp => SeccompProfile,
                       rootfs_mb => RootfsSizeMB, caps_keep => CapsKeep,
                       dns_ip => DnsIp, flags => Flags, volumes => WireVols}).

%% =================================================================
%% Other commands — TLV format
%% =================================================================

-spec encode_cmd_go() -> binary().
encode_cmd_go() ->
    msg(?TAG_CMD_GO, []).

-spec encode_cmd_kill(byte()) -> binary().
encode_cmd_kill(Signal) ->
    msg(?TAG_CMD_KILL, [tlv_u8(?EK_ATTR_SIGNAL, Signal)]).

-spec encode_cmd_net_setup(binary(), inet:ip4_address(),
                           0..32, inet:ip4_address()) -> binary().
encode_cmd_net_setup(IfName, {A, B, C, D}, Prefixlen, {GA, GB, GC, GD}) ->
    Ip = (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D,
    Gw = (GA bsl 24) bor (GB bsl 16) bor (GC bsl 8) bor GD,
    msg(?TAG_CMD_NET_SETUP, [
        tlv_str(?EK_ATTR_IFNAME, IfName),
        tlv_u32(?EK_ATTR_CONTAINER_IP, Ip),
        tlv_u32(?EK_ATTR_GATEWAY_IP, Gw),
        tlv_u8(?EK_ATTR_PREFIXLEN, Prefixlen)
    ]).

-spec encode_cmd_write_file(binary(), non_neg_integer(), binary()) -> binary().
encode_cmd_write_file(Path, Mode, Data) ->
    msg(?TAG_CMD_WRITE_FILE, [
        tlv_str(?EK_ATTR_FILE_PATH, Path),
        tlv_u16(?EK_ATTR_FILE_MODE, Mode),
        tlv_str(?EK_ATTR_CONTENT, Data)
    ]).

-spec encode_cmd_query_status() -> binary().
encode_cmd_query_status() ->
    msg(?TAG_CMD_QUERY_STATUS, []).

-spec encode_cmd_stdin(binary()) -> binary().
encode_cmd_stdin(Data) ->
    %% STDIN is raw bytes after Tag+Ver, no TLV
    <<?TAG_CMD_STDIN, ?PROTOCOL_VERSION, Data/binary>>.

-spec encode_cmd_resize(non_neg_integer(), non_neg_integer()) -> binary().
encode_cmd_resize(Rows, Cols) ->
    msg(?TAG_CMD_RESIZE, [
        tlv_u16(1, Rows),
        tlv_u16(2, Cols)
    ]).

-spec encode_cmd_device_filter(binary()) -> binary().
encode_cmd_device_filter(CgroupPath) ->
    msg(?TAG_CMD_DEVICE_FILTER, [
        tlv_str(1, CgroupPath)
    ]).

-spec encode_cmd_device_filter(binary(), [{integer(), integer(), integer(), integer()}]) -> binary().
encode_cmd_device_filter(CgroupPath, Rules) ->
    RulesBin = << <<Type:8, Major:32/big-signed, Minor:32/big-signed, Access:8>>
                  || {Type, Major, Minor, Access} <- Rules >>,
    msg(?TAG_CMD_DEVICE_FILTER, [
        tlv_str(1, CgroupPath),
        tlv_str(2, RulesBin)
    ]).

-spec encode_cmd_metrics_start(binary()) -> binary().
encode_cmd_metrics_start(CgroupPath) ->
    msg(?TAG_CMD_METRICS_START, [
        tlv_str(1, CgroupPath)
    ]).

-spec encode_cmd_metrics_stop() -> binary().
encode_cmd_metrics_stop() ->
    msg(?TAG_CMD_METRICS_STOP, []).

-spec spawn_flag_pty() -> non_neg_integer().
spawn_flag_pty() -> ?SPAWN_FLAG_PTY.

%% =================================================================
%% Decode replies (C -> Erlang)
%% =================================================================

-spec decode(binary()) -> {ok, atom(), map()} | {error, term()}.
decode(<<Tag, _Ver, Payload/binary>>) ->
    %% TLV replies: Tag + Version + Payload
    decode_tag(Tag, Payload);
decode(<<Tag, Payload/binary>>) ->
    %% Legacy: Tag + Payload (no version byte)
    decode_tag(Tag, Payload);
decode(<<>>) ->
    {error, empty_message};
decode(_) ->
    {error, invalid_message}.

decode_tag(?TAG_REPLY_OK, _) ->
    {ok, reply_ok, #{}};

decode_tag(?TAG_REPLY_ERROR, Bin) ->
    %% TLV: Attr 1 = errno (int32), Attr 2 = message (string)
    Attrs = decode_tlv_attrs(Bin),
    Code = case maps:find(1, Attrs) of
        {ok, <<C:32/big-signed>>} -> C;
        _ -> -1
    end,
    Msg = case maps:find(2, Attrs) of
        {ok, M} when is_binary(M) -> M;
        _ -> <<"unknown">>
    end,
    {ok, reply_error, #{code => Code, message => Msg}};

decode_tag(?TAG_REPLY_CONTAINER_PID, Bin) ->
    %% TLV: Attr 1 = PID (uint32), Attr 2 = netns path (string)
    Attrs = decode_tlv_attrs(Bin),
    Pid = case maps:find(1, Attrs) of
        {ok, <<P:32/big>>} -> P;
        _ -> 0
    end,
    Ns = case maps:find(2, Attrs) of
        {ok, N} when is_binary(N) -> N;
        _ -> <<>>
    end,
    {ok, reply_container_pid, #{child_pid => Pid, netns_path => Ns}};

decode_tag(?TAG_REPLY_READY, _) ->
    {ok, reply_ready, #{}};

decode_tag(?TAG_REPLY_EXITED, Bin) ->
    Attrs = decode_tlv_attrs(Bin),
    ExitCode = case maps:find(1, Attrs) of
        {ok, <<EC:32/big-signed>>} -> EC;
        _ -> -1
    end,
    Signal = case maps:find(2, Attrs) of
        {ok, <<S:8>>} -> S;
        {ok, <<S:32/big>>} -> S;
        _ -> 0
    end,
    {ok, reply_exited, #{exit_code => ExitCode, term_signal => Signal}};

decode_tag(?TAG_REPLY_STATUS, <<State:8, Pid:32/big, Uptime:64/big, _/binary>>) ->
    {ok, reply_status, #{state => State, child_pid => Pid, uptime_ms => Uptime}};
decode_tag(?TAG_REPLY_STATUS, _) ->
    {error, {malformed, reply_status}};

decode_tag(?TAG_REPLY_STDOUT, Data) ->
    {ok, reply_stdout, #{data => Data}};

decode_tag(?TAG_REPLY_STDERR, Data) ->
    {ok, reply_stderr, #{data => Data}};

decode_tag(?TAG_REPLY_METRICS_EVENT,
           <<Type:8, Pid:32/big, Tgid:32/big, Ts:64/big, Rest/binary>>) ->
    Event = decode_metrics_event(Type, Rest),
    {ok, reply_metrics_event, Event#{pid => Pid, tgid => Tgid,
                                     timestamp_ns => Ts}};
decode_tag(?TAG_REPLY_METRICS_EVENT, _) ->
    {error, {malformed, reply_metrics_event}};

decode_tag(Tag, _) ->
    {error, {unknown_tag, Tag}}.

%% -- TLV attribute decode (for replies) ----------------------------

decode_tlv_attrs(Bin) ->
    decode_tlv_attrs(Bin, #{}).

decode_tlv_attrs(<<Type:16/big, Len:16/big, Val:Len/binary, Rest/binary>>, Acc) ->
    decode_tlv_attrs(Rest, Acc#{Type => Val});
decode_tlv_attrs(_, Acc) ->
    Acc.

%% -- Metrics event decoding ----------------------------------------

decode_metrics_event(1, <<ChildPid:32/big>>) ->
    #{type => fork, child_pid => ChildPid};
decode_metrics_event(2, <<Comm:16/binary>>) ->
    #{type => exec, comm => strip_nulls(Comm)};
decode_metrics_event(3, <<ExitCode:32/big-signed>>) ->
    #{type => exit, exit_code => ExitCode};
decode_metrics_event(5, <<VictimPid:32/big>>) ->
    #{type => oom, victim_pid => VictimPid};
decode_metrics_event(Type, _) ->
    #{type => {unknown, Type}}.

strip_nulls(Bin) ->
    case binary:split(Bin, <<0>>) of
        [Name, _] -> Name;
        [Name]    -> Name
    end.

%% =================================================================
%% Volume helpers (legacy compat)
%% =================================================================

-define(EK_VOLUME_F_READONLY, 16#01).

-spec encode_volumes([map()]) -> binary().
encode_volumes(Volumes) ->
    [#{host => H, container => C, opts => O}
     || #{host := H, container := C, opts := O} <- Volumes].

-spec volume_opts(map()) -> non_neg_integer().
volume_opts(#{read_only := true}) -> ?EK_VOLUME_F_READONLY;
volume_opts(_) -> 0.
