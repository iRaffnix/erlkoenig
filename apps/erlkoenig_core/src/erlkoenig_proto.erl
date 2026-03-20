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

Handwritten. The protocol specification lives in proto/erlkoenig.protocol.

Transport: Erlang Port with {packet, 4}.
All multi-byte integers are big-endian on the wire.
Payload format: Tag:8 followed by field bytes.
""".

%% Decode
-export([decode/1,
         tag_name/1]).

%% Protocol version
-export([protocol_version/0,
         encode_handshake/0,
         check_handshake_reply/1]).

%% Encode commands
-export([encode_cmd_spawn/6,
         encode_cmd_spawn/7,
         encode_cmd_spawn/8,
         encode_cmd_spawn/9,
         encode_cmd_spawn/10,
         encode_cmd_spawn/11,
         encode_cmd_go/0,
         encode_cmd_kill/1,
         encode_cmd_net_setup/4,
         encode_cmd_write_file/3,
         encode_cmd_cgroup_set/3,
         encode_cmd_query_status/0,
         encode_cmd_stdin/1,
         encode_cmd_resize/2,
         encode_cmd_device_filter/1,
         encode_cmd_device_filter/2,
         encode_cmd_metrics_start/1,
         encode_cmd_metrics_stop/0,
         spawn_flag_pty/0,
         encode_volumes/1,
         volume_opts/1]).

%% -- Protocol version ---------------------------------------------

-define(PROTOCOL_VERSION, 2).
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
-define(TAG_CMD_WRITE_FILE,     16#16).
-define(TAG_CMD_STDIN,          16#17).
-define(TAG_CMD_RESIZE,         16#18).
-define(TAG_CMD_DEVICE_FILTER,  16#19).
-define(TAG_CMD_METRICS_START,  16#1A).
-define(TAG_CMD_METRICS_STOP,   16#1B).

-define(SPAWN_FLAG_PTY,         16#01).

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
tag_name(?TAG_CMD_WRITE_FILE)     -> cmd_write_file;
tag_name(?TAG_CMD_STDIN)          -> cmd_stdin;
tag_name(?TAG_CMD_RESIZE)         -> cmd_resize;
tag_name(?TAG_CMD_DEVICE_FILTER)  -> cmd_device_filter;
tag_name(?TAG_CMD_METRICS_START)  -> cmd_metrics_start;
tag_name(?TAG_CMD_METRICS_STOP)   -> cmd_metrics_stop;
tag_name(_)                        -> unknown.

%% =================================================================
%% Protocol handshake
%% =================================================================

-spec protocol_version() -> pos_integer().
protocol_version() -> ?PROTOCOL_VERSION.

-spec encode_handshake() -> binary().
encode_handshake() ->
    NodeHash = erlkoenig_pki:node_cert_hash(),
    <<?PROTOCOL_VERSION:8, NodeHash:?NODE_CERT_HASH_LEN/binary>>.

-spec check_handshake_reply(binary()) ->
    ok | {error, term()}.
check_handshake_reply(<<?PROTOCOL_VERSION:8, PeerHash:?NODE_CERT_HASH_LEN/binary>>) ->
    %% v2 reply — verify node cert hash matches
    MyHash = erlkoenig_pki:node_cert_hash(),
    case {MyHash, PeerHash} of
        {<<0:256>>, <<0:256>>} ->
            %% Neither side has a cert — ok (no node identity)
            ok;
        {<<0:256>>, _} ->
            logger:warning("[proto] C runtime has node cert but Erlang does not"),
            ok;
        {_, <<0:256>>} ->
            logger:warning("[proto] Erlang has node cert but C runtime does not"),
            ok;
        {MyHash, MyHash} ->
            %% Hashes match — mutual verification success
            logger:info("[proto] node cert verified (mutual)"),
            ok;
        {_, _} ->
            logger:error("[proto] node cert hash MISMATCH"),
            {error, node_cert_mismatch}
    end;
check_handshake_reply(<<1:8>>) ->
    %% v1 reply from older C runtime — accept if no node cert required
    case erlkoenig_pki:node_cert_hash() of
        <<0:256>> ->
            ok;
        _ ->
            logger:warning("[proto] C runtime sent v1 handshake "
                           "but node cert is configured"),
            ok  %% Allow during migration; change to error for strict mode
    end;
check_handshake_reply(<<Got:8, _/binary>>) ->
    {error, {protocol_mismatch, ?PROTOCOL_VERSION, Got}};
check_handshake_reply(_) ->
    {error, {protocol_mismatch, ?PROTOCOL_VERSION, unknown}}.

%% =================================================================
%% Encode commands (Erlang -> C)
%% =================================================================

%% cmd_spawn: Create container with isolated namespaces.
%%
%%   Path           :: binary()          - absolute path to static binary
%%   Args           :: [binary()]        - command-line arguments (max 255)
%%   Env            :: [{binary(), binary()}] - environment as {Key, Value}
%%   Uid, Gid       :: non_neg_integer() - container UID/GID
%%   SeccompProfile :: 0..255            - seccomp profile index (0 = none)
%%
%% Wire: <<0x10, Path:str16, Args:list8(str16),
%%          Env:list8(kv(str8, str16)), Uid:32, Gid:32, Seccomp:8>>

-spec encode_cmd_spawn(binary(), [binary()], [{binary(), binary()}],
                       non_neg_integer(), non_neg_integer(),
                       non_neg_integer()) -> binary().
encode_cmd_spawn(Path, Args, Env, Uid, Gid, SeccompProfile) ->
    encode_cmd_spawn(Path, Args, Env, Uid, Gid, SeccompProfile, 0, 0).

-spec encode_cmd_spawn(binary(), [binary()], [{binary(), binary()}],
                       non_neg_integer(), non_neg_integer(),
                       non_neg_integer(), non_neg_integer()) -> binary().
encode_cmd_spawn(Path, Args, Env, Uid, Gid, SeccompProfile, RootfsSizeMB) ->
    encode_cmd_spawn(Path, Args, Env, Uid, Gid, SeccompProfile, RootfsSizeMB, 0).

-doc "Encode CMD_SPAWN with capabilities (dns_ip defaults to 0). CapsKeep: 64-bit bitmask, bit N = keep CAP_N (0 = drop all).".
-spec encode_cmd_spawn(binary(), [binary()], [{binary(), binary()}],
                       non_neg_integer(), non_neg_integer(),
                       non_neg_integer(), non_neg_integer(),
                       non_neg_integer()) -> binary().
encode_cmd_spawn(Path, Args, Env, Uid, Gid, SeccompProfile, RootfsSizeMB, CapsKeep) ->
    encode_cmd_spawn(Path, Args, Env, Uid, Gid, SeccompProfile, RootfsSizeMB, CapsKeep, 0, 0).

-doc "Encode CMD_SPAWN with DNS IP (flags defaults to 0).".
-spec encode_cmd_spawn(binary(), [binary()], [{binary(), binary()}],
                       non_neg_integer(), non_neg_integer(),
                       non_neg_integer(), non_neg_integer(),
                       non_neg_integer(), non_neg_integer()) -> binary().
encode_cmd_spawn(Path, Args, Env, Uid, Gid, SeccompProfile, RootfsSizeMB, CapsKeep, DnsIp) ->
    encode_cmd_spawn(Path, Args, Env, Uid, Gid, SeccompProfile, RootfsSizeMB, CapsKeep, DnsIp, 0).

-doc "Encode CMD_SPAWN with all options including flags (no volumes). DnsIp: 32-bit network-order IPv4 for /etc/resolv.conf (0 = default gateway). Flags: 32-bit spawn flags (bit 0 = PTY mode).".
-spec encode_cmd_spawn(binary(), [binary()], [{binary(), binary()}],
                       non_neg_integer(), non_neg_integer(),
                       non_neg_integer(), non_neg_integer(),
                       non_neg_integer(), non_neg_integer(),
                       non_neg_integer()) -> binary().
encode_cmd_spawn(Path, Args, Env, Uid, Gid, SeccompProfile, RootfsSizeMB, CapsKeep, DnsIp, Flags) ->
    encode_cmd_spawn(Path, Args, Env, Uid, Gid, SeccompProfile, RootfsSizeMB, CapsKeep, DnsIp, Flags, []).

-doc """
Encode CMD_SPAWN with all options including bind-mount volumes.

Volumes: list of #{host := binary(), container := binary(), opts := non_neg_integer()}.
The opts field carries EK_VOLUME_F_* flags (0x01 = READONLY).

Lockstep contract: Erlang core and C runtime must be deployed together.
If Volumes = [] -> <<0:8>> is appended. An older C runtime without volume
support MUST NOT be mixed with a new core.
""".
-spec encode_cmd_spawn(binary(), [binary()], [{binary(), binary()}],
                       non_neg_integer(), non_neg_integer(),
                       non_neg_integer(), non_neg_integer(),
                       non_neg_integer(), non_neg_integer(),
                       non_neg_integer(), [map()]) -> binary().
encode_cmd_spawn(Path, Args, Env, Uid, Gid, SeccompProfile, RootfsSizeMB, CapsKeep, DnsIp, Flags, Volumes) ->
    ArgsBin = encode_list8_str16(Args),
    EnvBin  = encode_list8_kv(Env),
    VolumesBin = encode_volumes(Volumes),
    <<?TAG_CMD_SPAWN,
      (byte_size(Path)):16/big, Path/binary,
      ArgsBin/binary,
      EnvBin/binary,
      Uid:32/big,
      Gid:32/big,
      SeccompProfile:8,
      RootfsSizeMB:32/big,
      CapsKeep:64/big,
      DnsIp:32/big,
      Flags:32/big,
      VolumesBin/binary>>.

-spec encode_cmd_go() -> binary().
encode_cmd_go() ->
    <<?TAG_CMD_GO>>.

-spec encode_cmd_kill(byte()) -> binary().
encode_cmd_kill(Signal) ->
    <<?TAG_CMD_KILL, Signal:8>>.

%% cmd_net_setup: Configure networking inside container's netns.
%%
%%   IfName           :: binary()        - interface name (e.g. <<"eth0">>)
%%   Ip               :: {A,B,C,D}       - IPv4 address
%%   Prefixlen        :: 0..32           - subnet prefix length
%%   Gateway          :: {A,B,C,D}       - default gateway
%%
%% Wire: <<0x15, IfName:str16, A:8, B:8, C:8, D:8,
%%          Prefixlen:8, GA:8, GB:8, GC:8, GD:8>>
-spec encode_cmd_net_setup(binary(), inet:ip4_address(),
                           0..32, inet:ip4_address()) -> binary().
encode_cmd_net_setup(IfName, {A, B, C, D}, Prefixlen, {GA, GB, GC, GD}) ->
    <<?TAG_CMD_NET_SETUP,
      (byte_size(IfName)):16/big, IfName/binary,
      A:8, B:8, C:8, D:8,
      Prefixlen:8,
      GA:8, GB:8, GC:8, GD:8>>.

%% cmd_write_file: Write a file into the container rootfs (before GO).
%%
%%   Path  :: binary()          - absolute path in container (e.g. <<"/etc/app.conf">>)
%%   Mode  :: non_neg_integer() - POSIX permissions (e.g. 8#644)
%%   Data  :: binary()          - file contents
%%
%% Wire: <<0x16, Path:str16, Mode:16, DataLen:32, Data/binary>>
-spec encode_cmd_write_file(binary(), non_neg_integer(), binary()) -> binary().
encode_cmd_write_file(Path, Mode, Data) ->
    <<?TAG_CMD_WRITE_FILE,
      (byte_size(Path)):16/big, Path/binary,
      Mode:16/big,
      (byte_size(Data)):32/big, Data/binary>>.

-spec encode_cmd_cgroup_set(binary(), binary(), binary()) -> binary().
encode_cmd_cgroup_set(Subsystem, Key, Value) ->
    <<?TAG_CMD_CGROUP_SET,
      (byte_size(Subsystem)):8, Subsystem/binary,
      (byte_size(Key)):8, Key/binary,
      (byte_size(Value)):16/big, Value/binary>>.

-spec encode_cmd_query_status() -> binary().
encode_cmd_query_status() ->
    <<?TAG_CMD_QUERY_STATUS>>.

%% cmd_stdin: Send data to container stdin (pipe mode) or PTY.
%% Fire-and-forget: no reply expected.
-spec encode_cmd_stdin(binary()) -> binary().
encode_cmd_stdin(Data) ->
    <<?TAG_CMD_STDIN, (byte_size(Data)):16/big, Data/binary>>.

%% cmd_resize: Resize container PTY. Only valid in PTY mode.
-spec encode_cmd_resize(non_neg_integer(), non_neg_integer()) -> binary().
encode_cmd_resize(Rows, Cols) ->
    <<?TAG_CMD_RESIZE, Rows:16/big, Cols:16/big>>.

%% cmd_device_filter: Attach eBPF device filter to container cgroup.
%% CgroupPath = absolute path to cgroup dir (binary).
%% With no rules (rule_count=0), uses built-in OCI default allowlist.
-spec encode_cmd_device_filter(binary()) -> binary().
encode_cmd_device_filter(CgroupPath) ->
    <<?TAG_CMD_DEVICE_FILTER,
      (byte_size(CgroupPath)):16/big, CgroupPath/binary,
      0:8>>.

%% With explicit rules: [{Type, Major, Minor, Access}, ...]
%% Type: 1=block, 2=char. Major/Minor: int32 (-1=wildcard).
%% Access: bitmask (1=mknod, 2=read, 4=write, 7=rwm).
-spec encode_cmd_device_filter(binary(), [{integer(), integer(), integer(), integer()}]) -> binary().
encode_cmd_device_filter(CgroupPath, Rules) ->
    RulesBin = << <<Type:8, Major:32/big-signed, Minor:32/big-signed, Access:8>>
                  || {Type, Major, Minor, Access} <- Rules >>,
    <<?TAG_CMD_DEVICE_FILTER,
      (byte_size(CgroupPath)):16/big, CgroupPath/binary,
      (length(Rules)):8,
      RulesBin/binary>>.

%% cmd_metrics_start: Start eBPF tracepoint metrics for a container.
%% CgroupPath = absolute path to cgroup dir (binary).
-spec encode_cmd_metrics_start(binary()) -> binary().
encode_cmd_metrics_start(CgroupPath) ->
    <<?TAG_CMD_METRICS_START,
      (byte_size(CgroupPath)):16/big, CgroupPath/binary>>.

%% cmd_metrics_stop: Stop eBPF tracepoint metrics.
-spec encode_cmd_metrics_stop() -> binary().
encode_cmd_metrics_stop() ->
    <<?TAG_CMD_METRICS_STOP>>.

%% Helper: PTY spawn flag value.
-spec spawn_flag_pty() -> non_neg_integer().
spawn_flag_pty() -> ?SPAWN_FLAG_PTY.

%% =================================================================
%% Decode replies (C -> Erlang)
%% =================================================================

-spec decode(binary()) -> {ok, atom(), map()} | {error, term()}.
decode(<<Tag, Payload/binary>>) ->
    decode_tag(Tag, Payload);
decode(<<>>) ->
    {error, empty_message};
decode(_) ->
    {error, invalid_message}.

decode_tag(?TAG_REPLY_OK, <<Len:16/big, Data:Len/binary>>) ->
    {ok, reply_ok, #{data => Data}};
decode_tag(?TAG_REPLY_OK, _) ->
    {error, {malformed, reply_ok}};

decode_tag(?TAG_REPLY_ERROR, <<Code:32/big-signed,
                               MsgLen:16/big, Msg:MsgLen/binary>>) ->
    {ok, reply_error, #{code => Code, message => Msg}};
decode_tag(?TAG_REPLY_ERROR, _) ->
    {error, {malformed, reply_error}};

decode_tag(?TAG_REPLY_CONTAINER_PID, <<Pid:32/big,
                                       NsLen:16/big, Ns:NsLen/binary>>) ->
    {ok, reply_container_pid, #{child_pid => Pid, netns_path => Ns}};
decode_tag(?TAG_REPLY_CONTAINER_PID, _) ->
    {error, {malformed, reply_container_pid}};

decode_tag(?TAG_REPLY_READY, _) ->
    {ok, reply_ready, #{}};

decode_tag(?TAG_REPLY_EXITED, <<ExitCode:32/big-signed, Signal:8>>) ->
    {ok, reply_exited, #{exit_code => ExitCode, term_signal => Signal}};
decode_tag(?TAG_REPLY_EXITED, _) ->
    {error, {malformed, reply_exited}};

decode_tag(?TAG_REPLY_STATUS, <<State:8, Pid:32/big, Uptime:64/big>>) ->
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

%% -- Metrics event decoding ----------------------------------------

decode_metrics_event(1, <<ChildPid:32/big>>) ->
    #{type => fork, child_pid => ChildPid};
decode_metrics_event(2, <<Comm:16/binary>>) ->
    %% Strip trailing nulls from comm
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
%% Volume encoding
%% =================================================================

%% EK_VOLUME_F_READONLY = 0x01
-define(EK_VOLUME_F_READONLY, 16#01).

-doc "Encode a volume list for the SPAWN command wire format.".
-spec encode_volumes([map()]) -> binary().
encode_volumes([]) -> <<0:8>>;
encode_volumes(Volumes) when length(Volumes) =< 16 ->
    VolBin = << <<(byte_size(Src)):16/big, Src/binary,
                  (byte_size(Dst)):16/big, Dst/binary,
                  Opts:32/big>>
                || #{host := Src, container := Dst, opts := Opts} <- Volumes >>,
    <<(length(Volumes)):8, VolBin/binary>>.

-doc "Convert a volume options map to the wire-format opts bitmask.".
-spec volume_opts(map()) -> non_neg_integer().
volume_opts(#{read_only := true}) -> ?EK_VOLUME_F_READONLY;
volume_opts(_) -> 0.

%% =================================================================
%% List encoding helpers
%% =================================================================

-spec encode_list8_str16([binary()]) -> binary().
encode_list8_str16(Items) when length(Items) =< 255 ->
    Bin = << <<(byte_size(S)):16/big, S/binary>> || S <- Items >>,
    <<(length(Items)):8, Bin/binary>>.

-spec encode_list8_kv([{binary(), binary()}]) -> binary().
encode_list8_kv(Items) when length(Items) =< 255 ->
    Bin = << <<(byte_size(K)):8, K/binary,
              (byte_size(V)):16/big, V/binary>> || {K, V} <- Items >>,
    <<(length(Items)):8, Bin/binary>>.
