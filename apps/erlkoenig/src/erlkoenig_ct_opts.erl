%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%

-module(erlkoenig_ct_opts).
-moduledoc """
Pure helpers split out of `erlkoenig_ct'.

Every function here is deterministic: no processes, no ETS, no
`application:get_env/2'. That keeps them easy to unit-test and means
the gen_statem in `erlkoenig_ct' can call them without thinking about
side effects.

Categories:

  * Restart policy — `validate_restart/1', `normalize_restart/1',
    `should_restart/1', `is_failure_exit/1', `pod_exit_reason/1',
    `backoff_ms/1'. `should_restart', `is_failure_exit' and
    `pod_exit_reason' pattern-match on `#ct_data{}' and therefore
    pull in `erlkoenig_ct_state.hrl'.
  * Seccomp profile name ↔ id — `seccomp_profile_id/1',
    `seccomp_profile_name/1'.
  * Capability bit math — `cap_bit/1', `caps_to_mask/1',
    `mask_to_caps/1'.
  * Tiny DSL-facing coercions — `disk_limit_mb/1',
    `merge_socket_mounts/2', `to_bin/1'.

No behaviour change — only relocation.
""".

-include("erlkoenig_ct_state.hrl").

-export([
    %% Restart policy
    validate_restart/1,
    normalize_restart/1,
    should_restart/1,
    is_failure_exit/1,
    pod_exit_reason/1,
    backoff_ms/1,
    %% Seccomp
    seccomp_profile_id/1,
    seccomp_profile_name/1,
    %% Capabilities
    cap_bit/1,
    caps_to_mask/1,
    mask_to_caps/1,
    %% DSL coercions
    disk_limit_mb/1,
    merge_socket_mounts/2,
    to_bin/1
]).

%% =================================================================
%% Restart policy
%% =================================================================

-spec validate_restart(term()) -> erlkoenig:restart_policy().
%% OTP-style aliases (preferred by the DSL, normalized to legacy internal).
validate_restart(permanent)                             -> always;
validate_restart(transient)                             -> on_failure;
validate_restart(temporary)                             -> no_restart;
%% Legacy names (still used internally throughout the runtime).
validate_restart(no_restart)                            -> no_restart;
validate_restart(always)                                -> always;
validate_restart(on_failure)                            -> on_failure;
validate_restart({always, N}) when is_integer(N), N > 0 -> {always, N};
validate_restart({on_failure, N}) when is_integer(N), N > 0 -> {on_failure, N};
validate_restart(Other) -> error({invalid_restart_policy, Other}).

-spec normalize_restart(term()) ->
    {always | on_failure | no_restart, infinity | non_neg_integer()}.
normalize_restart(always)          -> {always, infinity};
normalize_restart(on_failure)      -> {on_failure, infinity};
normalize_restart({always, N})     -> {always, N};
normalize_restart({on_failure, N}) -> {on_failure, N};
normalize_restart(_)               -> {no_restart, 0}.

-spec should_restart(#ct_data{}) -> boolean().
should_restart(#ct_data{user_stopped = true}) -> false;
should_restart(#ct_data{restart = no_restart}) -> false;
should_restart(Data) ->
    {Strategy, Max} = normalize_restart(Data#ct_data.restart),
    WithinLimit = case Max of
        infinity -> true;
        N        -> Data#ct_data.restart_count < N
    end,
    case Strategy of
        always     -> WithinLimit;
        on_failure -> WithinLimit andalso is_failure_exit(Data)
    end.

-spec is_failure_exit(#ct_data{}) -> boolean().
is_failure_exit(#ct_data{exit_info = #{exit_code := 0, term_signal := 0}}) ->
    false;
is_failure_exit(_) ->
    true.

%% Exit reason for pod-supervised containers.
%% normal/shutdown → supervisor does NOT restart (transient).
%% Anything else → supervisor restarts the group.
-spec pod_exit_reason(#ct_data{}) -> term().
pod_exit_reason(#ct_data{user_stopped = true}) ->
    shutdown;
pod_exit_reason(Data) ->
    case is_failure_exit(Data) of
        false -> normal;
        true ->
            ExitCode = case Data#ct_data.exit_info of
                #{exit_code := C} -> C;
                _ -> unknown
            end,
            Signal = case Data#ct_data.exit_info of
                #{term_signal := S} -> S;
                _ -> 0
            end,
            {container_failed, ExitCode, Signal}
    end.

-spec backoff_ms(integer()) -> pos_integer().
backoff_ms(N) when N =< 0 -> 1000;
backoff_ms(N)              -> min(30_000, 1000 bsl min(N - 1, 4)).

%% =================================================================
%% Seccomp profile name ↔ id
%% =================================================================

-spec seccomp_profile_id(erlkoenig:seccomp_profile() | non_neg_integer()) ->
    non_neg_integer().
seccomp_profile_id(none)    -> 0;
seccomp_profile_id(default) -> 1;
seccomp_profile_id(strict)  -> 2;
seccomp_profile_id(network) -> 3;
seccomp_profile_id(N) when is_integer(N), N >= 0, N =< 255 -> N;
seccomp_profile_id(Other) -> error({invalid_seccomp_profile, Other}).

-spec seccomp_profile_name(non_neg_integer()) ->
    erlkoenig:seccomp_profile() | non_neg_integer().
seccomp_profile_name(0) -> none;
seccomp_profile_name(1) -> default;
seccomp_profile_name(2) -> strict;
seccomp_profile_name(3) -> network;
seccomp_profile_name(N) -> N.

%% =================================================================
%% Capabilities: atom list <-> 64-bit bitmask
%% =================================================================

-spec cap_bit(erlkoenig:capability()) -> 0..40.
cap_bit(chown)              -> 0;
cap_bit(dac_override)       -> 1;
cap_bit(dac_read_search)    -> 2;
cap_bit(fowner)             -> 3;
cap_bit(fsetid)             -> 4;
cap_bit(kill)               -> 5;
cap_bit(setgid)             -> 6;
cap_bit(setuid)             -> 7;
cap_bit(setpcap)            -> 8;
cap_bit(linux_immutable)    -> 9;
cap_bit(net_bind_service)   -> 10;
cap_bit(net_broadcast)      -> 11;
cap_bit(net_admin)          -> 12;
cap_bit(net_raw)            -> 13;
cap_bit(ipc_lock)           -> 14;
cap_bit(ipc_owner)          -> 15;
cap_bit(sys_module)         -> 16;
cap_bit(sys_rawio)          -> 17;
cap_bit(sys_chroot)         -> 18;
cap_bit(sys_ptrace)         -> 19;
cap_bit(sys_pacct)          -> 20;
cap_bit(sys_admin)          -> 21;
cap_bit(sys_boot)           -> 22;
cap_bit(sys_nice)           -> 23;
cap_bit(sys_resource)       -> 24;
cap_bit(sys_time)           -> 25;
cap_bit(sys_tty_config)     -> 26;
cap_bit(mknod)              -> 27;
cap_bit(lease)              -> 28;
cap_bit(audit_write)        -> 29;
cap_bit(audit_control)      -> 30;
cap_bit(setfcap)            -> 31;
cap_bit(mac_override)       -> 32;
cap_bit(mac_admin)          -> 33;
cap_bit(syslog)             -> 34;
cap_bit(wake_alarm)         -> 35;
cap_bit(block_suspend)      -> 36;
cap_bit(audit_read)         -> 37;
cap_bit(perfmon)            -> 38;
cap_bit(bpf)                -> 39;
cap_bit(checkpoint_restore) -> 40;
cap_bit(Other) -> error({unknown_capability, Other}).

-spec caps_to_mask([erlkoenig:capability()]) -> non_neg_integer().
caps_to_mask([]) -> 0;
caps_to_mask(Caps) when is_list(Caps) ->
    lists:foldl(fun(Cap, Acc) ->
        Acc bor (1 bsl cap_bit(Cap))
    end, 0, Caps).

-spec mask_to_caps(non_neg_integer()) -> [erlkoenig:capability()].
mask_to_caps(0) -> [];
mask_to_caps(Mask) ->
    AllCaps = [chown, dac_override, dac_read_search, fowner, fsetid,
               kill, setgid, setuid, setpcap, linux_immutable,
               net_bind_service, net_broadcast, net_admin, net_raw,
               ipc_lock, ipc_owner, sys_module, sys_rawio, sys_chroot,
               sys_ptrace, sys_pacct, sys_admin, sys_boot, sys_nice,
               sys_resource, sys_time, sys_tty_config, mknod, lease,
               audit_write, audit_control, setfcap, mac_override,
               mac_admin, syslog, wake_alarm, block_suspend, audit_read,
               perfmon, bpf, checkpoint_restore],
    [Cap || Cap <- AllCaps, Mask band (1 bsl cap_bit(Cap)) =/= 0].

%% =================================================================
%% DSL coercions
%% =================================================================

-spec disk_limit_mb(map()) -> non_neg_integer().
disk_limit_mb(#{disk := Bytes}) when is_integer(Bytes), Bytes > 0 ->
    max(1, Bytes div (1024 * 1024));
disk_limit_mb(_) ->
    0.

%% Merge DSL-emitted `socket_mounts` (raw host-dir bind specs) into
%% the regular volumes list as PRE-RESOLVED entries. The capability
%% framework hands us absolute host paths that need no `persist:`
%% lookup; the `kind => socket_mount` marker tells the volume
%% resolver to pass them through untouched.
-spec merge_socket_mounts([map()], [map()]) -> [map()].
merge_socket_mounts(Volumes, []) ->
    Volumes;
merge_socket_mounts(Volumes, SocketMounts) ->
    Extra = [#{host      => to_bin(H),
               container => to_bin(C),
               read_only => maps:get(read_only, M, false),
               kind      => socket_mount}
             || #{host := H, container := C} = M <- SocketMounts],
    Volumes ++ Extra.

-spec to_bin(binary() | iolist()) -> binary().
to_bin(B) when is_binary(B) -> B;
to_bin(L) when is_list(L)   -> list_to_binary(L).
