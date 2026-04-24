%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%

%% Shared state record for the `erlkoenig_ct' gen_statem and its
%% extracted helper modules. Previously lived inline in
%% `erlkoenig_ct.erl'; pulled into its own header so
%% `erlkoenig_ct_opts', `erlkoenig_ct_rt', `erlkoenig_ct_observe',
%% `erlkoenig_ct_resources', `erlkoenig_ct_net',
%% `erlkoenig_ct_cgroup', `erlkoenig_ct_volume' and
%% `erlkoenig_ct_security' can match on the same shape without
%% round-tripping through accessors.

-ifndef(ERLKOENIG_CT_STATE_HRL).
-define(ERLKOENIG_CT_STATE_HRL, true).

-record(ct_data, {
    id            :: binary(),
    binary_path   :: binary(),
    args          = [] :: [binary()],
    env           = [] :: [{binary(), binary()}],
    uid           = 0  :: non_neg_integer(),
    gid           = 0  :: non_neg_integer(),
    ip            :: inet:ip4_address() | undefined,
    zone          = default :: atom(),
    sock          :: gen_tcp:socket() | undefined,
    socket_path   :: binary() | undefined,
    os_pid        :: non_neg_integer() | undefined,
    netns_path    :: binary() | undefined,
    net_info      :: map() | undefined,
    started_at    :: integer() | undefined,
    exit_info     :: map() | undefined,
    error_reason  :: term() | undefined,
    from          :: gen_statem:from() | undefined,
    restart       = no_restart :: term(),
    restart_count = 0          :: non_neg_integer(),
    user_stopped  = false      :: boolean(),
    limits        = #{}        :: map(),
    seccomp       = 0          :: non_neg_integer(),
    caps_keep     = 0          :: non_neg_integer(),
    output        = undefined  :: pid() | undefined,
    name          = undefined  :: binary() | undefined,
    files         = #{}        :: #{binary() => binary()},
    handshake     = false      :: boolean(),
    pty           = false      :: boolean(),
    firewall      = #{}        :: map() | skip_firewall,
    extra_opts    = #{}        :: map(),
    sig_path      = undefined  :: binary() | undefined,
    signature_required = false :: boolean(),
    sig_verified  = false      :: boolean(),
    sig_meta      = undefined  :: map() | undefined,
    fuse_mount    = undefined  :: binary() | undefined,
    tmpfs_mounts  = []         :: [map()],
    volumes       = []         :: [map()],
    requires      = []         :: [atom()],
    dns_allowlist = undefined  :: [binary()] | undefined,
    pod_supervised = false     :: boolean(),
    publish       = []         :: [map()],
    stats_timers  = []         :: [reference()],
    last_cpu_usec = undefined  :: non_neg_integer() | undefined,
    stream        = undefined  :: map() | undefined,
    log_publisher = undefined  :: {pid(), atomics:atomics_ref()} | undefined,
    admission_token = undefined :: reference() | undefined,
    %% reconnect_attempts counts retries inside `disconnected' state. The
    %% original comment claimed "up to 30 retries = 30s" but no counter
    %% existed, so a dead runtime meant the gen_statem retried every
    %% second forever — a zombie process per lost container.
    reconnect_attempts = 0     :: non_neg_integer(),
    %% Tracks whether the one-shot registrations (pg:join,
    %% container_started event, dns/dets/audit register) have already
    %% fired in this gen_statem's lifetime. Needed to distinguish a
    %% same-session reconnect (running→disconnected→recovering→running,
    %% flag already true → skip to avoid double-emit) from an
    %% init-recover after a daemon crash (fresh #ct_data, flag is
    %% false → must fire so the restarted ecosystem learns about the
    %% container). Going via started_at alone doesn't work because
    %% recovering(info, {tcp,_,_}, _) overwrites started_at on every
    %% entry to running.
    first_running_entry_done = false :: boolean()
}).

-endif.
