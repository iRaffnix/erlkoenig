%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%

-module(elf_syscall_db).
-moduledoc """
Syscall number/name mapping database for Linux.

Provides bidirectional lookup between syscall numbers and names
for x86_64 and aarch64 architectures, plus security-relevant
category classification.
""".

-export([name/2, number/2, all/1, category/1]).

%% ---------------------------------------------------------------------------
%% API
%% ---------------------------------------------------------------------------

-spec name(x86_64 | aarch64, non_neg_integer()) -> {ok, binary()} | error.
name(Arch, Nr) ->
    case table(Arch) of
        error ->
            error;
        {ok, Tab} ->
            case maps:find(Nr, Tab) of
                {ok, _} = Ok -> Ok;
                error -> error
            end
    end.

-spec number(x86_64 | aarch64, binary()) -> {ok, non_neg_integer()} | error.
number(Arch, Name) ->
    case reverse_table(Arch) of
        error ->
            error;
        {ok, Tab} ->
            case maps:find(Name, Tab) of
                {ok, _} = Ok -> Ok;
                error -> error
            end
    end.

-spec all(x86_64 | aarch64) -> [{non_neg_integer(), binary()}].
all(Arch) ->
    case table(Arch) of
        error -> [];
        {ok, Tab} -> lists:sort(maps:to_list(Tab))
    end.

-spec category(binary()) ->
    network | filesystem | process | memory | ipc | time | signal | io | other.
category(Name) ->
    category_lookup(Name).

%% ---------------------------------------------------------------------------
%% Internal — table dispatch
%% ---------------------------------------------------------------------------

-spec table(x86_64 | aarch64) -> {ok, #{non_neg_integer() => binary()}} | error.
table(x86_64) -> {ok, x86_64_table()};
table(aarch64) -> {ok, aarch64_table()};
table(_) -> error.

-spec reverse_table(x86_64 | aarch64) -> {ok, #{binary() => non_neg_integer()}} | error.
reverse_table(Arch) ->
    case table(Arch) of
        error ->
            error;
        {ok, Tab} ->
            Rev = maps:fold(fun(Nr, Name, Acc) -> Acc#{Name => Nr} end, #{}, Tab),
            {ok, Rev}
    end.

%% ---------------------------------------------------------------------------
%% x86_64 syscall table (complete: 0-462, gap 336-423)
%% ---------------------------------------------------------------------------

x86_64_table() ->
    #{
        0 => <<"read">>,
        1 => <<"write">>,
        2 => <<"open">>,
        3 => <<"close">>,
        4 => <<"stat">>,
        5 => <<"fstat">>,
        6 => <<"lstat">>,
        7 => <<"poll">>,
        8 => <<"lseek">>,
        9 => <<"mmap">>,
        10 => <<"mprotect">>,
        11 => <<"munmap">>,
        12 => <<"brk">>,
        13 => <<"rt_sigaction">>,
        14 => <<"rt_sigprocmask">>,
        15 => <<"rt_sigreturn">>,
        16 => <<"ioctl">>,
        17 => <<"pread64">>,
        18 => <<"pwrite64">>,
        19 => <<"readv">>,
        20 => <<"writev">>,
        21 => <<"access">>,
        22 => <<"pipe">>,
        23 => <<"select">>,
        24 => <<"sched_yield">>,
        25 => <<"mremap">>,
        26 => <<"msync">>,
        27 => <<"mincore">>,
        28 => <<"madvise">>,
        29 => <<"shmget">>,
        30 => <<"shmat">>,
        31 => <<"shmctl">>,
        32 => <<"dup">>,
        33 => <<"dup2">>,
        34 => <<"pause">>,
        35 => <<"nanosleep">>,
        36 => <<"getitimer">>,
        37 => <<"alarm">>,
        38 => <<"setitimer">>,
        39 => <<"getpid">>,
        40 => <<"sendfile">>,
        41 => <<"socket">>,
        42 => <<"connect">>,
        43 => <<"accept">>,
        44 => <<"sendto">>,
        45 => <<"recvfrom">>,
        46 => <<"sendmsg">>,
        47 => <<"recvmsg">>,
        48 => <<"shutdown">>,
        49 => <<"bind">>,
        50 => <<"listen">>,
        51 => <<"getsockname">>,
        52 => <<"getpeername">>,
        53 => <<"socketpair">>,
        54 => <<"setsockopt">>,
        55 => <<"getsockopt">>,
        56 => <<"clone">>,
        57 => <<"fork">>,
        58 => <<"vfork">>,
        59 => <<"execve">>,
        60 => <<"exit">>,
        61 => <<"wait4">>,
        62 => <<"kill">>,
        63 => <<"uname">>,
        64 => <<"semget">>,
        65 => <<"semop">>,
        66 => <<"semctl">>,
        67 => <<"shmdt">>,
        68 => <<"msgget">>,
        69 => <<"msgsnd">>,
        70 => <<"msgrcv">>,
        71 => <<"msgctl">>,
        72 => <<"fcntl">>,
        73 => <<"flock">>,
        74 => <<"fsync">>,
        75 => <<"fdatasync">>,
        76 => <<"truncate">>,
        77 => <<"ftruncate">>,
        78 => <<"getdents">>,
        79 => <<"getcwd">>,
        80 => <<"chdir">>,
        81 => <<"fchdir">>,
        82 => <<"rename">>,
        83 => <<"mkdir">>,
        84 => <<"rmdir">>,
        85 => <<"creat">>,
        86 => <<"link">>,
        87 => <<"unlink">>,
        88 => <<"symlink">>,
        89 => <<"readlink">>,
        90 => <<"chmod">>,
        91 => <<"fchmod">>,
        92 => <<"chown">>,
        93 => <<"fchown">>,
        94 => <<"lchown">>,
        95 => <<"umask">>,
        96 => <<"gettimeofday">>,
        97 => <<"getrlimit">>,
        98 => <<"getrusage">>,
        99 => <<"sysinfo">>,
        100 => <<"times">>,
        101 => <<"ptrace">>,
        102 => <<"getuid">>,
        103 => <<"syslog">>,
        104 => <<"getgid">>,
        105 => <<"setuid">>,
        106 => <<"setgid">>,
        107 => <<"geteuid">>,
        108 => <<"getegid">>,
        109 => <<"setpgid">>,
        110 => <<"getppid">>,
        111 => <<"getpgrp">>,
        112 => <<"setsid">>,
        113 => <<"setreuid">>,
        114 => <<"setregid">>,
        115 => <<"getgroups">>,
        116 => <<"setgroups">>,
        117 => <<"setresuid">>,
        118 => <<"getresuid">>,
        119 => <<"setresgid">>,
        120 => <<"getresgid">>,
        121 => <<"getpgid">>,
        122 => <<"setfsuid">>,
        123 => <<"setfsgid">>,
        124 => <<"getsid">>,
        125 => <<"capget">>,
        126 => <<"capset">>,
        127 => <<"rt_sigpending">>,
        128 => <<"rt_sigtimedwait">>,
        129 => <<"rt_sigqueueinfo">>,
        130 => <<"rt_sigsuspend">>,
        131 => <<"sigaltstack">>,
        132 => <<"utime">>,
        133 => <<"mknod">>,
        134 => <<"uselib">>,
        135 => <<"personality">>,
        136 => <<"ustat">>,
        137 => <<"statfs">>,
        138 => <<"fstatfs">>,
        139 => <<"sysfs">>,
        140 => <<"getpriority">>,
        141 => <<"setpriority">>,
        142 => <<"sched_setparam">>,
        143 => <<"sched_getparam">>,
        144 => <<"sched_setscheduler">>,
        145 => <<"sched_getscheduler">>,
        146 => <<"sched_get_priority_max">>,
        147 => <<"sched_get_priority_min">>,
        148 => <<"sched_rr_get_interval">>,
        149 => <<"mlock">>,
        150 => <<"munlock">>,
        151 => <<"mlockall">>,
        152 => <<"munlockall">>,
        153 => <<"vhangup">>,
        154 => <<"modify_ldt">>,
        155 => <<"pivot_root">>,
        156 => <<"_sysctl">>,
        157 => <<"prctl">>,
        158 => <<"arch_prctl">>,
        159 => <<"adjtimex">>,
        160 => <<"setrlimit">>,
        161 => <<"chroot">>,
        162 => <<"sync">>,
        163 => <<"acct">>,
        164 => <<"settimeofday">>,
        165 => <<"mount">>,
        166 => <<"umount2">>,
        167 => <<"swapon">>,
        168 => <<"swapoff">>,
        169 => <<"reboot">>,
        170 => <<"sethostname">>,
        171 => <<"setdomainname">>,
        172 => <<"iopl">>,
        173 => <<"ioperm">>,
        174 => <<"create_module">>,
        175 => <<"init_module">>,
        176 => <<"delete_module">>,
        177 => <<"get_kernel_syms">>,
        178 => <<"query_module">>,
        179 => <<"quotactl">>,
        180 => <<"nfsservctl">>,
        181 => <<"getpmsg">>,
        182 => <<"putpmsg">>,
        183 => <<"afs_syscall">>,
        184 => <<"tuxcall">>,
        185 => <<"security">>,
        186 => <<"gettid">>,
        187 => <<"readahead">>,
        188 => <<"setxattr">>,
        189 => <<"lsetxattr">>,
        190 => <<"fsetxattr">>,
        191 => <<"getxattr">>,
        192 => <<"lgetxattr">>,
        193 => <<"fgetxattr">>,
        194 => <<"listxattr">>,
        195 => <<"llistxattr">>,
        196 => <<"flistxattr">>,
        197 => <<"removexattr">>,
        198 => <<"lremovexattr">>,
        199 => <<"fremovexattr">>,
        200 => <<"tkill">>,
        201 => <<"time">>,
        202 => <<"futex">>,
        203 => <<"sched_setaffinity">>,
        204 => <<"sched_getaffinity">>,
        205 => <<"set_thread_area">>,
        206 => <<"io_setup">>,
        207 => <<"io_destroy">>,
        208 => <<"io_getevents">>,
        209 => <<"io_submit">>,
        210 => <<"io_cancel">>,
        211 => <<"get_thread_area">>,
        212 => <<"lookup_dcookie">>,
        213 => <<"epoll_create">>,
        214 => <<"epoll_ctl_old">>,
        215 => <<"epoll_wait_old">>,
        216 => <<"remap_file_pages">>,
        217 => <<"getdents64">>,
        218 => <<"set_tid_address">>,
        219 => <<"restart_syscall">>,
        220 => <<"semtimedop">>,
        221 => <<"fadvise64">>,
        222 => <<"timer_create">>,
        223 => <<"timer_settime">>,
        224 => <<"timer_gettime">>,
        225 => <<"timer_getoverrun">>,
        226 => <<"timer_delete">>,
        227 => <<"clock_settime">>,
        228 => <<"clock_gettime">>,
        229 => <<"clock_getres">>,
        230 => <<"clock_nanosleep">>,
        231 => <<"exit_group">>,
        232 => <<"epoll_wait">>,
        233 => <<"epoll_ctl">>,
        234 => <<"tgkill">>,
        235 => <<"utimes">>,
        236 => <<"vserver">>,
        237 => <<"mbind">>,
        238 => <<"set_mempolicy">>,
        239 => <<"get_mempolicy">>,
        240 => <<"mq_open">>,
        241 => <<"mq_unlink">>,
        242 => <<"mq_timedsend">>,
        243 => <<"mq_timedreceive">>,
        244 => <<"mq_notify">>,
        245 => <<"mq_getsetattr">>,
        246 => <<"kexec_load">>,
        247 => <<"waitid">>,
        248 => <<"add_key">>,
        249 => <<"request_key">>,
        250 => <<"keyctl">>,
        251 => <<"ioprio_set">>,
        252 => <<"ioprio_get">>,
        253 => <<"inotify_init">>,
        254 => <<"inotify_add_watch">>,
        255 => <<"inotify_rm_watch">>,
        256 => <<"migrate_pages">>,
        257 => <<"openat">>,
        258 => <<"mkdirat">>,
        259 => <<"mknodat">>,
        260 => <<"fchownat">>,
        261 => <<"futimesat">>,
        262 => <<"newfstatat">>,
        263 => <<"unlinkat">>,
        264 => <<"renameat">>,
        265 => <<"linkat">>,
        266 => <<"symlinkat">>,
        267 => <<"readlinkat">>,
        268 => <<"fchmodat">>,
        269 => <<"faccessat">>,
        270 => <<"pselect6">>,
        271 => <<"ppoll">>,
        272 => <<"unshare">>,
        273 => <<"set_robust_list">>,
        274 => <<"get_robust_list">>,
        275 => <<"splice">>,
        276 => <<"tee">>,
        277 => <<"sync_file_range">>,
        278 => <<"vmsplice">>,
        279 => <<"move_pages">>,
        280 => <<"utimensat">>,
        281 => <<"epoll_pwait">>,
        282 => <<"signalfd">>,
        283 => <<"timerfd_create">>,
        284 => <<"eventfd">>,
        285 => <<"fallocate">>,
        286 => <<"timerfd_settime">>,
        287 => <<"timerfd_gettime">>,
        288 => <<"accept4">>,
        289 => <<"signalfd4">>,
        290 => <<"eventfd2">>,
        291 => <<"epoll_create1">>,
        292 => <<"dup3">>,
        293 => <<"pipe2">>,
        294 => <<"inotify_init1">>,
        295 => <<"preadv">>,
        296 => <<"pwritev">>,
        297 => <<"rt_tgsigqueueinfo">>,
        298 => <<"perf_event_open">>,
        299 => <<"recvmmsg">>,
        300 => <<"fanotify_init">>,
        301 => <<"fanotify_mark">>,
        302 => <<"prlimit64">>,
        303 => <<"name_to_handle_at">>,
        304 => <<"open_by_handle_at">>,
        305 => <<"clock_adjtime">>,
        306 => <<"syncfs">>,
        307 => <<"sendmmsg">>,
        308 => <<"setns">>,
        309 => <<"getcpu">>,
        310 => <<"process_vm_readv">>,
        311 => <<"process_vm_writev">>,
        312 => <<"kcmp">>,
        313 => <<"finit_module">>,
        314 => <<"sched_setattr">>,
        315 => <<"sched_getattr">>,
        316 => <<"renameat2">>,
        317 => <<"seccomp">>,
        318 => <<"getrandom">>,
        319 => <<"memfd_create">>,
        320 => <<"kexec_file_load">>,
        321 => <<"bpf">>,
        322 => <<"execveat">>,
        323 => <<"userfaultfd">>,
        324 => <<"membarrier">>,
        325 => <<"mlock2">>,
        326 => <<"copy_file_range">>,
        327 => <<"preadv2">>,
        328 => <<"pwritev2">>,
        329 => <<"pkey_mprotect">>,
        330 => <<"pkey_alloc">>,
        331 => <<"pkey_free">>,
        332 => <<"statx">>,
        333 => <<"io_pgetevents">>,
        334 => <<"rseq">>,
        335 => <<"uretprobe">>,
        %% 336-423: reserved/unassigned gap
        424 => <<"pidfd_send_signal">>,
        425 => <<"io_uring_setup">>,
        426 => <<"io_uring_enter">>,
        427 => <<"io_uring_register">>,
        428 => <<"open_tree">>,
        429 => <<"move_mount">>,
        430 => <<"fsopen">>,
        431 => <<"fsconfig">>,
        432 => <<"fsmount">>,
        433 => <<"fspick">>,
        434 => <<"pidfd_open">>,
        435 => <<"clone3">>,
        436 => <<"close_range">>,
        437 => <<"openat2">>,
        438 => <<"pidfd_getfd">>,
        439 => <<"faccessat2">>,
        440 => <<"process_madvise">>,
        441 => <<"epoll_pwait2">>,
        442 => <<"mount_setattr">>,
        443 => <<"quotactl_fd">>,
        444 => <<"landlock_create_ruleset">>,
        445 => <<"landlock_add_rule">>,
        446 => <<"landlock_restrict_self">>,
        447 => <<"memfd_secret">>,
        448 => <<"process_mrelease">>,
        449 => <<"futex_waitv">>,
        450 => <<"set_mempolicy_home_node">>,
        451 => <<"cachestat">>,
        452 => <<"fchmodat2">>,
        453 => <<"map_shadow_stack">>,
        454 => <<"futex_wake">>,
        455 => <<"futex_wait">>,
        456 => <<"futex_requeue">>,
        457 => <<"statmount">>,
        458 => <<"listmount">>,
        459 => <<"lsm_get_self_attr">>,
        460 => <<"lsm_set_self_attr">>,
        461 => <<"lsm_list_modules">>,
        462 => <<"mseal">>
    }.

%% ---------------------------------------------------------------------------
%% aarch64 syscall table
%% ---------------------------------------------------------------------------

aarch64_table() ->
    #{
        56 => <<"openat">>,
        57 => <<"close">>,
        63 => <<"read">>,
        64 => <<"write">>,
        66 => <<"writev">>,
        78 => <<"readlinkat">>,
        79 => <<"newfstatat">>,
        80 => <<"fstat">>,
        93 => <<"exit">>,
        94 => <<"exit_group">>,
        96 => <<"set_tid_address">>,
        98 => <<"futex">>,
        99 => <<"set_robust_list">>,
        113 => <<"clock_gettime">>,
        124 => <<"sched_yield">>,
        129 => <<"kill">>,
        134 => <<"rt_sigaction">>,
        135 => <<"rt_sigprocmask">>,
        136 => <<"rt_sigreturn">>,
        160 => <<"uname">>,
        169 => <<"gettimeofday">>,
        172 => <<"getpid">>,
        173 => <<"getppid">>,
        174 => <<"getuid">>,
        176 => <<"getgid">>,
        178 => <<"gettid">>,
        198 => <<"socket">>,
        200 => <<"bind">>,
        201 => <<"listen">>,
        202 => <<"connect">>,
        203 => <<"accept">>,
        204 => <<"getsockname">>,
        205 => <<"getpeername">>,
        206 => <<"sendto">>,
        207 => <<"recvfrom">>,
        208 => <<"setsockopt">>,
        209 => <<"getsockopt">>,
        210 => <<"shutdown">>,
        211 => <<"sendmsg">>,
        212 => <<"recvmsg">>,
        214 => <<"brk">>,
        215 => <<"munmap">>,
        216 => <<"mremap">>,
        220 => <<"clone">>,
        221 => <<"execve">>,
        222 => <<"mmap">>,
        226 => <<"mprotect">>,
        227 => <<"msync">>,
        233 => <<"madvise">>,
        261 => <<"prlimit64">>,
        278 => <<"getrandom">>,
        281 => <<"epoll_pwait">>,
        291 => <<"io_uring_enter">>,
        435 => <<"clone3">>
    }.

%% ---------------------------------------------------------------------------
%% Category classification
%% ---------------------------------------------------------------------------

-spec category_lookup(binary()) ->
    network | filesystem | process | memory | ipc | time | signal | io | other.
%% Network
category_lookup(<<"socket">>) -> network;
category_lookup(<<"connect">>) -> network;
category_lookup(<<"accept">>) -> network;
category_lookup(<<"accept4">>) -> network;
category_lookup(<<"bind">>) -> network;
category_lookup(<<"listen">>) -> network;
category_lookup(<<"sendto">>) -> network;
category_lookup(<<"recvfrom">>) -> network;
category_lookup(<<"sendmsg">>) -> network;
category_lookup(<<"recvmsg">>) -> network;
category_lookup(<<"shutdown">>) -> network;
category_lookup(<<"setsockopt">>) -> network;
category_lookup(<<"getsockopt">>) -> network;
category_lookup(<<"getsockname">>) -> network;
category_lookup(<<"getpeername">>) -> network;
category_lookup(<<"socketpair">>) -> network;
category_lookup(<<"sendfile">>) -> network;
category_lookup(<<"recvmmsg">>) -> network;
category_lookup(<<"sendmmsg">>) -> network;
%% Filesystem
category_lookup(<<"open">>) -> filesystem;
category_lookup(<<"openat">>) -> filesystem;
category_lookup(<<"openat2">>) -> filesystem;
category_lookup(<<"read">>) -> filesystem;
category_lookup(<<"write">>) -> filesystem;
category_lookup(<<"close">>) -> filesystem;
category_lookup(<<"close_range">>) -> filesystem;
category_lookup(<<"stat">>) -> filesystem;
category_lookup(<<"fstat">>) -> filesystem;
category_lookup(<<"lstat">>) -> filesystem;
category_lookup(<<"newfstatat">>) -> filesystem;
category_lookup(<<"statx">>) -> filesystem;
category_lookup(<<"statfs">>) -> filesystem;
category_lookup(<<"fstatfs">>) -> filesystem;
category_lookup(<<"lseek">>) -> filesystem;
category_lookup(<<"access">>) -> filesystem;
category_lookup(<<"faccessat">>) -> filesystem;
category_lookup(<<"faccessat2">>) -> filesystem;
category_lookup(<<"rename">>) -> filesystem;
category_lookup(<<"renameat">>) -> filesystem;
category_lookup(<<"renameat2">>) -> filesystem;
category_lookup(<<"mkdir">>) -> filesystem;
category_lookup(<<"mkdirat">>) -> filesystem;
category_lookup(<<"rmdir">>) -> filesystem;
category_lookup(<<"unlink">>) -> filesystem;
category_lookup(<<"unlinkat">>) -> filesystem;
category_lookup(<<"link">>) -> filesystem;
category_lookup(<<"linkat">>) -> filesystem;
category_lookup(<<"symlink">>) -> filesystem;
category_lookup(<<"symlinkat">>) -> filesystem;
category_lookup(<<"readlink">>) -> filesystem;
category_lookup(<<"readlinkat">>) -> filesystem;
category_lookup(<<"chmod">>) -> filesystem;
category_lookup(<<"fchmod">>) -> filesystem;
category_lookup(<<"fchmodat">>) -> filesystem;
category_lookup(<<"fchmodat2">>) -> filesystem;
category_lookup(<<"chown">>) -> filesystem;
category_lookup(<<"fchown">>) -> filesystem;
category_lookup(<<"fchownat">>) -> filesystem;
category_lookup(<<"lchown">>) -> filesystem;
category_lookup(<<"chdir">>) -> filesystem;
category_lookup(<<"fchdir">>) -> filesystem;
category_lookup(<<"getcwd">>) -> filesystem;
category_lookup(<<"creat">>) -> filesystem;
category_lookup(<<"mknod">>) -> filesystem;
category_lookup(<<"mknodat">>) -> filesystem;
category_lookup(<<"ftruncate">>) -> filesystem;
category_lookup(<<"truncate">>) -> filesystem;
category_lookup(<<"getdents">>) -> filesystem;
category_lookup(<<"getdents64">>) -> filesystem;
category_lookup(<<"fcntl">>) -> filesystem;
category_lookup(<<"flock">>) -> filesystem;
category_lookup(<<"fsync">>) -> filesystem;
category_lookup(<<"fdatasync">>) -> filesystem;
category_lookup(<<"readv">>) -> filesystem;
category_lookup(<<"writev">>) -> filesystem;
category_lookup(<<"pread64">>) -> filesystem;
category_lookup(<<"pwrite64">>) -> filesystem;
category_lookup(<<"preadv">>) -> filesystem;
category_lookup(<<"pwritev">>) -> filesystem;
category_lookup(<<"preadv2">>) -> filesystem;
category_lookup(<<"pwritev2">>) -> filesystem;
category_lookup(<<"utimensat">>) -> filesystem;
category_lookup(<<"futimesat">>) -> filesystem;
category_lookup(<<"utime">>) -> filesystem;
category_lookup(<<"utimes">>) -> filesystem;
category_lookup(<<"pivot_root">>) -> filesystem;
category_lookup(<<"chroot">>) -> filesystem;
category_lookup(<<"ioctl">>) -> filesystem;
category_lookup(<<"dup">>) -> filesystem;
category_lookup(<<"dup2">>) -> filesystem;
category_lookup(<<"dup3">>) -> filesystem;
category_lookup(<<"umask">>) -> filesystem;
category_lookup(<<"fallocate">>) -> filesystem;
category_lookup(<<"readahead">>) -> filesystem;
category_lookup(<<"fadvise64">>) -> filesystem;
category_lookup(<<"sync">>) -> filesystem;
category_lookup(<<"syncfs">>) -> filesystem;
category_lookup(<<"sync_file_range">>) -> filesystem;
category_lookup(<<"splice">>) -> filesystem;
category_lookup(<<"tee">>) -> filesystem;
category_lookup(<<"vmsplice">>) -> filesystem;
category_lookup(<<"copy_file_range">>) -> filesystem;
category_lookup(<<"name_to_handle_at">>) -> filesystem;
category_lookup(<<"open_by_handle_at">>) -> filesystem;
category_lookup(<<"open_tree">>) -> filesystem;
category_lookup(<<"move_mount">>) -> filesystem;
category_lookup(<<"fsopen">>) -> filesystem;
category_lookup(<<"fsconfig">>) -> filesystem;
category_lookup(<<"fsmount">>) -> filesystem;
category_lookup(<<"fspick">>) -> filesystem;
category_lookup(<<"mount">>) -> filesystem;
category_lookup(<<"umount2">>) -> filesystem;
category_lookup(<<"mount_setattr">>) -> filesystem;
category_lookup(<<"quotactl">>) -> filesystem;
category_lookup(<<"quotactl_fd">>) -> filesystem;
category_lookup(<<"cachestat">>) -> filesystem;
category_lookup(<<"statmount">>) -> filesystem;
category_lookup(<<"listmount">>) -> filesystem;
category_lookup(<<"setxattr">>) -> filesystem;
category_lookup(<<"lsetxattr">>) -> filesystem;
category_lookup(<<"fsetxattr">>) -> filesystem;
category_lookup(<<"getxattr">>) -> filesystem;
category_lookup(<<"lgetxattr">>) -> filesystem;
category_lookup(<<"fgetxattr">>) -> filesystem;
category_lookup(<<"listxattr">>) -> filesystem;
category_lookup(<<"llistxattr">>) -> filesystem;
category_lookup(<<"flistxattr">>) -> filesystem;
category_lookup(<<"removexattr">>) -> filesystem;
category_lookup(<<"lremovexattr">>) -> filesystem;
category_lookup(<<"fremovexattr">>) -> filesystem;
category_lookup(<<"remap_file_pages">>) -> filesystem;
%% Process
category_lookup(<<"clone">>) -> process;
category_lookup(<<"clone3">>) -> process;
category_lookup(<<"fork">>) -> process;
category_lookup(<<"vfork">>) -> process;
category_lookup(<<"execve">>) -> process;
category_lookup(<<"execveat">>) -> process;
category_lookup(<<"exit">>) -> process;
category_lookup(<<"exit_group">>) -> process;
category_lookup(<<"wait4">>) -> process;
category_lookup(<<"waitid">>) -> process;
category_lookup(<<"prctl">>) -> process;
category_lookup(<<"arch_prctl">>) -> process;
category_lookup(<<"ptrace">>) -> process;
category_lookup(<<"getpid">>) -> process;
category_lookup(<<"getppid">>) -> process;
category_lookup(<<"getuid">>) -> process;
category_lookup(<<"getgid">>) -> process;
category_lookup(<<"geteuid">>) -> process;
category_lookup(<<"getegid">>) -> process;
category_lookup(<<"gettid">>) -> process;
category_lookup(<<"setuid">>) -> process;
category_lookup(<<"setgid">>) -> process;
category_lookup(<<"setreuid">>) -> process;
category_lookup(<<"setregid">>) -> process;
category_lookup(<<"setresuid">>) -> process;
category_lookup(<<"getresuid">>) -> process;
category_lookup(<<"setresgid">>) -> process;
category_lookup(<<"getresgid">>) -> process;
category_lookup(<<"setfsuid">>) -> process;
category_lookup(<<"setfsgid">>) -> process;
category_lookup(<<"setpgid">>) -> process;
category_lookup(<<"getpgid">>) -> process;
category_lookup(<<"getpgrp">>) -> process;
category_lookup(<<"setsid">>) -> process;
category_lookup(<<"getsid">>) -> process;
category_lookup(<<"getgroups">>) -> process;
category_lookup(<<"setgroups">>) -> process;
category_lookup(<<"capget">>) -> process;
category_lookup(<<"capset">>) -> process;
category_lookup(<<"uname">>) -> process;
category_lookup(<<"getrlimit">>) -> process;
category_lookup(<<"setrlimit">>) -> process;
category_lookup(<<"prlimit64">>) -> process;
category_lookup(<<"getrusage">>) -> process;
category_lookup(<<"sysinfo">>) -> process;
category_lookup(<<"times">>) -> process;
category_lookup(<<"personality">>) -> process;
category_lookup(<<"getrandom">>) -> process;
category_lookup(<<"rseq">>) -> process;
category_lookup(<<"set_tid_address">>) -> process;
category_lookup(<<"set_robust_list">>) -> process;
category_lookup(<<"get_robust_list">>) -> process;
category_lookup(<<"sched_yield">>) -> process;
category_lookup(<<"sched_setparam">>) -> process;
category_lookup(<<"sched_getparam">>) -> process;
category_lookup(<<"sched_setscheduler">>) -> process;
category_lookup(<<"sched_getscheduler">>) -> process;
category_lookup(<<"sched_get_priority_max">>) -> process;
category_lookup(<<"sched_get_priority_min">>) -> process;
category_lookup(<<"sched_rr_get_interval">>) -> process;
category_lookup(<<"sched_setaffinity">>) -> process;
category_lookup(<<"sched_getaffinity">>) -> process;
category_lookup(<<"sched_setattr">>) -> process;
category_lookup(<<"sched_getattr">>) -> process;
category_lookup(<<"unshare">>) -> process;
category_lookup(<<"getcpu">>) -> process;
category_lookup(<<"seccomp">>) -> process;
category_lookup(<<"pidfd_send_signal">>) -> process;
category_lookup(<<"pidfd_open">>) -> process;
category_lookup(<<"pidfd_getfd">>) -> process;
category_lookup(<<"process_vm_readv">>) -> process;
category_lookup(<<"process_vm_writev">>) -> process;
category_lookup(<<"process_madvise">>) -> process;
category_lookup(<<"process_mrelease">>) -> process;
category_lookup(<<"kcmp">>) -> process;
category_lookup(<<"acct">>) -> process;
category_lookup(<<"getpriority">>) -> process;
category_lookup(<<"setpriority">>) -> process;
%% Memory
category_lookup(<<"mmap">>) -> memory;
category_lookup(<<"munmap">>) -> memory;
category_lookup(<<"mprotect">>) -> memory;
category_lookup(<<"brk">>) -> memory;
category_lookup(<<"madvise">>) -> memory;
category_lookup(<<"mremap">>) -> memory;
category_lookup(<<"msync">>) -> memory;
category_lookup(<<"mincore">>) -> memory;
category_lookup(<<"mlock">>) -> memory;
category_lookup(<<"munlock">>) -> memory;
category_lookup(<<"mlockall">>) -> memory;
category_lookup(<<"munlockall">>) -> memory;
category_lookup(<<"mlock2">>) -> memory;
category_lookup(<<"mbind">>) -> memory;
category_lookup(<<"set_mempolicy">>) -> memory;
category_lookup(<<"get_mempolicy">>) -> memory;
category_lookup(<<"set_mempolicy_home_node">>) -> memory;
category_lookup(<<"move_pages">>) -> memory;
category_lookup(<<"migrate_pages">>) -> memory;
category_lookup(<<"pkey_mprotect">>) -> memory;
category_lookup(<<"pkey_alloc">>) -> memory;
category_lookup(<<"pkey_free">>) -> memory;
category_lookup(<<"memfd_create">>) -> memory;
category_lookup(<<"memfd_secret">>) -> memory;
category_lookup(<<"membarrier">>) -> memory;
category_lookup(<<"userfaultfd">>) -> memory;
category_lookup(<<"mseal">>) -> memory;
category_lookup(<<"map_shadow_stack">>) -> memory;
%% IPC
category_lookup(<<"pipe">>) -> ipc;
category_lookup(<<"pipe2">>) -> ipc;
category_lookup(<<"futex">>) -> ipc;
category_lookup(<<"futex_waitv">>) -> ipc;
category_lookup(<<"futex_wake">>) -> ipc;
category_lookup(<<"futex_wait">>) -> ipc;
category_lookup(<<"futex_requeue">>) -> ipc;
category_lookup(<<"eventfd">>) -> ipc;
category_lookup(<<"eventfd2">>) -> ipc;
category_lookup(<<"shmget">>) -> ipc;
category_lookup(<<"shmat">>) -> ipc;
category_lookup(<<"shmctl">>) -> ipc;
category_lookup(<<"shmdt">>) -> ipc;
category_lookup(<<"semget">>) -> ipc;
category_lookup(<<"semop">>) -> ipc;
category_lookup(<<"semctl">>) -> ipc;
category_lookup(<<"semtimedop">>) -> ipc;
category_lookup(<<"msgget">>) -> ipc;
category_lookup(<<"msgsnd">>) -> ipc;
category_lookup(<<"msgrcv">>) -> ipc;
category_lookup(<<"msgctl">>) -> ipc;
category_lookup(<<"mq_open">>) -> ipc;
category_lookup(<<"mq_unlink">>) -> ipc;
category_lookup(<<"mq_timedsend">>) -> ipc;
category_lookup(<<"mq_timedreceive">>) -> ipc;
category_lookup(<<"mq_notify">>) -> ipc;
category_lookup(<<"mq_getsetattr">>) -> ipc;
%% Signal
category_lookup(<<"rt_sigaction">>) -> signal;
category_lookup(<<"rt_sigprocmask">>) -> signal;
category_lookup(<<"rt_sigreturn">>) -> signal;
category_lookup(<<"rt_sigpending">>) -> signal;
category_lookup(<<"rt_sigtimedwait">>) -> signal;
category_lookup(<<"rt_sigqueueinfo">>) -> signal;
category_lookup(<<"rt_sigsuspend">>) -> signal;
category_lookup(<<"rt_tgsigqueueinfo">>) -> signal;
category_lookup(<<"sigaltstack">>) -> signal;
category_lookup(<<"kill">>) -> signal;
category_lookup(<<"tkill">>) -> signal;
category_lookup(<<"tgkill">>) -> signal;
category_lookup(<<"alarm">>) -> signal;
category_lookup(<<"signalfd">>) -> signal;
category_lookup(<<"signalfd4">>) -> signal;
category_lookup(<<"pause">>) -> signal;
%% Time
category_lookup(<<"clock_gettime">>) -> time;
category_lookup(<<"clock_settime">>) -> time;
category_lookup(<<"clock_getres">>) -> time;
category_lookup(<<"clock_nanosleep">>) -> time;
category_lookup(<<"clock_adjtime">>) -> time;
category_lookup(<<"nanosleep">>) -> time;
category_lookup(<<"gettimeofday">>) -> time;
category_lookup(<<"settimeofday">>) -> time;
category_lookup(<<"adjtimex">>) -> time;
category_lookup(<<"getitimer">>) -> time;
category_lookup(<<"setitimer">>) -> time;
category_lookup(<<"timer_create">>) -> time;
category_lookup(<<"timer_settime">>) -> time;
category_lookup(<<"timer_gettime">>) -> time;
category_lookup(<<"timer_getoverrun">>) -> time;
category_lookup(<<"timer_delete">>) -> time;
category_lookup(<<"timerfd_create">>) -> time;
category_lookup(<<"timerfd_settime">>) -> time;
category_lookup(<<"timerfd_gettime">>) -> time;
category_lookup(<<"time">>) -> time;
%% IO
category_lookup(<<"epoll_wait">>) -> io;
category_lookup(<<"epoll_pwait">>) -> io;
category_lookup(<<"epoll_pwait2">>) -> io;
category_lookup(<<"epoll_ctl">>) -> io;
category_lookup(<<"epoll_create">>) -> io;
category_lookup(<<"epoll_create1">>) -> io;
category_lookup(<<"epoll_ctl_old">>) -> io;
category_lookup(<<"epoll_wait_old">>) -> io;
category_lookup(<<"select">>) -> io;
category_lookup(<<"pselect6">>) -> io;
category_lookup(<<"poll">>) -> io;
category_lookup(<<"ppoll">>) -> io;
category_lookup(<<"io_setup">>) -> io;
category_lookup(<<"io_destroy">>) -> io;
category_lookup(<<"io_getevents">>) -> io;
category_lookup(<<"io_submit">>) -> io;
category_lookup(<<"io_cancel">>) -> io;
category_lookup(<<"io_pgetevents">>) -> io;
category_lookup(<<"io_uring_setup">>) -> io;
category_lookup(<<"io_uring_enter">>) -> io;
category_lookup(<<"io_uring_register">>) -> io;
category_lookup(<<"perf_event_open">>) -> io;
category_lookup(<<"inotify_init">>) -> io;
category_lookup(<<"inotify_add_watch">>) -> io;
category_lookup(<<"inotify_rm_watch">>) -> io;
category_lookup(<<"inotify_init1">>) -> io;
category_lookup(<<"fanotify_init">>) -> io;
category_lookup(<<"fanotify_mark">>) -> io;
%% Other / system administration
category_lookup(_) -> other.
