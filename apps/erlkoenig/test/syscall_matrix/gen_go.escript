#!/usr/bin/env escript
%% -*- erlang -*-
%%% @doc Generate Go test programs that invoke specific syscalls.
%%%
%%% Each generated .go file triggers several related syscalls via
%%% syscall.RawSyscall, grouped by category.

-mode(compile).

main(_Args) ->
    ScriptDir = filename:dirname(escript:script_name()),
    GoDir = filename:join(ScriptDir, "go"),
    ok = filelib:ensure_dir(filename:join(GoDir, "dummy")),

    Categories = categories(),
    lists:foreach(fun({Cat, Syscalls}) ->
        generate(GoDir, Cat, Syscalls)
    end, Categories),
    io:format("Generated ~b Go source files in ~s~n",
              [length(Categories), GoDir]).

generate(Dir, Category, Syscalls) ->
    Filename = io_lib:format("cat_~s.go", [Category]),
    Path = filename:join(Dir, lists:flatten(Filename)),

    Header =
        "package main\n\n"
        "import (\n"
        "\t\"syscall\"\n"
        "\t\"unsafe\"\n"
        ")\n\n"
        "func main() {\n"
        "\t// Suppress unused import\n"
        "\t_ = unsafe.Pointer(nil)\n\n",

    Body = lists:flatten([format_syscall(S) || S <- Syscalls]),

    Footer = "}\n",

    ok = file:write_file(Path, [Header, Body, Footer]).

format_syscall({Nr, Name, Comment}) ->
    io_lib:format(
        "\t// ~s (~b)\n"
        "\tsyscall.RawSyscall(~b, 0, 0, 0) // ~s\n\n",
        [Comment, Nr, Nr, Name]).

%% Syscall categories with representative syscalls for Go binaries.
%% Each entry: {Nr, "name", "description"}
categories() ->
    [
        {network, [
            {41,  "socket",       "Create socket"},
            {42,  "connect",      "Connect to address"},
            {49,  "bind",         "Bind socket"},
            {50,  "listen",       "Listen on socket"},
            {43,  "accept",       "Accept connection"},
            {44,  "sendto",       "Send data"},
            {45,  "recvfrom",     "Receive data"},
            {48,  "shutdown",     "Shutdown socket"},
            {54,  "setsockopt",   "Set socket option"},
            {55,  "getsockopt",   "Get socket option"},
            {288, "accept4",      "Accept4 connection"}
        ]},
        {filesystem, [
            {257, "openat",       "Open file relative to dirfd"},
            {3,   "close",        "Close file descriptor"},
            {0,   "read",         "Read from fd"},
            {1,   "write",        "Write to fd"},
            {262, "newfstatat",   "Stat file"},
            {217, "getdents64",   "Read directory entries"},
            {263, "unlinkat",     "Remove file"},
            {83,  "mkdir",        "Create directory"},
            {84,  "rmdir",        "Remove directory"},
            {82,  "rename",       "Rename file"},
            {8,   "lseek",        "Seek in file"},
            {72,  "fcntl",        "File control"},
            {285, "fallocate",    "Allocate file space"},
            {332, "statx",        "Extended stat"},
            {439, "faccessat2",   "Check file access"}
        ]},
        {process, [
            {39,  "getpid",       "Get process ID"},
            {110, "getppid",      "Get parent PID"},
            {102, "getuid",       "Get user ID"},
            {104, "getgid",       "Get group ID"},
            {186, "gettid",       "Get thread ID"},
            {63,  "uname",        "Get system info"},
            {157, "prctl",        "Process control"},
            {158, "arch_prctl",   "Arch-specific prctl"},
            {61,  "wait4",        "Wait for process"},
            {247, "waitid",       "Wait for process (extended)"},
            {272, "unshare",      "Unshare namespaces"},
            {302, "prlimit64",    "Get/set resource limits"},
            {435, "clone3",       "Clone process (v3)"}
        ]},
        {memory, [
            {9,   "mmap",         "Map memory"},
            {11,  "munmap",       "Unmap memory"},
            {10,  "mprotect",     "Set memory protection"},
            {12,  "brk",          "Change data segment size"},
            {28,  "madvise",      "Advise on memory usage"},
            {25,  "mremap",       "Remap memory"},
            {149, "mlock",        "Lock memory"},
            {150, "munlock",      "Unlock memory"},
            {319, "memfd_create", "Create anonymous file"},
            {329, "pkey_mprotect", "Pkey memory protect"}
        ]},
        {ipc, [
            {22,  "pipe",         "Create pipe"},
            {293, "pipe2",        "Create pipe with flags"},
            {202, "futex",        "Fast userspace mutex"},
            {290, "eventfd2",     "Create event fd"},
            {29,  "shmget",       "Get shared memory"},
            {64,  "semget",       "Get semaphore"},
            {68,  "msgget",       "Get message queue"},
            {240, "mq_open",      "Open message queue"}
        ]},
        {signal, [
            {13,  "rt_sigaction",    "Set signal handler"},
            {14,  "rt_sigprocmask",  "Block/unblock signals"},
            {62,  "kill",            "Send signal"},
            {200, "tkill",           "Thread-directed signal"},
            {234, "tgkill",          "Thread group signal"},
            {131, "sigaltstack",     "Set alternate signal stack"},
            {37,  "alarm",           "Set alarm timer"}
        ]},
        {time, [
            {228, "clock_gettime",   "Get clock time"},
            {229, "clock_getres",    "Get clock resolution"},
            {35,  "nanosleep",       "High-res sleep"},
            {96,  "gettimeofday",    "Get time of day"},
            {222, "timer_create",    "Create POSIX timer"},
            {283, "timerfd_create",  "Create timer fd"},
            {201, "time",            "Get time in seconds"}
        ]},
        {io_multiplex, [
            {232, "epoll_wait",      "Wait for epoll events"},
            {233, "epoll_ctl",       "Control epoll"},
            {291, "epoll_create1",   "Create epoll fd"},
            {281, "epoll_pwait",     "Epoll wait with sigmask"},
            {253, "inotify_init",    "Init inotify"},
            {294, "inotify_init1",   "Init inotify with flags"},
            {425, "io_uring_setup",  "Setup io_uring"},
            {426, "io_uring_enter",  "Submit/wait io_uring"}
        ]},
        {security, [
            {317, "seccomp",               "Seccomp filter"},
            {321, "bpf",                   "BPF operations"},
            {125, "capget",                "Get capabilities"},
            {126, "capset",                "Set capabilities"},
            {444, "landlock_create_ruleset", "Landlock create"},
            {445, "landlock_add_rule",      "Landlock add rule"},
            {446, "landlock_restrict_self", "Landlock restrict"},
            {318, "getrandom",             "Get random bytes"}
        ]},
        {system, [
            {165, "mount",         "Mount filesystem"},
            {166, "umount2",       "Unmount filesystem"},
            {161, "chroot",        "Change root"},
            {155, "pivot_root",    "Pivot root"},
            {308, "setns",         "Set namespace"},
            {162, "sync",          "Sync filesystems"},
            {434, "pidfd_open",    "Open process fd"},
            {436, "close_range",   "Close fd range"},
            {462, "mseal",         "Memory seal"}
        ]}
    ].
