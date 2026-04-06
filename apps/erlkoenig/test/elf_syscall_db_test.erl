-module(elf_syscall_db_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%% ---------------------------------------------------------------------------
%% name/2
%% ---------------------------------------------------------------------------

name_x86_64_known_test() ->
    ?assertEqual({ok, <<"read">>}, elf_syscall_db:name(x86_64, 0)),
    ?assertEqual({ok, <<"write">>}, elf_syscall_db:name(x86_64, 1)),
    ?assertEqual({ok, <<"open">>}, elf_syscall_db:name(x86_64, 2)),
    ?assertEqual({ok, <<"close">>}, elf_syscall_db:name(x86_64, 3)),
    ?assertEqual({ok, <<"mmap">>}, elf_syscall_db:name(x86_64, 9)),
    ?assertEqual({ok, <<"clone">>}, elf_syscall_db:name(x86_64, 56)),
    ?assertEqual({ok, <<"execve">>}, elf_syscall_db:name(x86_64, 59)),
    ?assertEqual({ok, <<"exit">>}, elf_syscall_db:name(x86_64, 60)),
    ?assertEqual({ok, <<"openat">>}, elf_syscall_db:name(x86_64, 257)),
    ?assertEqual({ok, <<"clone3">>}, elf_syscall_db:name(x86_64, 435)).

name_aarch64_known_test() ->
    ?assertEqual({ok, <<"openat">>}, elf_syscall_db:name(aarch64, 56)),
    ?assertEqual({ok, <<"close">>}, elf_syscall_db:name(aarch64, 57)),
    ?assertEqual({ok, <<"read">>}, elf_syscall_db:name(aarch64, 63)),
    ?assertEqual({ok, <<"write">>}, elf_syscall_db:name(aarch64, 64)),
    ?assertEqual({ok, <<"exit">>}, elf_syscall_db:name(aarch64, 93)),
    ?assertEqual({ok, <<"socket">>}, elf_syscall_db:name(aarch64, 198)),
    ?assertEqual({ok, <<"clone3">>}, elf_syscall_db:name(aarch64, 435)).

name_unknown_test() ->
    ?assertEqual(error, elf_syscall_db:name(x86_64, 99999)),
    ?assertEqual(error, elf_syscall_db:name(aarch64, 99999)).

name_unsupported_arch_test() ->
    ?assertEqual(error, elf_syscall_db:name(riscv, 0)).

%% ---------------------------------------------------------------------------
%% number/2
%% ---------------------------------------------------------------------------

number_x86_64_test() ->
    ?assertEqual({ok, 0}, elf_syscall_db:number(x86_64, <<"read">>)),
    ?assertEqual({ok, 1}, elf_syscall_db:number(x86_64, <<"write">>)),
    ?assertEqual({ok, 59}, elf_syscall_db:number(x86_64, <<"execve">>)),
    ?assertEqual({ok, 257}, elf_syscall_db:number(x86_64, <<"openat">>)).

number_aarch64_test() ->
    ?assertEqual({ok, 63}, elf_syscall_db:number(aarch64, <<"read">>)),
    ?assertEqual({ok, 64}, elf_syscall_db:number(aarch64, <<"write">>)),
    ?assertEqual({ok, 221}, elf_syscall_db:number(aarch64, <<"execve">>)).

number_unknown_test() ->
    ?assertEqual(error, elf_syscall_db:number(x86_64, <<"nonexistent_syscall">>)).

%% ---------------------------------------------------------------------------
%% all/1
%% ---------------------------------------------------------------------------

all_x86_64_nonempty_test() ->
    List = elf_syscall_db:all(x86_64),
    ?assert(length(List) > 50),
    %% Sorted by number
    Nrs = [Nr || {Nr, _} <- List],
    ?assertEqual(Nrs, lists:sort(Nrs)),
    %% Contains known entries
    ?assert(lists:member({0, <<"read">>}, List)),
    ?assert(lists:member({59, <<"execve">>}, List)).

all_aarch64_nonempty_test() ->
    List = elf_syscall_db:all(aarch64),
    ?assert(length(List) > 30).

all_unsupported_test() ->
    ?assertEqual([], elf_syscall_db:all(riscv)).

%% ---------------------------------------------------------------------------
%% category/1
%% ---------------------------------------------------------------------------

category_network_test() ->
    ?assertEqual(network, elf_syscall_db:category(<<"socket">>)),
    ?assertEqual(network, elf_syscall_db:category(<<"connect">>)),
    ?assertEqual(network, elf_syscall_db:category(<<"bind">>)),
    ?assertEqual(network, elf_syscall_db:category(<<"listen">>)),
    ?assertEqual(network, elf_syscall_db:category(<<"accept">>)),
    ?assertEqual(network, elf_syscall_db:category(<<"sendto">>)),
    ?assertEqual(network, elf_syscall_db:category(<<"recvfrom">>)),
    ?assertEqual(network, elf_syscall_db:category(<<"setsockopt">>)),
    ?assertEqual(network, elf_syscall_db:category(<<"getsockopt">>)).

category_filesystem_test() ->
    ?assertEqual(filesystem, elf_syscall_db:category(<<"open">>)),
    ?assertEqual(filesystem, elf_syscall_db:category(<<"openat">>)),
    ?assertEqual(filesystem, elf_syscall_db:category(<<"read">>)),
    ?assertEqual(filesystem, elf_syscall_db:category(<<"write">>)),
    ?assertEqual(filesystem, elf_syscall_db:category(<<"close">>)),
    ?assertEqual(filesystem, elf_syscall_db:category(<<"chmod">>)),
    ?assertEqual(filesystem, elf_syscall_db:category(<<"unlink">>)).

category_process_test() ->
    ?assertEqual(process, elf_syscall_db:category(<<"clone">>)),
    ?assertEqual(process, elf_syscall_db:category(<<"fork">>)),
    ?assertEqual(process, elf_syscall_db:category(<<"execve">>)),
    ?assertEqual(process, elf_syscall_db:category(<<"exit">>)),
    ?assertEqual(process, elf_syscall_db:category(<<"prctl">>)).

category_memory_test() ->
    ?assertEqual(memory, elf_syscall_db:category(<<"mmap">>)),
    ?assertEqual(memory, elf_syscall_db:category(<<"munmap">>)),
    ?assertEqual(memory, elf_syscall_db:category(<<"mprotect">>)),
    ?assertEqual(memory, elf_syscall_db:category(<<"brk">>)).

category_ipc_test() ->
    ?assertEqual(ipc, elf_syscall_db:category(<<"pipe">>)),
    ?assertEqual(ipc, elf_syscall_db:category(<<"futex">>)),
    ?assertEqual(ipc, elf_syscall_db:category(<<"eventfd2">>)).

category_signal_test() ->
    ?assertEqual(signal, elf_syscall_db:category(<<"rt_sigaction">>)),
    ?assertEqual(signal, elf_syscall_db:category(<<"rt_sigprocmask">>)),
    ?assertEqual(signal, elf_syscall_db:category(<<"kill">>)),
    ?assertEqual(signal, elf_syscall_db:category(<<"tkill">>)).

category_time_test() ->
    ?assertEqual(time, elf_syscall_db:category(<<"clock_gettime">>)),
    ?assertEqual(time, elf_syscall_db:category(<<"nanosleep">>)),
    ?assertEqual(time, elf_syscall_db:category(<<"gettimeofday">>)).

category_io_test() ->
    ?assertEqual(io, elf_syscall_db:category(<<"epoll_wait">>)),
    ?assertEqual(io, elf_syscall_db:category(<<"epoll_ctl">>)),
    ?assertEqual(io, elf_syscall_db:category(<<"epoll_create1">>)),
    ?assertEqual(io, elf_syscall_db:category(<<"select">>)).

category_other_test() ->
    ?assertEqual(other, elf_syscall_db:category(<<"unknown">>)),
    ?assertEqual(other, elf_syscall_db:category(<<"totally_made_up">>)).
