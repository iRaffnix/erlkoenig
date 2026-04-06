-module(elf_seccomp_prop_test).
-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("elf_seccomp.hrl").

%% ---------------------------------------------------------------------------
%% Generators
%% ---------------------------------------------------------------------------

%% x86_64 syscall numbers range from 0 to 462.
syscall_nr() ->
    integer(0, 462).

syscall_list() ->
    list(syscall_nr()).

%% ---------------------------------------------------------------------------
%% Properties
%% ---------------------------------------------------------------------------

%% Property 1: BPF bytecode length is always a multiple of 8 bytes.
%% Each BPF instruction is exactly 8 bytes (struct sock_filter).
prop_bpf_length_multiple_of_8() ->
    ?FORALL(
        Nrs,
        syscall_list(),
        begin
            Profile = elf_seccomp:from_syscalls(x86_64, Nrs),
            Bpf = elf_seccomp:to_bpf(Profile),
            byte_size(Bpf) rem 8 =:= 0
        end
    ).

%% Property 2: Generated JSON is valid (starts with '{', ends with '}').
prop_json_valid_braces() ->
    ?FORALL(
        Nrs,
        syscall_list(),
        begin
            Profile = elf_seccomp:from_syscalls(x86_64, Nrs),
            Json = iolist_to_binary(elf_seccomp:to_json(Profile)),
            byte_size(Json) > 0 andalso
                binary:first(Json) =:= ${ andalso
                binary:last(Json) =:= $}
        end
    ).

%% Property 3: BPF always starts with LD instruction and ends with RET ALLOW.
prop_bpf_structure() ->
    ?FORALL(
        Nrs,
        syscall_list(),
        begin
            Profile = elf_seccomp:from_syscalls(x86_64, Nrs),
            Bpf = elf_seccomp:to_bpf(Profile),
            Size = byte_size(Bpf),
            %% First instruction: BPF_LD | BPF_W | BPF_ABS (0x20)
            <<FirstCode:16/little, _:16, _:32, _/binary>> = Bpf,
            %% Last instruction: BPF_RET (0x06) with SECCOMP_RET_ALLOW
            <<_:(Size - 8)/binary, LastCode:16/little, _:16, LastK:32/little>> = Bpf,
            FirstCode =:= 16#20 andalso
                LastCode =:= 16#06 andalso
                LastK =:= 16#7FFF0000
        end
    ).

%% Property 4: Roundtrip through from_syscalls -> to_erlang preserves syscall set.
prop_roundtrip_syscalls() ->
    ?FORALL(
        Nrs,
        syscall_list(),
        begin
            Sorted = lists:usort(Nrs),
            Profile = elf_seccomp:from_syscalls(x86_64, Nrs),
            Map = elf_seccomp:to_erlang(Profile),
            maps:get(syscalls, Map) =:= Sorted
        end
    ).

%% ---------------------------------------------------------------------------
%% EUnit wrappers
%% ---------------------------------------------------------------------------

bpf_length_multiple_of_8_test() ->
    ?assert(
        proper:quickcheck(
            prop_bpf_length_multiple_of_8(),
            [{numtests, 200}, {to_file, user}]
        )
    ).

json_valid_braces_test() ->
    ?assert(
        proper:quickcheck(
            prop_json_valid_braces(),
            [{numtests, 200}, {to_file, user}]
        )
    ).

bpf_structure_test() ->
    ?assert(
        proper:quickcheck(
            prop_bpf_structure(),
            [{numtests, 200}, {to_file, user}]
        )
    ).

roundtrip_syscalls_test() ->
    ?assert(
        proper:quickcheck(
            prop_roundtrip_syscalls(),
            [{numtests, 200}, {to_file, user}]
        )
    ).
