-module(elf_seccomp_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("elf_parse.hrl").
-include("elf_seccomp.hrl").

%% ---------------------------------------------------------------------------
%% Test ELF binary construction helpers (same as elf_syscall_test)
%% ---------------------------------------------------------------------------

-define(TEXT_VADDR, 16#400000).

make_elf(Machine, TextContent) ->
    TextOff = 16#078,
    TextSize = byte_size(TextContent),
    StrTab = <<0, ".text", 0, ".shstrtab", 0>>,
    StrTabSize = byte_size(StrTab),
    StrtabOff = TextOff + TextSize,
    ShdrOff0 = StrtabOff + StrTabSize,
    ShdrOff = (ShdrOff0 + 7) band (bnot 7),
    PadSize = ShdrOff - ShdrOff0,
    Header = elf_header_le(
        ?ET_EXEC,
        Machine,
        ?TEXT_VADDR,
        64,
        ShdrOff,
        1,
        3,
        2
    ),
    Phdr = phdr_le(
        ?PT_LOAD,
        ?PF_R bor ?PF_X,
        TextOff,
        ?TEXT_VADDR,
        ?TEXT_VADDR,
        TextSize,
        TextSize,
        16#1000
    ),
    Shdr0 = shdr_le(0, ?SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0),
    Shdr1 = shdr_le(
        1,
        ?SHT_PROGBITS,
        ?SHF_ALLOC bor ?SHF_EXECINSTR,
        ?TEXT_VADDR,
        TextOff,
        TextSize,
        0,
        0,
        16,
        0
    ),
    Shdr2 = shdr_le(7, ?SHT_STRTAB, 0, 0, StrtabOff, StrTabSize, 0, 0, 1, 0),
    Pad = <<0:(PadSize * 8)>>,
    <<Header/binary, Phdr/binary, TextContent/binary, StrTab/binary, Pad/binary, Shdr0/binary,
        Shdr1/binary, Shdr2/binary>>.

x86_64_syscall_seq(Nr) ->
    <<16#B8, Nr:32/little, 16#0F, 16#05>>.

elf_header_le(Type, Machine, Entry, PhOff, ShOff, PhNum, ShNum, ShStrNdx) ->
    <<16#7F, "ELF", 2:8, 1:8, 1:8, 0:8, 0:64, Type:16/little, Machine:16/little, 1:32/little,
        Entry:64/little, PhOff:64/little, ShOff:64/little, 0:32/little, 64:16/little, 56:16/little,
        PhNum:16/little, 64:16/little, ShNum:16/little, ShStrNdx:16/little>>.

phdr_le(PType, PFlags, POffset, PVaddr, PPaddr, PFilesz, PMemsz, PAlign) ->
    <<PType:32/little, PFlags:32/little, POffset:64/little, PVaddr:64/little, PPaddr:64/little,
        PFilesz:64/little, PMemsz:64/little, PAlign:64/little>>.

shdr_le(
    ShName,
    ShType,
    ShFlags,
    ShAddr,
    ShOffset,
    ShSize,
    ShLink,
    ShInfo,
    ShAddralign,
    ShEntsize
) ->
    <<ShName:32/little, ShType:32/little, ShFlags:64/little, ShAddr:64/little, ShOffset:64/little,
        ShSize:64/little, ShLink:32/little, ShInfo:32/little, ShAddralign:64/little,
        ShEntsize:64/little>>.

%% ===========================================================================
%% from_syscalls tests
%% ===========================================================================

from_syscalls_basic_test() ->
    Profile = elf_seccomp:from_syscalls(x86_64, [0, 1, 60, 231]),
    ?assertEqual(x86_64, Profile#seccomp_profile.arch),
    ?assertEqual(kill_process, Profile#seccomp_profile.default_action),
    ?assertEqual([0, 1, 60, 231], Profile#seccomp_profile.syscalls),
    ?assert(lists:member(<<"read">>, Profile#seccomp_profile.names)),
    ?assert(lists:member(<<"write">>, Profile#seccomp_profile.names)),
    ?assert(lists:member(<<"exit">>, Profile#seccomp_profile.names)),
    ?assert(lists:member(<<"exit_group">>, Profile#seccomp_profile.names)),
    ?assertEqual(0, Profile#seccomp_profile.unresolved).

from_syscalls_aarch64_test() ->
    Profile = elf_seccomp:from_syscalls(aarch64, [63, 64, 93]),
    ?assertEqual(aarch64, Profile#seccomp_profile.arch),
    ?assert(lists:member(<<"read">>, Profile#seccomp_profile.names)),
    ?assert(lists:member(<<"write">>, Profile#seccomp_profile.names)),
    ?assert(lists:member(<<"exit">>, Profile#seccomp_profile.names)).

from_syscalls_unresolved_test() ->
    %% Syscall 99999 doesn't exist in the database
    Profile = elf_seccomp:from_syscalls(x86_64, [1, 99999]),
    ?assertEqual(1, Profile#seccomp_profile.unresolved),
    ?assertEqual([1, 99999], Profile#seccomp_profile.syscalls),
    ?assertEqual([<<"write">>], Profile#seccomp_profile.names).

%% ===========================================================================
%% to_json tests
%% ===========================================================================

to_json_structure_test() ->
    Profile = elf_seccomp:from_syscalls(x86_64, [0, 1, 60]),
    Json = iolist_to_binary(elf_seccomp:to_json(Profile)),
    %% Check required fields are present
    ?assertNotEqual(nomatch, binary:match(Json, <<"defaultAction">>)),
    ?assertNotEqual(nomatch, binary:match(Json, <<"SCMP_ACT_KILL_PROCESS">>)),
    ?assertNotEqual(nomatch, binary:match(Json, <<"SCMP_ARCH_X86_64">>)),
    ?assertNotEqual(nomatch, binary:match(Json, <<"SCMP_ACT_ALLOW">>)),
    ?assertNotEqual(nomatch, binary:match(Json, <<"architectures">>)),
    ?assertNotEqual(nomatch, binary:match(Json, <<"syscalls">>)),
    %% Check syscall names are present
    ?assertNotEqual(nomatch, binary:match(Json, <<"read">>)),
    ?assertNotEqual(nomatch, binary:match(Json, <<"write">>)),
    ?assertNotEqual(nomatch, binary:match(Json, <<"exit">>)).

to_json_aarch64_test() ->
    Profile = elf_seccomp:from_syscalls(aarch64, [63]),
    Json = iolist_to_binary(elf_seccomp:to_json(Profile)),
    ?assertNotEqual(nomatch, binary:match(Json, <<"SCMP_ARCH_AARCH64">>)).

to_json_empty_test() ->
    Profile = elf_seccomp:from_syscalls(x86_64, []),
    Json = iolist_to_binary(elf_seccomp:to_json(Profile)),
    ?assertNotEqual(nomatch, binary:match(Json, <<"SCMP_ACT_KILL_PROCESS">>)),
    ?assertNotEqual(nomatch, binary:match(Json, <<"SCMP_ACT_ALLOW">>)).

%% ===========================================================================
%% to_bpf tests
%% ===========================================================================

to_bpf_first_insn_is_load_test() ->
    Profile = elf_seccomp:from_syscalls(x86_64, [1, 60]),
    Bpf = elf_seccomp:to_bpf(Profile),
    %% First instruction: BPF_LD | BPF_W | BPF_ABS, K=0
    <<Code:16/little, 0:8, 0:8, 0:32/little, _/binary>> = Bpf,
    %% BPF_LD | BPF_W | BPF_ABS
    ?assertEqual(16#20, Code).

to_bpf_last_insn_is_allow_test() ->
    Profile = elf_seccomp:from_syscalls(x86_64, [1, 60]),
    Bpf = elf_seccomp:to_bpf(Profile),
    Size = byte_size(Bpf),
    %% Last 8 bytes should be RET ALLOW
    <<_:(Size - 8)/binary, Code:16/little, 0:8, 0:8, K:32/little>> = Bpf,
    %% BPF_RET
    ?assertEqual(16#06, Code),
    %% SECCOMP_RET_ALLOW
    ?assertEqual(16#7FFF0000, K).

to_bpf_second_to_last_is_deny_test() ->
    Profile = elf_seccomp:from_syscalls(x86_64, [1, 60]),
    Bpf = elf_seccomp:to_bpf(Profile),
    Size = byte_size(Bpf),
    %% Second to last 8 bytes should be RET KILL_PROCESS
    <<_:(Size - 16)/binary, Code:16/little, 0:8, 0:8, K:32/little, _:8/binary>> = Bpf,
    %% BPF_RET
    ?assertEqual(16#06, Code),
    %% SECCOMP_RET_KILL_PROCESS
    ?assertEqual(16#80000000, K).

to_bpf_linear_length_test() ->
    %% For N syscalls (linear): 1 LD + N JEQ + 1 DENY + 1 ALLOW = N + 3
    Profile = elf_seccomp:from_syscalls(x86_64, [1, 60, 231]),
    Bpf = elf_seccomp:to_bpf(Profile),
    %% 3 syscalls + 3 overhead = 6 instructions * 8 bytes
    ExpectedLen = (3 + 3) * 8,
    ?assertEqual(ExpectedLen, byte_size(Bpf)).

to_bpf_single_syscall_test() ->
    Profile = elf_seccomp:from_syscalls(x86_64, [1]),
    Bpf = elf_seccomp:to_bpf(Profile),
    %% 1 LD + 1 JEQ + 1 DENY + 1 ALLOW = 4 instructions
    ?assertEqual(4 * 8, byte_size(Bpf)),
    %% Verify the JEQ checks for syscall 1

    %% skip LD
    <<_:8/binary, JeqCode:16/little, Jt:8, _Jf:8, Nr:32/little, _/binary>> = Bpf,
    %% BPF_JMP | BPF_JEQ | BPF_K
    ?assertEqual(16#15, JeqCode),
    %% syscall number
    ?assertEqual(1, Nr),
    %% jump over DENY to ALLOW
    ?assertEqual(1, Jt).

to_bpf_empty_test() ->
    Profile = elf_seccomp:from_syscalls(x86_64, []),
    Bpf = elf_seccomp:to_bpf(Profile),
    %% 1 LD + 1 DENY + 1 ALLOW = 3 instructions
    ?assertEqual(3 * 8, byte_size(Bpf)).

to_bpf_bst_kicks_in_test() ->
    %% Generate >20 syscalls to trigger BST mode
    Nrs = lists:seq(0, 25),
    Profile = elf_seccomp:from_syscalls(x86_64, Nrs),
    Bpf = elf_seccomp:to_bpf(Profile),
    N = length(Nrs),
    %% BST should produce more instructions than linear would
    %% Linear would be N + 3 instructions. BST uses JGE nodes + JEQ leaves.
    %% The BST has more total instructions due to JGE branching nodes.
    LinearSize = (N + 3) * 8,
    BstSize = byte_size(Bpf),
    ?assert(BstSize > LinearSize),
    %% First instruction is still LD
    <<Code:16/little, 0:8, 0:8, 0:32/little, _/binary>> = Bpf,
    ?assertEqual(16#20, Code),
    %% Last instruction is still RET ALLOW
    <<_:(BstSize - 8)/binary, RetCode:16/little, 0:8, 0:8, K:32/little>> = Bpf,
    ?assertEqual(16#06, RetCode),
    ?assertEqual(16#7FFF0000, K).

to_bpf_linear_at_threshold_test() ->
    %% Exactly 20 syscalls should use linear (not BST)
    Nrs = lists:seq(0, 19),
    Profile = elf_seccomp:from_syscalls(x86_64, Nrs),
    Bpf = elf_seccomp:to_bpf(Profile),
    %% Linear: 1 LD + 20 JEQ + 1 DENY + 1 ALLOW = 23 instructions
    ?assertEqual(23 * 8, byte_size(Bpf)).

%% ===========================================================================
%% to_erlang tests
%% ===========================================================================

to_erlang_test() ->
    Profile = elf_seccomp:from_syscalls(x86_64, [0, 1]),
    Map = elf_seccomp:to_erlang(Profile),
    ?assertEqual(x86_64, maps:get(arch, Map)),
    ?assertEqual(kill_process, maps:get(default_action, Map)),
    ?assertEqual([0, 1], maps:get(syscalls, Map)),
    ?assertEqual(0, maps:get(unresolved, Map)).

%% ===========================================================================
%% from_binary tests
%% ===========================================================================

from_binary_x86_64_test() ->
    Text = <<(x86_64_syscall_seq(1))/binary, (x86_64_syscall_seq(231))/binary>>,
    Bin = make_elf(?EM_X86_64, Text),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Profile} = elf_seccomp:from_binary(Elf),
    ?assertEqual(x86_64, Profile#seccomp_profile.arch),
    ?assertEqual(kill_process, Profile#seccomp_profile.default_action),
    ?assert(lists:member(1, Profile#seccomp_profile.syscalls)),
    ?assert(lists:member(231, Profile#seccomp_profile.syscalls)),
    ?assert(lists:member(<<"write">>, Profile#seccomp_profile.names)),
    ?assert(lists:member(<<"exit_group">>, Profile#seccomp_profile.names)).

from_binary_unsupported_arch_test() ->
    Text = <<16#90, 16#90, 16#90, 16#C3>>,
    Bin = make_elf(?EM_ARM, Text),
    {ok, Elf} = elf_parse:from_binary(Bin),
    ?assertEqual({error, unsupported_arch}, elf_seccomp:from_binary(Elf)).

%% ===========================================================================
%% analyze_to_json tests
%% ===========================================================================

analyze_to_json_test() ->
    Text = <<(x86_64_syscall_seq(1))/binary, (x86_64_syscall_seq(60))/binary>>,
    Bin = make_elf(?EM_X86_64, Text),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Json} = elf_seccomp:analyze_to_json(Elf),
    JsonBin = iolist_to_binary(Json),
    ?assertNotEqual(nomatch, binary:match(JsonBin, <<"write">>)),
    ?assertNotEqual(nomatch, binary:match(JsonBin, <<"exit">>)).

analyze_to_json_error_test() ->
    Text = <<16#90, 16#C3>>,
    Bin = make_elf(?EM_ARM, Text),
    {ok, Elf} = elf_parse:from_binary(Bin),
    ?assertEqual({error, unsupported_arch}, elf_seccomp:analyze_to_json(Elf)).

%% ===========================================================================
%% BPF correctness: verify jump targets
%% ===========================================================================

bpf_linear_jump_correctness_test() ->
    %% For 3 syscalls [1, 60, 231], verify each JEQ jumps to ALLOW correctly
    Profile = elf_seccomp:from_syscalls(x86_64, [1, 60, 231]),
    Bpf = elf_seccomp:to_bpf(Profile),
    %% Layout: LD, JEQ(1), JEQ(60), JEQ(231), DENY, ALLOW
    %% Indices: 0,  1,      2,       3,        4,    5
    %% JEQ at 1: jt should be 4 (skip to 5 = ALLOW, relative = 5-1-1=3... wait)
    %% Actually: jt = number of remaining JEQs + deny = instructions to skip
    %% JEQ at idx 1: need to reach idx 5 (ALLOW), relative jt = 5-1-1 = 3? No.
    %% BPF jump is relative to NEXT instruction. From idx 1, jt=N-i where i=0-based
    %% among JEQs and N=3. So jt for first JEQ = 3, second = 2, third = 1.

    %% Parse instruction at offset 8 (JEQ #1, for syscall 1)
    <<_:8/binary, _:16/little, Jt1:8, _:8, Nr1:32/little, _:16/little, Jt2:8, _:8, Nr2:32/little,
        _:16/little, Jt3:8, _:8, Nr3:32/little, _/binary>> = Bpf,
    ?assertEqual(1, Nr1),
    ?assertEqual(60, Nr2),
    ?assertEqual(231, Nr3),
    %% jump over 2 more JEQs + DENY = 3
    ?assertEqual(3, Jt1),
    %% jump over 1 more JEQ + DENY = 2
    ?assertEqual(2, Jt2),
    %% jump over DENY = 1
    ?assertEqual(1, Jt3).
