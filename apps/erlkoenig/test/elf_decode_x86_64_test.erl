-module(elf_decode_x86_64_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%% We need the record definition — replicate it here since the module
%% doesn't export a header.
-record(x86_insn, {
    offset :: non_neg_integer(),
    length :: pos_integer(),
    type :: atom(),
    value :: integer() | undefined
}).

%% ===================================================================
%% SYSCALL detection
%% ===================================================================

syscall_basic_test() ->
    Bin = <<16#0F, 16#05>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(syscall, I#x86_insn.type),
    ?assertEqual(2, I#x86_insn.length),
    ?assertEqual(0, I#x86_insn.offset).

syscall_at_offset_test() ->
    Bin = <<16#90, 16#90, 16#0F, 16#05>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 2),
    ?assertEqual(syscall, I#x86_insn.type),
    ?assertEqual(2, I#x86_insn.offset).

find_syscalls_test() ->
    %% NOP, SYSCALL, NOP, SYSCALL
    Bin = <<16#90, 16#0F, 16#05, 16#90, 16#0F, 16#05>>,
    Offsets = elf_decode_x86_64:find_syscalls(Bin),
    ?assertEqual([1, 4], Offsets).

%% ===================================================================
%% MOV EAX, imm32
%% ===================================================================

mov_eax_imm32_test() ->
    %% B8 3C 00 00 00 = MOV EAX, 60
    Bin = <<16#B8, 60:32/little>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(mov_rax_imm, I#x86_insn.type),
    ?assertEqual(60, I#x86_insn.value),
    ?assertEqual(5, I#x86_insn.length).

mov_eax_imm32_syscall_1_test() ->
    %% MOV EAX, 1 (write)
    Bin = <<16#B8, 1:32/little>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(1, I#x86_insn.value).

mov_ecx_imm32_test() ->
    %% B9 xx xx xx xx = MOV ECX, imm32 — not RAX
    Bin = <<16#B9, 42:32/little>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(other, I#x86_insn.type),
    ?assertEqual(5, I#x86_insn.length).

%% ===================================================================
%% REX-prefixed instructions
%% ===================================================================

rex_w_mov_rax_imm64_test() ->
    %% 48 B8 imm64 = MOV RAX, imm64
    Bin = <<16#48, 16#B8, 231:64/little>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(mov_rax_imm, I#x86_insn.type),
    ?assertEqual(231, I#x86_insn.value),
    %% REX(1) + B8(1) + imm64(8)
    ?assertEqual(10, I#x86_insn.length).

rex_w_mov_rax_sign_ext_imm32_test() ->
    %% 48 C7 C0 3C 00 00 00 = MOV RAX, 60
    Bin = <<16#48, 16#C7, 16#C0, 60:32/little>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(mov_rax_imm, I#x86_insn.type),
    ?assertEqual(60, I#x86_insn.value),
    ?assertEqual(7, I#x86_insn.length).

rex_w_xor_rax_rax_test() ->
    %% 48 31 C0 = XOR RAX, RAX
    Bin = <<16#48, 16#31, 16#C0>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(xor_rax_rax, I#x86_insn.type),
    ?assertEqual(3, I#x86_insn.length).

%% ===================================================================
%% XOR EAX, EAX
%% ===================================================================

xor_eax_eax_test() ->
    %% 31 C0 = XOR EAX, EAX
    Bin = <<16#31, 16#C0>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(xor_rax_rax, I#x86_insn.type),
    ?assertEqual(2, I#x86_insn.length).

xor_eax_eax_opcode33_test() ->
    %% 33 C0 = XOR EAX, EAX (alternate encoding)
    Bin = <<16#33, 16#C0>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(xor_rax_rax, I#x86_insn.type).

xor_ecx_ecx_not_rax_test() ->
    %% 31 C9 = XOR ECX, ECX — should be other, not xor_rax_rax
    Bin = <<16#31, 16#C9>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(other, I#x86_insn.type),
    ?assertEqual(2, I#x86_insn.length).

%% ===================================================================
%% Control flow
%% ===================================================================

ret_test() ->
    Bin = <<16#C3>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(ret, I#x86_insn.type),
    ?assertEqual(1, I#x86_insn.length).

ret_imm16_test() ->
    Bin = <<16#C2, 8:16/little>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(ret, I#x86_insn.type),
    ?assertEqual(3, I#x86_insn.length).

call_rel32_test() ->
    Bin = <<16#E8, 0:32/little>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(call, I#x86_insn.type),
    ?assertEqual(5, I#x86_insn.length).

jmp_rel32_test() ->
    Bin = <<16#E9, 0:32/little>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(jmp, I#x86_insn.type),
    ?assertEqual(5, I#x86_insn.length).

jmp_rel8_test() ->
    Bin = <<16#EB, 16#FE>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(jmp, I#x86_insn.type),
    ?assertEqual(2, I#x86_insn.length).

jcc_rel8_test() ->
    %% 74 xx = JE rel8
    Bin = <<16#74, 16#10>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(jcc, I#x86_insn.type),
    ?assertEqual(2, I#x86_insn.length).

jcc_rel32_test() ->
    %% 0F 84 xx xx xx xx = JE rel32
    Bin = <<16#0F, 16#84, 0:32/little>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(jcc, I#x86_insn.type),
    ?assertEqual(6, I#x86_insn.length).

call_indirect_test() ->
    %% FF 15 xx xx xx xx = CALL [rip+disp32]
    Bin = <<16#FF, 16#15, 0:32/little>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(call, I#x86_insn.type),
    ?assertEqual(6, I#x86_insn.length).

jmp_indirect_test() ->
    %% FF 25 xx xx xx xx = JMP [rip+disp32]
    Bin = <<16#FF, 16#25, 0:32/little>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(jmp, I#x86_insn.type),
    ?assertEqual(6, I#x86_insn.length).

%% ===================================================================
%% ModR/M + SIB + Displacement length calculation
%% ===================================================================

modrm_reg_reg_test() ->
    %% 89 C1 = MOV ECX, EAX (mod=11, rm=001, reg=000)
    Bin = <<16#89, 16#C1>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(2, I#x86_insn.length).

modrm_rip_relative_test() ->
    %% 8B 05 xx xx xx xx = MOV EAX, [rip+disp32] (mod=00, rm=101)
    Bin = <<16#8B, 16#05, 0:32/little>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(6, I#x86_insn.length).

modrm_disp8_test() ->
    %% 8B 40 10 = MOV EAX, [RAX+0x10] (mod=01, rm=000, disp8)
    Bin = <<16#8B, 16#40, 16#10>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(3, I#x86_insn.length).

modrm_disp32_test() ->
    %% 8B 80 xx xx xx xx = MOV EAX, [RAX+disp32] (mod=10, rm=000)
    Bin = <<16#8B, 16#80, 0:32/little>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(6, I#x86_insn.length).

modrm_sib_no_disp_test() ->
    %% 8B 04 24 = MOV EAX, [RSP] (mod=00, rm=100 → SIB, SIB=0x24: base=RSP, index=none)
    Bin = <<16#8B, 16#04, 16#24>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(3, I#x86_insn.length).

modrm_sib_disp8_test() ->
    %% 8B 44 24 08 = MOV EAX, [RSP+8] (mod=01, rm=100 → SIB, disp8)
    Bin = <<16#8B, 16#44, 16#24, 16#08>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(4, I#x86_insn.length).

modrm_sib_disp32_test() ->
    %% 8B 84 24 xx xx xx xx = MOV EAX, [RSP+disp32] (mod=10, rm=100 → SIB, disp32)
    Bin = <<16#8B, 16#84, 16#24, 0:32/little>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(7, I#x86_insn.length).

modrm_sib_base_rbp_mod00_test() ->
    %% 8B 04 2D xx xx xx xx = MOV EAX, [RBP*1+disp32]
    %% (mod=00, rm=100 → SIB, SIB base=101 → disp32, no base)
    Bin = <<16#8B, 16#04, 16#2D, 0:32/little>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(7, I#x86_insn.length).

%% ===================================================================
%% Prefix handling
%% ===================================================================

prefix_66_test() ->
    %% 66 90 = NOP (with 0x66 prefix, still 2 bytes total)
    Bin = <<16#66, 16#90>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(2, I#x86_insn.length).

prefix_rep_test() ->
    %% F3 A4 = REP MOVSB
    Bin = <<16#F3, 16#A4>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(2, I#x86_insn.length).

%% ===================================================================
%% decode_all
%% ===================================================================

decode_all_simple_test() ->
    %% NOP, NOP, SYSCALL
    Bin = <<16#90, 16#90, 16#0F, 16#05>>,
    Insns = elf_decode_x86_64:decode_all(Bin),
    ?assertEqual(3, length(Insns)),
    [I1, I2, I3] = Insns,
    ?assertEqual(0, I1#x86_insn.offset),
    ?assertEqual(1, I2#x86_insn.offset),
    ?assertEqual(2, I3#x86_insn.offset),
    ?assertEqual(syscall, I3#x86_insn.type).

%% ===================================================================
%% Backward scanning for syscall number resolution
%% ===================================================================

resolve_mov_eax_before_syscall_test() ->
    %% MOV EAX, 60; SYSCALL
    Bin = <<16#B8, 60:32/little, 16#0F, 16#05>>,
    Insns = elf_decode_x86_64:decode_all(Bin),
    ?assertEqual(60, elf_decode_x86_64:resolve_syscall(Bin, 5, Insns)).

resolve_xor_eax_before_syscall_test() ->
    %% XOR EAX, EAX; SYSCALL  → read(0)
    Bin = <<16#31, 16#C0, 16#0F, 16#05>>,
    Insns = elf_decode_x86_64:decode_all(Bin),
    ?assertEqual(0, elf_decode_x86_64:resolve_syscall(Bin, 2, Insns)).

resolve_with_intervening_other_test() ->
    %% MOV EAX, 1; MOV EDI, 1; SYSCALL

    %% MOV EAX, 1
    Bin =
        <<16#B8, 1:32/little,
            %% MOV EDI, 1
            16#BF, 1:32/little,
            %% SYSCALL
            16#0F, 16#05>>,
    Insns = elf_decode_x86_64:decode_all(Bin),
    ?assertEqual(1, elf_decode_x86_64:resolve_syscall(Bin, 10, Insns)).

resolve_blocked_by_ret_test() ->
    %% MOV EAX, 60; RET; SYSCALL
    Bin = <<16#B8, 60:32/little, 16#C3, 16#0F, 16#05>>,
    Insns = elf_decode_x86_64:decode_all(Bin),
    ?assertEqual(unresolved, elf_decode_x86_64:resolve_syscall(Bin, 6, Insns)).

resolve_blocked_by_jmp_test() ->
    %% MOV EAX, 60; JMP +0; SYSCALL
    Bin = <<16#B8, 60:32/little, 16#EB, 16#00, 16#0F, 16#05>>,
    Insns = elf_decode_x86_64:decode_all(Bin),
    ?assertEqual(unresolved, elf_decode_x86_64:resolve_syscall(Bin, 7, Insns)).

resolve_rex_w_mov_test() ->
    %% 48 C7 C0 E7 00 00 00 = MOV RAX, 231; SYSCALL
    Bin = <<16#48, 16#C7, 16#C0, 231:32/little, 16#0F, 16#05>>,
    Insns = elf_decode_x86_64:decode_all(Bin),
    ?assertEqual(231, elf_decode_x86_64:resolve_syscall(Bin, 7, Insns)).

%% ===================================================================
%% extract_syscalls — realistic sequence
%% ===================================================================

extract_syscalls_test() ->
    %% Simulates: write(1, msg, 13) then exit(0)
    %%
    %% MOV EAX, 1       ; sys_write
    %% MOV EDI, 1       ; fd=1
    %% SYSCALL
    %% XOR EAX, EAX     ; 0 (but we'll use mov eax, 60 for exit)
    %% MOV EAX, 60      ; sys_exit
    %% XOR EDI, EDI     ; status=0
    %% SYSCALL

    %% MOV EAX, 1
    Bin =
        <<16#B8, 1:32/little,
            %% MOV EDI, 1
            16#BF, 1:32/little,
            %% SYSCALL
            16#0F, 16#05,
            %% MOV EAX, 60
            16#B8, 60:32/little,
            %% XOR EDI, EDI
            16#31, 16#FF,
            %% SYSCALL
            16#0F, 16#05>>,
    {Numbers, Unresolved} = elf_decode_x86_64:extract_syscalls(Bin),
    ?assertEqual([1, 60], Numbers),
    ?assertEqual(0, Unresolved).

extract_syscalls_with_unresolved_test() ->
    %% SYSCALL with no setup
    Bin = <<16#0F, 16#05>>,
    {Numbers, Unresolved} = elf_decode_x86_64:extract_syscalls(Bin),
    ?assertEqual([], Numbers),
    ?assertEqual(1, Unresolved).

extract_syscalls_xor_zero_test() ->
    %% XOR EAX, EAX; SYSCALL → read(0)
    Bin = <<16#31, 16#C0, 16#0F, 16#05>>,
    {Numbers, Unresolved} = elf_decode_x86_64:extract_syscalls(Bin),
    ?assertEqual([0], Numbers),
    ?assertEqual(0, Unresolved).

%% ===================================================================
%% Edge cases
%% ===================================================================

eof_test() ->
    ?assertEqual({error, eof}, elf_decode_x86_64:decode(<<>>, 0)).

eof_offset_test() ->
    ?assertEqual({error, eof}, elf_decode_x86_64:decode(<<16#90>>, 1)).

nop_test() ->
    Bin = <<16#90>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(other, I#x86_insn.type),
    ?assertEqual(1, I#x86_insn.length).

int3_test() ->
    Bin = <<16#CC>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(other, I#x86_insn.type),
    ?assertEqual(1, I#x86_insn.length).

push_pop_test() ->
    %% 50 = PUSH RAX, 58 = POP RAX
    Bin = <<16#50, 16#58>>,
    Insns = elf_decode_x86_64:decode_all(Bin),
    ?assertEqual(2, length(Insns)),
    [I1, I2] = Insns,
    ?assertEqual(1, I1#x86_insn.length),
    ?assertEqual(1, I2#x86_insn.length).

lea_sib_test() ->
    %% 8D 04 C5 00 00 00 00 = LEA EAX, [RAX*8+0]
    %% mod=00, rm=100(SIB), SIB: scale=2#11, index=000, base=101 → disp32
    Bin = <<16#8D, 16#04, 16#C5, 0:32/little>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(7, I#x86_insn.length).

sub_imm_grp1_test() ->
    %% 83 EC 08 = SUB ESP, 8 (group1 r/m32, imm8)
    Bin = <<16#83, 16#EC, 16#08>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(3, I#x86_insn.length).

cmp_imm32_grp1_test() ->
    %% 81 FF 00 01 00 00 = CMP EDI, 256 (group1 r/m32, imm32)
    Bin = <<16#81, 16#FF, 0, 1, 0, 0>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(6, I#x86_insn.length).

test_f7_imm32_test() ->
    %% F7 C0 FF 00 00 00 = TEST EAX, 255 (group3 /0, imm32)
    Bin = <<16#F7, 16#C0, 255:32/little>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(6, I#x86_insn.length).

multi_byte_nop_test() ->
    %% 0F 1F 00 = NOP DWORD [RAX] (3-byte NOP)
    Bin = <<16#0F, 16#1F, 16#00>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(3, I#x86_insn.length).

multi_byte_nop_sib_test() ->
    %% 0F 1F 44 00 00 = NOP DWORD [RAX+RAX*1+0] (5-byte NOP)
    Bin = <<16#0F, 16#1F, 16#44, 16#00, 16#00>>,
    {ok, I} = elf_decode_x86_64:decode(Bin, 0),
    ?assertEqual(5, I#x86_insn.length).

%% ===================================================================
%% Realistic hello-world-like code sequence
%% ===================================================================

realistic_hello_world_test() ->
    %% Simulate a static hello world:
    %%   push rbp                    ; 55
    %%   mov rbp, rsp                ; 48 89 E5
    %%   sub rsp, 16                 ; 48 83 EC 10
    %%   mov eax, 1                  ; B8 01 00 00 00   (sys_write)
    %%   mov edi, 1                  ; BF 01 00 00 00
    %%   lea rsi, [rip+0x100]        ; 48 8D 35 00 01 00 00
    %%   mov edx, 14                 ; BA 0E 00 00 00
    %%   syscall                     ; 0F 05
    %%   mov eax, 60                 ; B8 3C 00 00 00   (sys_exit)
    %%   xor edi, edi                ; 31 FF
    %%   syscall                     ; 0F 05

    %% PUSH RBP
    Bin =
        <<16#55,
            %% MOV RBP, RSP
            16#48, 16#89, 16#E5,
            %% SUB RSP, 16
            16#48, 16#83, 16#EC, 16#10,
            %% MOV EAX, 1
            16#B8, 1:32/little,
            %% MOV EDI, 1
            16#BF, 1:32/little,
            %% LEA RSI, [rip+0x100]
            16#48, 16#8D, 16#35, 256:32/little,
            %% MOV EDX, 14
            16#BA, 14:32/little,
            %% SYSCALL
            16#0F, 16#05,
            %% MOV EAX, 60
            16#B8, 60:32/little,
            %% XOR EDI, EDI
            16#31, 16#FF,
            %% SYSCALL
            16#0F, 16#05>>,

    Insns = elf_decode_x86_64:decode_all(Bin),

    %% Verify total decoded bytes = binary size
    TotalLen = lists:sum([I#x86_insn.length || I <- Insns]),
    ?assertEqual(byte_size(Bin), TotalLen),

    %% Verify syscalls found
    SyscallOffsets = [
        I#x86_insn.offset
     || I <- Insns,
        I#x86_insn.type =:= syscall
    ],
    ?assertEqual(2, length(SyscallOffsets)),

    %% Extract syscall numbers
    {Numbers, Unresolved} = elf_decode_x86_64:extract_syscalls(Bin),
    ?assertEqual([1, 60], Numbers),
    ?assertEqual(0, Unresolved).
