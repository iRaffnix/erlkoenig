-module(elf_decode_aarch64_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%% Helper: encode a 32-bit instruction as 4-byte little-endian binary
-define(LE32(X), <<(X):32/little-unsigned>>).

%% -------------------------------------------------------------------
%% Instruction encoding helpers
%% -------------------------------------------------------------------

%% MOVZ Xd, #imm16, LSL #(hw*16)
%% 1_10_100101_hw_imm16_Rd
movz_x(Rd, Imm16, Hw) ->
    (1 bsl 31) bor (2#10 bsl 29) bor (2#100101 bsl 23) bor
        (Hw bsl 21) bor (Imm16 bsl 5) bor Rd.

%% MOVZ Wd, #imm16
%% 0_10_100101_hw_imm16_Rd
movz_w(Rd, Imm16, Hw) ->
    (0 bsl 31) bor (2#10 bsl 29) bor (2#100101 bsl 23) bor
        (Hw bsl 21) bor (Imm16 bsl 5) bor Rd.

%% MOVK Xd, #imm16, LSL #(hw*16)
%% 1_11_100101_hw_imm16_Rd
movk_x(Rd, Imm16, Hw) ->
    (1 bsl 31) bor (2#11 bsl 29) bor (2#100101 bsl 23) bor
        (Hw bsl 21) bor (Imm16 bsl 5) bor Rd.

%% -------------------------------------------------------------------
%% SVC #0 detection
%% -------------------------------------------------------------------

svc_detection_test() ->
    Bin = ?LE32(16#D4000001),
    {ok, Insn} = elf_decode_aarch64:decode(Bin, 0),
    ?assertEqual(svc, element(4, Insn)),
    ?assertEqual(0, element(2, Insn)),
    ?assertEqual(4, element(3, Insn)).

%% -------------------------------------------------------------------
%% RET detection
%% -------------------------------------------------------------------

ret_detection_test() ->
    Bin = ?LE32(16#D65F03C0),
    {ok, Insn} = elf_decode_aarch64:decode(Bin, 0),
    ?assertEqual(ret, element(4, Insn)).

%% -------------------------------------------------------------------
%% MOV X8, #imm (MOVZ 64-bit)
%% -------------------------------------------------------------------

mov_x8_zero_test() ->
    %% MOVZ X8, #0
    Insn = movz_x(8, 0, 0),
    Bin = ?LE32(Insn),
    {ok, Dec} = elf_decode_aarch64:decode(Bin, 0),
    ?assertEqual(mov_x8_imm, element(4, Dec)),
    ?assertEqual(0, element(5, Dec)).

mov_x8_write_test() ->
    %% MOVZ X8, #64 (write syscall on aarch64)
    Insn = movz_x(8, 64, 0),
    Bin = ?LE32(Insn),
    {ok, Dec} = elf_decode_aarch64:decode(Bin, 0),
    ?assertEqual(mov_x8_imm, element(4, Dec)),
    ?assertEqual(64, element(5, Dec)).

mov_x8_exit_test() ->
    %% MOVZ X8, #93 (exit syscall)
    Insn = movz_x(8, 93, 0),
    Bin = ?LE32(Insn),
    {ok, Dec} = elf_decode_aarch64:decode(Bin, 0),
    ?assertEqual(mov_x8_imm, element(4, Dec)),
    ?assertEqual(93, element(5, Dec)).

mov_x8_execve_test() ->
    %% MOVZ X8, #221 (execve syscall)
    Insn = movz_x(8, 221, 0),
    Bin = ?LE32(Insn),
    {ok, Dec} = elf_decode_aarch64:decode(Bin, 0),
    ?assertEqual(mov_x8_imm, element(4, Dec)),
    ?assertEqual(221, element(5, Dec)).

mov_x8_imm1_test() ->
    %% MOVZ X8, #1
    Insn = movz_x(8, 1, 0),
    Bin = ?LE32(Insn),
    {ok, Dec} = elf_decode_aarch64:decode(Bin, 0),
    ?assertEqual(mov_x8_imm, element(4, Dec)),
    ?assertEqual(1, element(5, Dec)).

%% -------------------------------------------------------------------
%% MOV W8, #imm (MOVZ 32-bit)
%% -------------------------------------------------------------------

mov_w8_imm_test() ->
    %% MOVZ W8, #64 (write syscall, 32-bit encoding)
    Insn = movz_w(8, 64, 0),
    Bin = ?LE32(Insn),
    {ok, Dec} = elf_decode_aarch64:decode(Bin, 0),
    ?assertEqual(mov_x8_imm, element(4, Dec)),
    ?assertEqual(64, element(5, Dec)).

mov_w8_exit_test() ->
    %% MOVZ W8, #93
    Insn = movz_w(8, 93, 0),
    Bin = ?LE32(Insn),
    {ok, Dec} = elf_decode_aarch64:decode(Bin, 0),
    ?assertEqual(mov_x8_imm, element(4, Dec)),
    ?assertEqual(93, element(5, Dec)).

%% -------------------------------------------------------------------
%% MOV to other registers should be 'other'
%% -------------------------------------------------------------------

mov_x0_imm_not_x8_test() ->
    %% MOVZ X0, #42 — not X8, should be 'other'
    Insn = movz_x(0, 42, 0),
    Bin = ?LE32(Insn),
    {ok, Dec} = elf_decode_aarch64:decode(Bin, 0),
    ?assertEqual(other, element(4, Dec)).

%% -------------------------------------------------------------------
%% BL detection
%% -------------------------------------------------------------------

bl_detection_test() ->
    %% BL: top 6 bits = 100101, rest is offset
    %% 0x94000001 = BL +4
    Bin = ?LE32(16#94000001),
    {ok, Insn} = elf_decode_aarch64:decode(Bin, 0),
    ?assertEqual(bl, element(4, Insn)).

bl_large_offset_test() ->
    %% BL with larger offset: 0x97FFFFFF
    Bin = ?LE32(16#97FFFFFF),
    {ok, Insn} = elf_decode_aarch64:decode(Bin, 0),
    ?assertEqual(bl, element(4, Insn)).

%% -------------------------------------------------------------------
%% B (unconditional branch) detection
%% -------------------------------------------------------------------

b_detection_test() ->
    %% B: top 6 bits = 000101
    %% 0x14000001 = B +4
    Bin = ?LE32(16#14000001),
    {ok, Insn} = elf_decode_aarch64:decode(Bin, 0),
    ?assertEqual(b, element(4, Insn)).

b_large_offset_test() ->
    %% 0x17FFFFFF
    Bin = ?LE32(16#17FFFFFF),
    {ok, Insn} = elf_decode_aarch64:decode(Bin, 0),
    ?assertEqual(b, element(4, Insn)).

%% -------------------------------------------------------------------
%% B.cond (conditional branch) detection
%% -------------------------------------------------------------------

b_cond_detection_test() ->
    %% B.cond: top byte = 0x54
    %% 0x54000001 = B.NE +0
    Bin = ?LE32(16#54000001),
    {ok, Insn} = elf_decode_aarch64:decode(Bin, 0),
    ?assertEqual(b_cond, element(4, Insn)).

b_cond_eq_test() ->
    %% B.EQ: 0x54000040 (cond=0000, offset=2)
    Bin = ?LE32(16#54000040),
    {ok, Insn} = elf_decode_aarch64:decode(Bin, 0),
    ?assertEqual(b_cond, element(4, Insn)).

%% -------------------------------------------------------------------
%% decode_all on a sequence
%% -------------------------------------------------------------------

decode_all_sequence_test() ->
    %% MOVZ X8, #64; SVC #0; RET
    Seq = <<?LE32(movz_x(8, 64, 0))/binary, ?LE32(16#D4000001)/binary, ?LE32(16#D65F03C0)/binary>>,
    Insns = elf_decode_aarch64:decode_all(Seq),
    ?assertEqual(3, length(Insns)),
    ?assertEqual(mov_x8_imm, element(4, lists:nth(1, Insns))),
    ?assertEqual(svc, element(4, lists:nth(2, Insns))),
    ?assertEqual(ret, element(4, lists:nth(3, Insns))).

decode_all_offsets_test() ->
    %% Verify offsets are correct (0, 4, 8)

    %% some instruction
    Seq = <<?LE32(16#D2800808)/binary, ?LE32(16#D4000001)/binary, ?LE32(16#D65F03C0)/binary>>,
    Insns = elf_decode_aarch64:decode_all(Seq),
    ?assertEqual(0, element(2, lists:nth(1, Insns))),
    ?assertEqual(4, element(2, lists:nth(2, Insns))),
    ?assertEqual(8, element(2, lists:nth(3, Insns))).

%% -------------------------------------------------------------------
%% extract_syscalls on realistic sequences
%% -------------------------------------------------------------------

extract_write_exit_test() ->
    %% Typical aarch64 program:
    %%   MOV X8, #64    (write)
    %%   SVC #0
    %%   MOV X8, #93    (exit)
    %%   SVC #0
    Seq = <<
        ?LE32(movz_x(8, 64, 0))/binary,
        ?LE32(16#D4000001)/binary,
        ?LE32(movz_x(8, 93, 0))/binary,
        ?LE32(16#D4000001)/binary
    >>,
    {Syscalls, Unresolved} = elf_decode_aarch64:extract_syscalls(Seq),
    ?assertEqual([64, 93], Syscalls),
    ?assertEqual(0, Unresolved).

extract_with_other_insns_test() ->
    %% MOV X0, #1; MOV X8, #64; SVC #0
    %% X0 setup should be ignored (other), X8 found
    Seq = <<
        ?LE32(movz_x(0, 1, 0))/binary, ?LE32(movz_x(8, 64, 0))/binary, ?LE32(16#D4000001)/binary
    >>,
    {Syscalls, Unresolved} = elf_decode_aarch64:extract_syscalls(Seq),
    ?assertEqual([64], Syscalls),
    ?assertEqual(0, Unresolved).

extract_unresolved_test() ->
    %% RET; SVC #0 — no MOV X8 before SVC (blocked by RET)
    Seq = <<?LE32(16#D65F03C0)/binary, ?LE32(16#D4000001)/binary>>,
    {Syscalls, Unresolved} = elf_decode_aarch64:extract_syscalls(Seq),
    ?assertEqual([], Syscalls),
    ?assertEqual(1, Unresolved).

%% -------------------------------------------------------------------
%% MOVZ + MOVK combination for large syscall numbers
%% -------------------------------------------------------------------

movk_combination_test() ->
    %% MOVZ X8, #0x1234
    %% MOVK X8, #0x5678, LSL #16
    %% SVC #0
    %% Expected value: 0x5678_1234
    MovzInsn = movz_x(8, 16#1234, 0),
    MovkInsn = movk_x(8, 16#5678, 1),
    Seq = <<?LE32(MovzInsn)/binary, ?LE32(MovkInsn)/binary, ?LE32(16#D4000001)/binary>>,
    {Syscalls, Unresolved} = elf_decode_aarch64:extract_syscalls(Seq),
    ?assertEqual([16#56781234], Syscalls),
    ?assertEqual(0, Unresolved).

movk_two_parts_test() ->
    %% MOVZ X8, #0xAAAA
    %% MOVK X8, #0xBBBB, LSL #16
    %% MOVK X8, #0xCCCC, LSL #32
    %% SVC #0
    MovzInsn = movz_x(8, 16#AAAA, 0),
    Movk1 = movk_x(8, 16#BBBB, 1),
    Movk2 = movk_x(8, 16#CCCC, 2),
    Seq = <<
        ?LE32(MovzInsn)/binary, ?LE32(Movk1)/binary, ?LE32(Movk2)/binary, ?LE32(16#D4000001)/binary
    >>,
    {Syscalls, Unresolved} = elf_decode_aarch64:extract_syscalls(Seq),
    Expected = 16#CCCC_BBBB_AAAA,
    ?assertEqual([Expected], Syscalls),
    ?assertEqual(0, Unresolved).

%% -------------------------------------------------------------------
%% find_syscalls
%% -------------------------------------------------------------------

find_syscalls_test() ->
    Seq = <<
        ?LE32(movz_x(8, 64, 0))/binary,
        ?LE32(16#D4000001)/binary,
        ?LE32(movz_x(8, 93, 0))/binary,
        ?LE32(16#D4000001)/binary
    >>,
    Sites = elf_decode_aarch64:find_syscalls(Seq),
    ?assertEqual([4, 12], Sites).

%% -------------------------------------------------------------------
%% Edge cases
%% -------------------------------------------------------------------

empty_binary_test() ->
    ?assertEqual([], elf_decode_aarch64:decode_all(<<>>)),
    ?assertEqual([], elf_decode_aarch64:find_syscalls(<<>>)),
    ?assertEqual({[], 0}, elf_decode_aarch64:extract_syscalls(<<>>)).

truncated_test() ->
    %% Less than 4 bytes
    ?assertEqual({error, eof}, elf_decode_aarch64:decode(<<1, 2, 3>>, 0)),
    ?assertEqual([], elf_decode_aarch64:decode_all(<<1, 2, 3>>)).

offset_past_end_test() ->
    Bin = ?LE32(16#D4000001),
    ?assertEqual({error, eof}, elf_decode_aarch64:decode(Bin, 4)).

%% Block boundary stops resolve
bl_blocks_resolve_test() ->
    %% MOV X8, #64; BL somewhere; SVC #0
    %% BL should block backward scan
    Seq = <<?LE32(movz_x(8, 64, 0))/binary, ?LE32(16#94000010)/binary, ?LE32(16#D4000001)/binary>>,
    {Syscalls, Unresolved} = elf_decode_aarch64:extract_syscalls(Seq),
    ?assertEqual([], Syscalls),
    ?assertEqual(1, Unresolved).

%% W8 variant in extract
extract_w8_variant_test() ->
    %% MOVZ W8, #221 (execve); SVC #0
    Seq = <<?LE32(movz_w(8, 221, 0))/binary, ?LE32(16#D4000001)/binary>>,
    {Syscalls, Unresolved} = elf_decode_aarch64:extract_syscalls(Seq),
    ?assertEqual([221], Syscalls),
    ?assertEqual(0, Unresolved).
