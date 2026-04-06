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

-module(elf_decode_x86_64).
-moduledoc """
Minimal x86-64 instruction decoder for syscall extraction.

Decodes instruction lengths and identifies instructions relevant
to syscall analysis: SYSCALL, MOV RAX/EAX with immediates,
XOR RAX/EAX zeroing, control flow (RET, CALL, JMP, Jcc).

Does NOT attempt full disassembly -- unknown opcodes are skipped
as single-byte {other, undefined} instructions.
""".

-export([
    decode/2,
    decode_all/1,
    find_syscalls/1,
    resolve_syscall/3,
    extract_syscalls/1,
    call_targets/3
]).

-export_type([insn_type/0]).

%% -------------------------------------------------------------------
%% Types & Records
%% -------------------------------------------------------------------

-type insn_type() ::
    syscall
    | mov_rax_imm
    | xor_rax_rax
    | ret
    | call
    | jmp
    | jcc
    | other.

-record(x86_insn, {
    offset :: non_neg_integer(),
    length :: pos_integer(),
    type :: insn_type(),
    value :: integer() | undefined
}).

%% -------------------------------------------------------------------
%% Public API
%% -------------------------------------------------------------------

-doc "Decode a single instruction at the given byte offset.".
-spec decode(binary(), non_neg_integer()) -> {ok, #x86_insn{}} | {error, term()}.
decode(Bin, Offset) when Offset < byte_size(Bin) ->
    <<_:Offset/binary, Rest/binary>> = Bin,
    case decode_insn(Rest, Offset) of
        {ok, _} = Ok -> Ok;
        {error, _} = Err -> Err
    end;
decode(_Bin, _Offset) ->
    {error, eof}.

-doc "Decode all instructions in a binary chunk.".
-spec decode_all(binary()) -> [#x86_insn{}].
decode_all(Bin) ->
    decode_all(Bin, 0, byte_size(Bin), []).

-doc "Find offsets of all SYSCALL instructions.".
-spec find_syscalls(binary()) -> [non_neg_integer()].
find_syscalls(Bin) ->
    [I#x86_insn.offset || I <- decode_all(Bin), I#x86_insn.type =:= syscall].

-doc """
Scan backwards from a SYSCALL site to resolve the RAX value.
Instructions is the complete decoded list (in offset order).
""".
-spec resolve_syscall(binary(), non_neg_integer(), [#x86_insn{}]) ->
    integer() | unresolved.
resolve_syscall(_Bin, SyscallOffset, Insns) ->
    %% Collect instructions before the syscall, in reverse order (nearest first).
    Before = lists:reverse([
        I
     || I <- Insns,
        I#x86_insn.offset < SyscallOffset
    ]),
    scan_for_rax(Before).

-doc """
Extract all syscall numbers from a code section.
Returns {ResolvedNumbers, UnresolvedCount}.
""".
-spec extract_syscalls(binary()) -> {[integer()], non_neg_integer()}.
extract_syscalls(Bin) ->
    Insns = decode_all(Bin),
    Sites = [I#x86_insn.offset || I <- Insns, I#x86_insn.type =:= syscall],
    {Resolved, Unresolved} =
        lists:foldl(
            fun(Off, {RAcc, UAcc}) ->
                case resolve_syscall(Bin, Off, Insns) of
                    unresolved -> {RAcc, UAcc + 1};
                    N -> {[N | RAcc], UAcc}
                end
            end,
            {[], 0},
            Sites
        ),
    {lists:usort(Resolved), Unresolved}.

-doc """
Find direct CALL rel32 targets from pre-decoded instructions.
Returns [{CallOffset, AbsoluteTargetAddr}].
""".
-spec call_targets(binary(), non_neg_integer(), [#x86_insn{}]) ->
    [{non_neg_integer(), non_neg_integer()}].
call_targets(Bin, BaseAddr, Insns) ->
    lists:filtermap(
        fun
            (#x86_insn{type = call, offset = Off, length = Len}) when Len >= 5 ->
                %% Direct CALL rel32: E8 byte is at the end of the instruction
                E8Pos = Off + Len - 5,
                case Bin of
                    <<_:E8Pos/binary, 16#E8, Rel:32/little-signed, _/binary>> ->
                        Target = BaseAddr + Off + Len + Rel,
                        {true, {Off, Target}};
                    _ ->
                        false
                end;
            (_) ->
                false
        end,
        Insns
    ).

%% -------------------------------------------------------------------
%% Internal: decode loop
%% -------------------------------------------------------------------

-spec decode_all(binary(), non_neg_integer(), non_neg_integer(), [#x86_insn{}]) ->
    [#x86_insn{}].
decode_all(_Bin, Offset, Size, Acc) when Offset >= Size ->
    lists:reverse(Acc);
decode_all(Bin, Offset, Size, Acc) ->
    case decode(Bin, Offset) of
        {ok, #x86_insn{length = Len} = Insn} ->
            decode_all(Bin, Offset + Len, Size, [Insn | Acc]);
        {error, _} ->
            lists:reverse(Acc)
    end.

%% -------------------------------------------------------------------
%% Internal: backward scan for RAX value
%% -------------------------------------------------------------------

-spec scan_for_rax([#x86_insn{}]) -> integer() | unresolved.
scan_for_rax([]) ->
    unresolved;
scan_for_rax([#x86_insn{type = mov_rax_imm, value = V} | _]) ->
    V;
scan_for_rax([#x86_insn{type = xor_rax_rax} | _]) ->
    0;
%% Block boundaries stop the scan.
scan_for_rax([#x86_insn{type = T} | _]) when
    T =:= ret; T =:= call; T =:= jmp; T =:= jcc; T =:= syscall
->
    unresolved;
scan_for_rax([_ | Rest]) ->
    scan_for_rax(Rest).

%% -------------------------------------------------------------------
%% Internal: single instruction decode
%% -------------------------------------------------------------------

-spec decode_insn(binary(), non_neg_integer()) ->
    {ok, #x86_insn{}} | {error, eof | truncated}.
decode_insn(<<>>, _Off) ->
    {error, eof};
decode_insn(Bytes, Off) ->
    {Prefixes, Rest0} = eat_prefixes(Bytes, #{}),
    RexW = maps:get(rex_w, Prefixes, false),
    Op66 = maps:get(op66, Prefixes, false),
    PrefixLen = byte_size(Bytes) - byte_size(Rest0),
    case Rest0 of
        %% SYSCALL: 0F 05
        <<16#0F, 16#05, _/binary>> ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 2,
                type = syscall,
                value = undefined
            }};
        %% Two-byte opcode escape
        <<16#0F, SecondByte, Tail/binary>> ->
            decode_two_byte(SecondByte, Tail, Off, PrefixLen, Op66);
        %% RET (C3)
        <<16#C3, _/binary>> ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 1,
                type = ret,
                value = undefined
            }};
        %% CALL rel32 (E8)
        <<16#E8, _:32/little, _/binary>> ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 5,
                type = call,
                value = undefined
            }};
        %% JMP rel32 (E9)
        <<16#E9, _:32/little, _/binary>> ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 5,
                type = jmp,
                value = undefined
            }};
        %% JMP rel8 (EB)
        <<16#EB, _:8, _/binary>> ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 2,
                type = jmp,
                value = undefined
            }};
        %% Jcc rel8 (70-7F)
        <<Jcc, _:8, _/binary>> when Jcc >= 16#70, Jcc =< 16#7F ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 2,
                type = jcc,
                value = undefined
            }};
        %% XOR r/m32, r32 (opcode 31) — check for XOR EAX, EAX / XOR RAX, RAX
        <<16#31, ModRM, Tail2/binary>> ->
            Len = 2 + modrm_extra_len(ModRM, Tail2),
            Type =
                case ModRM of
                    %% XOR EAX, EAX (or RAX w/ REX.W)
                    16#C0 -> xor_rax_rax;
                    _ -> other
                end,
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + Len,
                type = Type,
                value = undefined
            }};
        %% XOR r32, r/m32 (opcode 33) — check for XOR EAX, EAX
        <<16#33, ModRM, Tail2/binary>> ->
            Len = 2 + modrm_extra_len(ModRM, Tail2),
            Type =
                case ModRM of
                    16#C0 -> xor_rax_rax;
                    _ -> other
                end,
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + Len,
                type = Type,
                value = undefined
            }};
        %% MOV r32, imm32 (B8+rd) / with REX.W: MOV r64, imm64
        <<Opc, _/binary>> when Opc >= 16#B8, Opc =< 16#BF ->
            Reg = Opc - 16#B8,
            case RexW of
                true ->
                    %% MOV r64, imm64 — 8-byte immediate
                    case Rest0 of
                        <<_:8, Imm:64/little-signed, _/binary>> ->
                            IsRax = (Reg =:= 0),
                            Type =
                                case IsRax of
                                    true -> mov_rax_imm;
                                    false -> other
                                end,
                            Val =
                                case IsRax of
                                    true -> Imm;
                                    false -> undefined
                                end,
                            {ok, #x86_insn{
                                offset = Off,
                                length = PrefixLen + 1 + 8,
                                type = Type,
                                value = Val
                            }};
                        _ ->
                            {error, truncated}
                    end;
                false ->
                    case Rest0 of
                        <<_:8, Imm:32/little-signed, _/binary>> ->
                            IsRax = (Reg =:= 0),
                            Type =
                                case IsRax of
                                    true -> mov_rax_imm;
                                    false -> other
                                end,
                            Val =
                                case IsRax of
                                    true -> Imm;
                                    false -> undefined
                                end,
                            {ok, #x86_insn{
                                offset = Off,
                                length = PrefixLen + 1 + 4,
                                type = Type,
                                value = Val
                            }};
                        _ ->
                            {error, truncated}
                    end
            end;
        %% MOV r/m64, sign-extended imm32 (C7 /0) — e.g. 48 C7 C0 xx xx xx xx
        <<16#C7, ModRM, Tail2/binary>> ->
            RegField = (ModRM bsr 3) band 7,
            case RegField of
                0 ->
                    Extra = modrm_extra_len(ModRM, Tail2),
                    %% After ModRM+SIB+disp comes the imm32
                    ImmOff = Extra,
                    FullTail = <<ModRM, Tail2/binary>>,
                    %% opcode + modrm + extras + imm32
                    TotalLen = 2 + Extra + 4,
                    Mod = ModRM bsr 6,
                    Rm = ModRM band 7,
                    %% Detect MOV RAX, imm32 (ModRM = C0: mod=11, rm=000)
                    case Mod =:= 2#11 andalso Rm =:= 0 of
                        true ->
                            case FullTail of
                                <<_:((1 + ImmOff) * 8), Imm:32/little-signed, _/binary>> ->
                                    {ok, #x86_insn{
                                        offset = Off,
                                        length = PrefixLen + TotalLen,
                                        type = mov_rax_imm,
                                        value = Imm
                                    }};
                                _ ->
                                    {error, truncated}
                            end;
                        false ->
                            {ok, #x86_insn{
                                offset = Off,
                                length = PrefixLen + TotalLen,
                                type = other,
                                value = undefined
                            }}
                    end;
                _ ->
                    Extra = modrm_extra_len(ModRM, Tail2),
                    ImmSize =
                        case Op66 of
                            true -> 2;
                            false -> 4
                        end,
                    {ok, #x86_insn{
                        offset = Off,
                        length = PrefixLen + 2 + Extra + ImmSize,
                        type = other,
                        value = undefined
                    }}
            end;
        %% MOV r/m8, imm8 (C6 /0)
        <<16#C6, ModRM, Tail2/binary>> ->
            Extra = modrm_extra_len(ModRM, Tail2),
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 2 + Extra + 1,
                type = other,
                value = undefined
            }};
        %% MOV r/m16/32, imm16/32 with 0x66 prefix handled above via C7
        %% Already covered by C7 case

        %% Generic one-byte opcodes with ModR/M
        <<Opc, ModRM, Tail2/binary>> when
            %% ALU r/m, r: 00,01,02,03,08,09,0A,0B,10..13,18..1B,20..23,28..2B,30..33,38..3B
            (Opc band 16#C0 =:= 16#00 andalso Opc band 16#04 =:= 0 andalso
                Opc =/= 16#0F andalso Opc =/= 16#06 andalso Opc =/= 16#07 andalso
                Opc =/= 16#0E andalso Opc =/= 16#16 andalso Opc =/= 16#17 andalso
                Opc =/= 16#1E andalso Opc =/= 16#1F andalso
                Opc =/= 16#26 andalso Opc =/= 16#27 andalso
                Opc =/= 16#2E andalso Opc =/= 16#2F andalso
                Opc =/= 16#36 andalso Opc =/= 16#37 andalso
                Opc =/= 16#3E andalso Opc =/= 16#3F);
            %% 84-8F: TEST, XCHG, MOV, LEA, etc.
            (Opc >= 16#84 andalso Opc =< 16#8F andalso
                Opc =/= 16#8C andalso Opc =/= 16#8E andalso
                %% 8D = LEA, handled but has ModRM
                Opc =/= 16#8D);
            %% LEA
            Opc =:= 16#8D;
            %% MOV Sreg
            Opc =:= 16#8C;
            %% MOV Sreg
            Opc =:= 16#8E;
            %% D0-D3: shift group
            (Opc >= 16#D0 andalso Opc =< 16#D3);
            %% F6, F7: unary group (TEST/NOT/NEG/MUL/DIV)
            Opc =:= 16#F6;
            Opc =:= 16#F7;
            %% FE, FF: INC/DEC/CALL/JMP group
            Opc =:= 16#FE;
            Opc =:= 16#FF
        ->
            Extra = modrm_extra_len(ModRM, Tail2),
            ImmSize = modrm_opcode_imm(Opc, ModRM, Op66),
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 2 + Extra + ImmSize,
                type = classify_modrm_opcode(Opc, ModRM),
                value = undefined
            }};
        %% ALU AL/AX/EAX, imm: 04,0C,14,1C,24,2C,34,3C (imm8)
        %%                       05,0D,15,1D,25,2D,35,3D (imm16/32)
        <<Opc, _/binary>> when Opc band 16#C7 =:= 16#04 ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 2,
                type = other,
                value = undefined
            }};
        <<Opc, _/binary>> when Opc band 16#C7 =:= 16#05 ->
            ImmSize =
                case Op66 of
                    true -> 2;
                    false -> 4
                end,
            case Rest0 of
                <<_:8, _:ImmSize/binary, _/binary>> ->
                    {ok, #x86_insn{
                        offset = Off,
                        length = PrefixLen + 1 + ImmSize,
                        type = other,
                        value = undefined
                    }};
                _ ->
                    {error, truncated}
            end;
        %% PUSH/POP r64 (50-5F)
        <<Opc, _/binary>> when Opc >= 16#50, Opc =< 16#5F ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 1,
                type = other,
                value = undefined
            }};
        %% PUSH imm8 (6A)
        <<16#6A, _:8, _/binary>> ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 2,
                type = other,
                value = undefined
            }};
        %% PUSH imm32 (68)
        <<16#68, _:32/little, _/binary>> ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 5,
                type = other,
                value = undefined
            }};
        %% IMUL r, r/m, imm8 (6B)
        <<16#6B, ModRM, Tail2/binary>> ->
            Extra = modrm_extra_len(ModRM, Tail2),
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 2 + Extra + 1,
                type = other,
                value = undefined
            }};
        %% IMUL r, r/m, imm32 (69)
        <<16#69, ModRM, Tail2/binary>> ->
            Extra = modrm_extra_len(ModRM, Tail2),
            ImmSize =
                case Op66 of
                    true -> 2;
                    false -> 4
                end,
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 2 + Extra + ImmSize,
                type = other,
                value = undefined
            }};
        %% Grp1 r/m8, imm8 (80)
        <<16#80, ModRM, Tail2/binary>> ->
            Extra = modrm_extra_len(ModRM, Tail2),
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 2 + Extra + 1,
                type = other,
                value = undefined
            }};
        %% Grp1 r/m32, imm32 (81)
        <<16#81, ModRM, Tail2/binary>> ->
            Extra = modrm_extra_len(ModRM, Tail2),
            ImmSize =
                case Op66 of
                    true -> 2;
                    false -> 4
                end,
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 2 + Extra + ImmSize,
                type = other,
                value = undefined
            }};
        %% Grp1 r/m32, imm8 (83)
        <<16#83, ModRM, Tail2/binary>> ->
            Extra = modrm_extra_len(ModRM, Tail2),
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 2 + Extra + 1,
                type = other,
                value = undefined
            }};
        %% NOP (90)
        <<16#90, _/binary>> ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 1,
                type = other,
                value = undefined
            }};
        %% XCHG EAX, r32 (91-97)
        <<Opc, _/binary>> when Opc >= 16#91, Opc =< 16#97 ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 1,
                type = other,
                value = undefined
            }};
        %% CBW/CWD/CDQ variants (98, 99)
        <<Opc, _/binary>> when Opc =:= 16#98; Opc =:= 16#99 ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 1,
                type = other,
                value = undefined
            }};
        %% MOV AL/AX/EAX, moffs (A0, A1)
        <<16#A0, _/binary>> ->
            moffs_insn(Rest0, Off, PrefixLen, 1);
        <<16#A1, _/binary>> ->
            moffs_insn(Rest0, Off, PrefixLen, 1);
        %% MOV moffs, AL/AX/EAX (A2, A3)
        <<16#A2, _/binary>> ->
            moffs_insn(Rest0, Off, PrefixLen, 1);
        <<16#A3, _/binary>> ->
            moffs_insn(Rest0, Off, PrefixLen, 1);
        %% TEST AL, imm8 (A8)
        <<16#A8, _:8, _/binary>> ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 2,
                type = other,
                value = undefined
            }};
        %% TEST EAX, imm32 (A9)
        <<16#A9, _/binary>> ->
            ImmSize =
                case Op66 of
                    true -> 2;
                    false -> 4
                end,
            case Rest0 of
                <<_:8, _:ImmSize/binary, _/binary>> ->
                    {ok, #x86_insn{
                        offset = Off,
                        length = PrefixLen + 1 + ImmSize,
                        type = other,
                        value = undefined
                    }};
                _ ->
                    {error, truncated}
            end;
        %% MOV r8, imm8 (B0-B7)
        <<Opc, _:8, _/binary>> when Opc >= 16#B0, Opc =< 16#B7 ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 2,
                type = other,
                value = undefined
            }};
        %% RET imm16 (C2)
        <<16#C2, _:16/little, _/binary>> ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 3,
                type = ret,
                value = undefined
            }};
        %% LEAVE (C9)
        <<16#C9, _/binary>> ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 1,
                type = other,
                value = undefined
            }};
        %% INT3 (CC)
        <<16#CC, _/binary>> ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 1,
                type = other,
                value = undefined
            }};
        %% INT imm8 (CD)
        <<16#CD, _:8, _/binary>> ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 2,
                type = other,
                value = undefined
            }};
        %% LOOP/LOOPcc/JCXZ (E0-E3)
        <<Opc, _:8, _/binary>> when Opc >= 16#E0, Opc =< 16#E3 ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 2,
                type = jcc,
                value = undefined
            }};
        %% IN/OUT imm8 (E4-E7)
        <<Opc, _:8, _/binary>> when Opc >= 16#E4, Opc =< 16#E7 ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 2,
                type = other,
                value = undefined
            }};
        %% IN/OUT DX (EC-EF)
        <<Opc, _/binary>> when Opc >= 16#EC, Opc =< 16#EF ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 1,
                type = other,
                value = undefined
            }};
        %% HLT (F4)
        <<16#F4, _/binary>> ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 1,
                type = other,
                value = undefined
            }};
        %% CLC/STC/CLI/STI/CLD/STD (F8-FD)
        <<Opc, _/binary>> when Opc >= 16#F8, Opc =< 16#FD ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 1,
                type = other,
                value = undefined
            }};
        %% MOVSB/MOVSQ/STOSB/etc (A4-A7, AA-AF single byte with REP)
        <<Opc, _/binary>> when
            Opc >= 16#A4, Opc =< 16#A7;
            Opc >= 16#AA, Opc =< 16#AF
        ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 1,
                type = other,
                value = undefined
            }};
        %% Catch-all: unknown opcode, skip 1 byte
        <<_, _/binary>> ->
            {ok, #x86_insn{
                offset = Off,
                length = PrefixLen + 1,
                type = other,
                value = undefined
            }};
        _ ->
            {error, truncated}
    end.

%% -------------------------------------------------------------------
%% Two-byte opcode (0F xx) decoding
%% -------------------------------------------------------------------

-spec decode_two_byte(
    byte(),
    binary(),
    non_neg_integer(),
    non_neg_integer(),
    boolean()
) ->
    {ok, #x86_insn{}} | {error, term()}.

%% Jcc rel32 (0F 80 - 0F 8F)
decode_two_byte(Sec, _Tail, Off, PLen, _Op66) when
    Sec >= 16#80, Sec =< 16#8F
->
    {ok, #x86_insn{
        offset = Off,
        length = PLen + 2 + 4,
        type = jcc,
        value = undefined
    }};
%% SETcc (0F 90 - 0F 9F) — ModR/M
decode_two_byte(Sec, Tail, Off, PLen, _Op66) when
    Sec >= 16#90, Sec =< 16#9F
->
    case Tail of
        <<ModRM, Tail2/binary>> ->
            Extra = modrm_extra_len(ModRM, Tail2),
            {ok, #x86_insn{
                offset = Off,
                length = PLen + 3 + Extra,
                type = other,
                value = undefined
            }};
        _ ->
            {error, truncated}
    end;
%% CMOVcc (0F 40 - 0F 4F) — ModR/M
decode_two_byte(Sec, Tail, Off, PLen, _Op66) when
    Sec >= 16#40, Sec =< 16#4F
->
    case Tail of
        <<ModRM, Tail2/binary>> ->
            Extra = modrm_extra_len(ModRM, Tail2),
            {ok, #x86_insn{
                offset = Off,
                length = PLen + 3 + Extra,
                type = other,
                value = undefined
            }};
        _ ->
            {error, truncated}
    end;
%% MOVZX/MOVSX (0F B6, 0F B7, 0F BE, 0F BF) — ModR/M
decode_two_byte(Sec, Tail, Off, PLen, _Op66) when
    Sec =:= 16#B6; Sec =:= 16#B7; Sec =:= 16#BE; Sec =:= 16#BF
->
    case Tail of
        <<ModRM, Tail2/binary>> ->
            Extra = modrm_extra_len(ModRM, Tail2),
            {ok, #x86_insn{
                offset = Off,
                length = PLen + 3 + Extra,
                type = other,
                value = undefined
            }};
        _ ->
            {error, truncated}
    end;
%% IMUL r, r/m (0F AF) — ModR/M
decode_two_byte(16#AF, Tail, Off, PLen, _Op66) ->
    case Tail of
        <<ModRM, Tail2/binary>> ->
            Extra = modrm_extra_len(ModRM, Tail2),
            {ok, #x86_insn{
                offset = Off,
                length = PLen + 3 + Extra,
                type = other,
                value = undefined
            }};
        _ ->
            {error, truncated}
    end;
%% BSF/BSR (0F BC, 0F BD) — ModR/M
decode_two_byte(Sec, Tail, Off, PLen, _Op66) when
    Sec =:= 16#BC; Sec =:= 16#BD
->
    case Tail of
        <<ModRM, Tail2/binary>> ->
            Extra = modrm_extra_len(ModRM, Tail2),
            {ok, #x86_insn{
                offset = Off,
                length = PLen + 3 + Extra,
                type = other,
                value = undefined
            }};
        _ ->
            {error, truncated}
    end;
%% BT/BTS/BTR/BTC r/m, r (0F A3, 0F AB, 0F B3, 0F BB) — ModR/M
decode_two_byte(Sec, Tail, Off, PLen, _Op66) when
    Sec =:= 16#A3; Sec =:= 16#AB; Sec =:= 16#B3; Sec =:= 16#BB
->
    case Tail of
        <<ModRM, Tail2/binary>> ->
            Extra = modrm_extra_len(ModRM, Tail2),
            {ok, #x86_insn{
                offset = Off,
                length = PLen + 3 + Extra,
                type = other,
                value = undefined
            }};
        _ ->
            {error, truncated}
    end;
%% BT/BTS/BTR/BTC r/m, imm8 (0F BA /4-7) — ModR/M + imm8
decode_two_byte(16#BA, Tail, Off, PLen, _Op66) ->
    case Tail of
        <<ModRM, Tail2/binary>> ->
            Extra = modrm_extra_len(ModRM, Tail2),
            {ok, #x86_insn{
                offset = Off,
                length = PLen + 3 + Extra + 1,
                type = other,
                value = undefined
            }};
        _ ->
            {error, truncated}
    end;
%% SHLD/SHRD imm8 (0F A4, 0F AC) — ModR/M + imm8
decode_two_byte(Sec, Tail, Off, PLen, _Op66) when
    Sec =:= 16#A4; Sec =:= 16#AC
->
    case Tail of
        <<ModRM, Tail2/binary>> ->
            Extra = modrm_extra_len(ModRM, Tail2),
            {ok, #x86_insn{
                offset = Off,
                length = PLen + 3 + Extra + 1,
                type = other,
                value = undefined
            }};
        _ ->
            {error, truncated}
    end;
%% SHLD/SHRD CL (0F A5, 0F AD) — ModR/M
decode_two_byte(Sec, Tail, Off, PLen, _Op66) when
    Sec =:= 16#A5; Sec =:= 16#AD
->
    case Tail of
        <<ModRM, Tail2/binary>> ->
            Extra = modrm_extra_len(ModRM, Tail2),
            {ok, #x86_insn{
                offset = Off,
                length = PLen + 3 + Extra,
                type = other,
                value = undefined
            }};
        _ ->
            {error, truncated}
    end;
%% XADD (0F C0, 0F C1) — ModR/M
decode_two_byte(Sec, Tail, Off, PLen, _Op66) when
    Sec =:= 16#C0; Sec =:= 16#C1
->
    case Tail of
        <<ModRM, Tail2/binary>> ->
            Extra = modrm_extra_len(ModRM, Tail2),
            {ok, #x86_insn{
                offset = Off,
                length = PLen + 3 + Extra,
                type = other,
                value = undefined
            }};
        _ ->
            {error, truncated}
    end;
%% CMPXCHG (0F B0, 0F B1) — ModR/M
decode_two_byte(Sec, Tail, Off, PLen, _Op66) when
    Sec =:= 16#B0; Sec =:= 16#B1
->
    case Tail of
        <<ModRM, Tail2/binary>> ->
            Extra = modrm_extra_len(ModRM, Tail2),
            {ok, #x86_insn{
                offset = Off,
                length = PLen + 3 + Extra,
                type = other,
                value = undefined
            }};
        _ ->
            {error, truncated}
    end;
%% NOP r/m (0F 1F) — multi-byte NOP, ModR/M
decode_two_byte(16#1F, Tail, Off, PLen, _Op66) ->
    case Tail of
        <<ModRM, Tail2/binary>> ->
            Extra = modrm_extra_len(ModRM, Tail2),
            {ok, #x86_insn{
                offset = Off,
                length = PLen + 3 + Extra,
                type = other,
                value = undefined
            }};
        _ ->
            {error, truncated}
    end;
%% 0F 38 xx — three-byte opcode map 1 (all have ModR/M)
decode_two_byte(16#38, Tail, Off, PLen, _Op66) ->
    case Tail of
        <<_ThirdByte, ModRM, Tail2/binary>> ->
            Extra = modrm_extra_len(ModRM, Tail2),
            {ok, #x86_insn{
                offset = Off,
                length = PLen + 4 + Extra,
                type = other,
                value = undefined
            }};
        _ ->
            {error, truncated}
    end;
%% 0F 3A xx — three-byte opcode map 2 (all have ModR/M + imm8)
decode_two_byte(16#3A, Tail, Off, PLen, _Op66) ->
    case Tail of
        <<_ThirdByte, ModRM, Tail2/binary>> ->
            Extra = modrm_extra_len(ModRM, Tail2),
            {ok, #x86_insn{
                offset = Off,
                length = PLen + 4 + Extra + 1,
                type = other,
                value = undefined
            }};
        _ ->
            {error, truncated}
    end;
%% RDTSC (0F 31), CPUID (0F A2), LFENCE/MFENCE/SFENCE (0F AE — simplified)
decode_two_byte(Sec, _Tail, Off, PLen, _Op66) when
    Sec =:= 16#31; Sec =:= 16#A2
->
    {ok, #x86_insn{
        offset = Off,
        length = PLen + 2,
        type = other,
        value = undefined
    }};
%% WRMSR/RDMSR/RDPMC (0F 30, 0F 32, 0F 33)
decode_two_byte(Sec, _Tail, Off, PLen, _Op66) when
    Sec =:= 16#30; Sec =:= 16#32; Sec =:= 16#33
->
    {ok, #x86_insn{
        offset = Off,
        length = PLen + 2,
        type = other,
        value = undefined
    }};
%% Generic 0F xx with ModR/M for remaining common opcodes
%% SSE/SSE2 load/store, MOVAPS, MOVDQA, etc.
decode_two_byte(Sec, Tail, Off, PLen, _Op66) when
    %% MOVxPS/MOVxPD etc.
    (Sec >= 16#10 andalso Sec =< 16#17);
    %% MOVAPS, COMISS, etc.
    (Sec >= 16#28 andalso Sec =< 16#2F);
    %% SSE arith/logic
    (Sec >= 16#50 andalso Sec =< 16#7F);
    %% PUSH/POP FS/GS
    (Sec >= 16#A0 andalso Sec =< 16#A1);
    %% LFENCE etc (ModR/M)
    Sec =:= 16#AE;
    %% SSE compare, shuffle
    (Sec >= 16#C2 andalso Sec =< 16#C6);
    %% SSE misc
    (Sec >= 16#D0 andalso Sec =< 16#FF)
->
    case Tail of
        <<ModRM, Tail2/binary>> ->
            Extra = modrm_extra_len(ModRM, Tail2),
            ImmSize =
                case Sec of
                    %% PSHUFx imm8
                    16#70 -> 1;
                    %% CMPxPS/PD imm8
                    16#C2 -> 1;
                    %% PINSRW imm8
                    16#C4 -> 1;
                    %% PEXTRW (no imm, despite reg encoding)
                    16#C5 -> 0;
                    %% SHUFPS/PD imm8
                    16#C6 -> 1;
                    _ -> 0
                end,
            {ok, #x86_insn{
                offset = Off,
                length = PLen + 3 + Extra + ImmSize,
                type = other,
                value = undefined
            }};
        _ ->
            {error, truncated}
    end;
%% Fallback: unknown 0F xx, assume 2 bytes
decode_two_byte(_Sec, _Tail, Off, PLen, _Op66) ->
    {ok, #x86_insn{
        offset = Off,
        length = PLen + 2,
        type = other,
        value = undefined
    }}.

%% -------------------------------------------------------------------
%% Prefix consumption
%% -------------------------------------------------------------------

%% No spec — internal function, Dialyzer infers precise map type.
eat_prefixes(<<16#66, Rest/binary>>, Acc) ->
    eat_prefixes(Rest, Acc#{op66 => true});
eat_prefixes(<<16#67, Rest/binary>>, Acc) ->
    eat_prefixes(Rest, Acc#{addr67 => true});
eat_prefixes(<<16#F0, Rest/binary>>, Acc) ->
    eat_prefixes(Rest, Acc#{lock => true});
eat_prefixes(<<16#F2, Rest/binary>>, Acc) ->
    eat_prefixes(Rest, Acc#{repne => true});
eat_prefixes(<<16#F3, Rest/binary>>, Acc) ->
    eat_prefixes(Rest, Acc#{rep => true});
eat_prefixes(<<Rex, Rest/binary>>, Acc) when
    Rex >= 16#40, Rex =< 16#4F
->
    W = (Rex bsr 3) band 1 =:= 1,
    eat_prefixes(Rest, Acc#{rex => Rex, rex_w => W});
eat_prefixes(Bin, Acc) ->
    {Acc, Bin}.

%% -------------------------------------------------------------------
%% ModR/M + SIB + Displacement length calculation
%% -------------------------------------------------------------------

%% Returns the number of EXTRA bytes after the ModR/M byte
%% (SIB + displacement, NOT including the ModR/M byte itself).
-spec modrm_extra_len(byte(), binary()) -> 0 | 1 | 2 | 4 | 5.
modrm_extra_len(ModRM, _Tail) ->
    Mod = ModRM bsr 6,
    Rm = ModRM band 7,
    case Mod of
        2#11 ->
            %% Register-register, no memory operand
            0;
        2#00 ->
            case Rm of
                %% SIB follows
                2#100 -> 1 + sib_disp_len(2#00, _Tail);
                %% RIP-relative disp32
                2#101 -> 4;
                _ -> 0
            end;
        2#01 ->
            case Rm of
                %% SIB + disp8
                2#100 -> 1 + 1 + sib_base_extra(2#01, _Tail);
                %% disp8
                _ -> 1
            end;
        2#10 ->
            case Rm of
                %% SIB + disp32
                2#100 -> 1 + 4 + sib_base_extra(2#10, _Tail);
                %% disp32
                _ -> 4
            end
    end.

%% Calculate displacement from SIB byte when mod=00.
%% If base=101 (RBP) and mod=00, there's a disp32 instead of base.
-spec sib_disp_len(0, binary()) -> 0 | 4.
sib_disp_len(2#00, <<SIB, _/binary>>) ->
    Base = SIB band 7,
    case Base of
        %% disp32, no base
        2#101 -> 4;
        _ -> 0
    end;
sib_disp_len(_, _) ->
    0.

%% Extra displacement bytes that SIB base=101 might NOT add
%% (already accounted for in the mod-based disp). Returns 0.
-spec sib_base_extra(1 | 2, binary()) -> 0.
sib_base_extra(_Mod, _Tail) ->
    0.

%% -------------------------------------------------------------------
%% Immediate size for ModR/M-bearing opcodes
%% -------------------------------------------------------------------

-spec modrm_opcode_imm(byte(), byte(), boolean()) -> non_neg_integer().
modrm_opcode_imm(16#F6, ModRM, _Op66) ->
    %% F6: group 3, byte operand; /0 and /1 (TEST) have imm8
    Reg = (ModRM bsr 3) band 7,
    case Reg of
        0 -> 1;
        1 -> 1;
        _ -> 0
    end;
modrm_opcode_imm(16#F7, ModRM, Op66) ->
    %% F7: group 3, word/dword operand; /0 and /1 (TEST) have imm16/32
    Reg = (ModRM bsr 3) band 7,
    case Reg of
        0 ->
            case Op66 of
                true -> 2;
                false -> 4
            end;
        1 ->
            case Op66 of
                true -> 2;
                false -> 4
            end;
        _ ->
            0
    end;
modrm_opcode_imm(_, _ModRM, _Op66) ->
    0.

%% -------------------------------------------------------------------
%% Classify ModR/M-based opcodes for type tagging
%% -------------------------------------------------------------------

-spec classify_modrm_opcode(byte(), byte()) -> call | jmp | other.
classify_modrm_opcode(16#FF, ModRM) ->
    Reg = (ModRM bsr 3) band 7,
    case Reg of
        %% CALL r/m64
        2 -> call;
        %% JMP r/m64
        4 -> jmp;
        _ -> other
    end;
classify_modrm_opcode(_, _) ->
    other.

%% -------------------------------------------------------------------
%% Memory-offset instructions (A0-A3): 8-byte address in 64-bit mode
%% -------------------------------------------------------------------

-spec moffs_insn(
    binary(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer()
) ->
    {ok, #x86_insn{}} | {error, term()}.
moffs_insn(Rest, Off, PLen, _OpcLen) ->
    %% In 64-bit mode, moffs is 8 bytes (unless 0x67 prefix → 4 bytes).
    %% We simplify: always 8 bytes.
    case Rest of
        <<_:8, _:64, _/binary>> ->
            {ok, #x86_insn{
                offset = Off,
                length = PLen + 1 + 8,
                type = other,
                value = undefined
            }};
        _ ->
            {error, truncated}
    end.
