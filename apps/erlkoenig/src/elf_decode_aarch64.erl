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

-module(elf_decode_aarch64).
-moduledoc """
Minimal AArch64 instruction decoder for syscall extraction.

All AArch64 instructions are 4 bytes, little-endian.
Identifies instructions relevant to syscall analysis:
SVC #0, MOV X8/W8 with immediates (MOVZ/MOVK), RET, BL, B, B.cond.

Unknown opcodes are decoded as {other, undefined}.
""".

-export([
    decode/2,
    decode_all/1,
    find_syscalls/1,
    resolve_syscall/3,
    extract_syscalls/1
]).

-export_type([insn_type/0]).

%% -------------------------------------------------------------------
%% Types & Records
%% -------------------------------------------------------------------

-type insn_type() ::
    svc
    | mov_x8_imm
    | movk_x8_imm
    | ret
    | bl
    | b
    | b_cond
    | other.

-record(aarch64_insn, {
    offset :: non_neg_integer(),
    length :: 4,
    type :: insn_type(),
    value :: integer() | undefined
}).

%% -------------------------------------------------------------------
%% Public API
%% -------------------------------------------------------------------

-doc "Decode a single instruction at the given byte offset.".
-spec decode(binary(), non_neg_integer()) -> {ok, #aarch64_insn{}} | {error, term()}.
decode(Bin, Offset) when Offset + 4 =< byte_size(Bin) ->
    <<_:Offset/binary, Insn:32/little-unsigned, _/binary>> = Bin,
    {ok, classify(Insn, Offset)};
decode(_Bin, _Offset) ->
    {error, eof}.

-doc "Decode all instructions in a binary chunk.".
-spec decode_all(binary()) -> [#aarch64_insn{}].
decode_all(Bin) ->
    decode_all(Bin, 0, byte_size(Bin) band (bnot 3), []).

-doc "Find offsets of all SVC #0 instructions.".
-spec find_syscalls(binary()) -> [non_neg_integer()].
find_syscalls(Bin) ->
    [I#aarch64_insn.offset || I <- decode_all(Bin), I#aarch64_insn.type =:= svc].

-doc """
Scan backwards from an SVC site to resolve the X8 value.
Instructions is the complete decoded list (in offset order).
Handles MOVZ + MOVK combinations for large immediates.
""".
-spec resolve_syscall(binary(), non_neg_integer(), [#aarch64_insn{}]) ->
    integer() | unresolved.
resolve_syscall(_Bin, SvcOffset, Insns) ->
    Before = lists:reverse([
        I
     || I <- Insns,
        I#aarch64_insn.offset < SvcOffset
    ]),
    scan_for_x8(Before, 0, false).

-doc """
Extract all syscall numbers from a code section.
Returns {ResolvedNumbers, UnresolvedCount}.
""".
-spec extract_syscalls(binary()) -> {[integer()], non_neg_integer()}.
extract_syscalls(Bin) ->
    Insns = decode_all(Bin),
    Sites = [I#aarch64_insn.offset || I <- Insns, I#aarch64_insn.type =:= svc],
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

%% -------------------------------------------------------------------
%% Internal: decode loop
%% -------------------------------------------------------------------

-spec decode_all(binary(), non_neg_integer(), non_neg_integer(), [#aarch64_insn{}]) ->
    [#aarch64_insn{}].
decode_all(_Bin, Offset, Size, Acc) when Offset >= Size ->
    lists:reverse(Acc);
decode_all(Bin, Offset, Size, Acc) ->
    case decode(Bin, Offset) of
        {ok, Insn} ->
            decode_all(Bin, Offset + 4, Size, [Insn | Acc]);
        {error, _} ->
            lists:reverse(Acc)
    end.

%% -------------------------------------------------------------------
%% Internal: backward scan for X8 value
%% -------------------------------------------------------------------

%% Scanning backwards (nearest-first). Accumulate MOVK shifted parts,
%% then when we hit MOVZ we have the complete value.
%% Acc = accumulated MOVK bits so far, HaveMovk = seen at least one MOVK.
-spec scan_for_x8([#aarch64_insn{}], non_neg_integer(), boolean()) ->
    integer() | unresolved.
scan_for_x8([], _, _) ->
    unresolved;
%% MOVK: accumulate shifted value, keep scanning for MOVZ base
scan_for_x8([#aarch64_insn{type = movk_x8_imm, value = Val} | Rest], Acc, _) ->
    scan_for_x8(Rest, Acc bor Val, true);
%% MOVZ: this is the base — combine with any accumulated MOVK parts
scan_for_x8([#aarch64_insn{type = mov_x8_imm, value = Val} | _], Acc, _) ->
    Val bor Acc;
%% Block boundaries stop the scan.
scan_for_x8([#aarch64_insn{type = T} | _], _, _) when
    T =:= ret; T =:= bl; T =:= b; T =:= b_cond; T =:= svc
->
    unresolved;
scan_for_x8([_ | Rest], Acc, HaveMovk) ->
    scan_for_x8(Rest, Acc, HaveMovk).

%% -------------------------------------------------------------------
%% Internal: classify a 32-bit instruction word
%% -------------------------------------------------------------------

-spec classify(non_neg_integer(), non_neg_integer()) -> #aarch64_insn{}.
classify(Insn, Offset) ->
    case classify_type(Insn) of
        {Type, Value} ->
            #aarch64_insn{
                offset = Offset,
                length = 4,
                type = Type,
                value = Value
            };
        Type ->
            #aarch64_insn{
                offset = Offset,
                length = 4,
                type = Type,
                value = undefined
            }
    end.

-spec classify_type(non_neg_integer()) ->
    svc | ret | bl | b | b_cond | other | {mov_x8_imm | movk_x8_imm, non_neg_integer()}.
classify_type(16#D4000001) ->
    svc;
classify_type(16#D65F03C0) ->
    ret;
classify_type(Insn) ->
    %% Bits [31:26] determine major opcode group
    Top6 = Insn bsr 26,
    case Top6 of
        %% BL imm26
        2#100101 ->
            bl;
        %% B imm26
        2#000101 ->
            b;
        _ ->
            %% B.cond: bits [31:24] = 01010100
            Top8 = Insn bsr 24,
            case Top8 of
                16#54 -> b_cond;
                _ -> classify_mov(Insn)
            end
    end.

-spec classify_mov(non_neg_integer()) ->
    other | {mov_x8_imm | movk_x8_imm, non_neg_integer()}.
classify_mov(Insn) ->
    Rd = Insn band 16#1F,
    case Rd =:= 8 of
        false ->
            other;
        true ->
            %% MOVZ: sf_10_100101_hw_imm16_Rd
            %% MOVK: sf_11_100101_hw_imm16_Rd
            %% Bits [28:23] must be 100101
            Fixed = (Insn bsr 23) band 2#111111,
            case Fixed of
                2#100101 ->
                    Opc = (Insn bsr 29) band 2#11,
                    Hw = (Insn bsr 21) band 3,
                    Imm16 = (Insn bsr 5) band 16#FFFF,
                    Shift = Hw * 16,
                    ShiftedVal = Imm16 bsl Shift,
                    case Opc of
                        %% MOVZ
                        2#10 -> {mov_x8_imm, ShiftedVal};
                        %% MOVK
                        2#11 -> {movk_x8_imm, ShiftedVal};
                        _ -> other
                    end;
                _ ->
                    other
            end
    end.
