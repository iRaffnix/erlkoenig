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

-module(elf_lang_dwarf).
-moduledoc """
DWARF debug info analyzer -- extracts high-level metadata.

NOT a full DWARF parser. Only extracts:
- Whether .debug_info is present
- Per-CU: producer string, source language, compilation directory, name
- Source file list from .debug_line headers (DWARF-4 only)

Supports DWARF-4 and DWARF-5 compilation unit headers.
""".

-include("elf_parse.hrl").
-include("elf_lang_dwarf.hrl").

-export([
    has_debug_info/1,
    compilation_units/1,
    source_files/1
]).

-export_type([dwarf_cu/0]).

-type dwarf_cu() :: #dwarf_cu{}.

%% ---------------------------------------------------------------------------
%% Public API
%% ---------------------------------------------------------------------------

-doc "True if .debug_info section exists and is non-empty.".
-spec has_debug_info(#elf{}) -> boolean().
has_debug_info(Elf) ->
    case elf_parse:section(<<".debug_info">>, Elf) of
        {ok, #elf_shdr{size = Sz}} when Sz > 0 -> true;
        _ -> false
    end.

-doc "Extract compilation units from .debug_info.".
-spec compilation_units(#elf{}) -> {ok, [#dwarf_cu{}]} | {error, term()}.
compilation_units(Elf) ->
    case get_section_data(<<".debug_info">>, Elf) of
        {ok, DebugInfo} ->
            Abbrev =
                case get_section_data(<<".debug_abbrev">>, Elf) of
                    {ok, A} -> A;
                    _ -> <<>>
                end,
            DebugStr =
                case get_section_data(<<".debug_str">>, Elf) of
                    {ok, S} -> S;
                    _ -> <<>>
                end,
            LineStr =
                case get_section_data(<<".debug_line_str">>, Elf) of
                    {ok, LS} -> LS;
                    _ -> <<>>
                end,
            Endian = (Elf#elf.header)#elf_header.endian,
            {ok, parse_cus(DebugInfo, Abbrev, DebugStr, LineStr, Endian, [])};
        {error, _} ->
            {error, no_debug_info}
    end.

-doc """
Extract source file names from .debug_line section headers.
Only supports DWARF-4 line table format. DWARF-5 CUs are skipped.
""".
-spec source_files(#elf{}) -> {ok, [binary()]} | {error, term()}.
source_files(Elf) ->
    case get_section_data(<<".debug_line">>, Elf) of
        {ok, DebugLine} ->
            Endian = (Elf#elf.header)#elf_header.endian,
            {ok, parse_line_units(DebugLine, Endian, [])};
        {error, _} ->
            {error, no_debug_line}
    end.

%% ---------------------------------------------------------------------------
%% Internal — Section data helper
%% ---------------------------------------------------------------------------

-spec get_section_data(binary(), #elf{}) -> {ok, binary()} | {error, term()}.
get_section_data(Name, Elf) ->
    case elf_parse:section(Name, Elf) of
        {ok, Shdr} -> elf_parse:section_data(Shdr, Elf);
        Error -> Error
    end.

%% ---------------------------------------------------------------------------
%% Internal — Compilation Unit parsing
%% ---------------------------------------------------------------------------

-spec parse_cus(
    binary(),
    binary(),
    binary(),
    binary(),
    little | big,
    [#dwarf_cu{}]
) -> [#dwarf_cu{}].
parse_cus(<<>>, _Abbrev, _Str, _LineStr, _Endian, Acc) ->
    lists:reverse(Acc);
parse_cus(Bin, Abbrev, Str, LineStr, Endian, Acc) ->
    case parse_cu_header(Bin, Endian) of
        {ok, Version, AbbrevOff, AddrSize, DieData, Rest} ->
            CU = parse_cu_die(
                DieData,
                Abbrev,
                AbbrevOff,
                AddrSize,
                Str,
                LineStr,
                Version,
                Endian
            ),
            parse_cus(Rest, Abbrev, Str, LineStr, Endian, [CU | Acc]);
        {error, _} ->
            lists:reverse(Acc)
    end.

%% Parse a CU header, returning {ok, Version, AbbrevOff, AddrSize, DieData, Rest}
%% DieData is the binary from after the header to the end of this CU.
%% Rest is the binary after this entire CU.
parse_cu_header(Bin, little) ->
    parse_cu_header_1(Bin, little);
parse_cu_header(Bin, big) ->
    parse_cu_header_1(Bin, big).

parse_cu_header_1(Bin, _Endian) when byte_size(Bin) < 4 ->
    {error, truncated};
parse_cu_header_1(Bin, Endian) ->
    %% Read unit_length (32-bit DWARF only, skip 64-bit)
    {UnitLen, AfterLen} = read_u32(Bin, Endian),
    maybe
        ok ?=
            case UnitLen of
                16#FFFFFFFF -> {error, dwarf64_unsupported};
                _ when byte_size(AfterLen) < UnitLen -> {error, truncated};
                _ -> ok
            end,
        <<CUBody:UnitLen/binary, Rest/binary>> = AfterLen,
        {ok, Version, AbbrevOff, AddrSize, DieData} ?= parse_cu_fields(CUBody, Endian),
        {ok, Version, AbbrevOff, AddrSize, DieData, Rest}
    end.

parse_cu_fields(CUBody, _Endian) when byte_size(CUBody) < 2 ->
    {error, truncated};
parse_cu_fields(CUBody, Endian) ->
    {Version, After1} = read_u16(CUBody, Endian),
    case Version of
        4 ->
            %% DWARF-4: version(2) + abbrev_offset(4) + address_size(1)
            case After1 of
                <<>> ->
                    {error, truncated};
                _ when byte_size(After1) < 5 -> {error, truncated};
                _ ->
                    {AbbrevOff, After2} = read_u32(After1, Endian),
                    <<AddrSize:8, DieData/binary>> = After2,
                    {ok, 4, AbbrevOff, AddrSize, DieData}
            end;
        5 ->
            %% DWARF-5: version(2) + unit_type(1) + address_size(1) + abbrev_offset(4)
            case After1 of
                <<_UnitType:8, AddrSize:8, Rest/binary>> when byte_size(Rest) >= 4 ->
                    {AbbrevOff, DieData} = read_u32(Rest, Endian),
                    {ok, 5, AbbrevOff, AddrSize, DieData};
                _ ->
                    {error, truncated}
            end;
        _ ->
            %% Unknown version — skip
            {error, {unknown_version, Version}}
    end.

%% ---------------------------------------------------------------------------
%% Internal — DIE parsing (first DIE only = compile_unit)
%% ---------------------------------------------------------------------------

parse_cu_die(DieData, Abbrev, AbbrevOff, AddrSize, Str, LineStr, Version, Endian) ->
    BaseCU = #dwarf_cu{version = Version},
    case decode_uleb128(DieData) of
        {0, _} ->
            %% Null DIE
            BaseCU;
        {AbbrevCode, AttrData} ->
            case lookup_abbrev(Abbrev, AbbrevOff, AbbrevCode) of
                {ok, ?DW_TAG_compile_unit, AttrSpecs} ->
                    parse_cu_attrs(
                        AttrData,
                        AttrSpecs,
                        AddrSize,
                        Str,
                        LineStr,
                        Endian,
                        BaseCU
                    );
                {ok, _OtherTag, _} ->
                    BaseCU;
                error ->
                    BaseCU
            end
    end.

%% Parse attribute values for the compile_unit DIE.
parse_cu_attrs(_Bin, [], _AddrSize, _Str, _LineStr, _Endian, CU) ->
    CU;
parse_cu_attrs(Bin, [{Attr, Form} | Rest], AddrSize, Str, LineStr, Endian, CU) ->
    case read_form_value(Bin, Form, AddrSize, Endian) of
        {ok, Value, Remaining} ->
            CU1 = apply_cu_attr(Attr, Form, Value, Str, LineStr, Endian, CU),
            parse_cu_attrs(Remaining, Rest, AddrSize, Str, LineStr, Endian, CU1);
        {error, _} ->
            CU
    end.

apply_cu_attr(?DW_AT_producer, Form, Value, Str, LineStr, _Endian, CU) ->
    CU#dwarf_cu{producer = resolve_string(Form, Value, Str, LineStr)};
apply_cu_attr(?DW_AT_language, _Form, Value, _Str, _LineStr, _Endian, CU) ->
    CU#dwarf_cu{language = decode_language(Value)};
apply_cu_attr(?DW_AT_name, Form, Value, Str, LineStr, _Endian, CU) ->
    CU#dwarf_cu{name = resolve_string(Form, Value, Str, LineStr)};
apply_cu_attr(?DW_AT_comp_dir, Form, Value, Str, LineStr, _Endian, CU) ->
    CU#dwarf_cu{comp_dir = resolve_string(Form, Value, Str, LineStr)};
apply_cu_attr(_, _, _, _, _, _, CU) ->
    CU.

-spec resolve_string(non_neg_integer(), term(), binary(), binary()) -> binary() | undefined.
resolve_string(?DW_FORM_string, Value, _Str, _LineStr) ->
    Value;
resolve_string(?DW_FORM_strp, Offset, Str, _LineStr) ->
    read_debug_str(Str, Offset);
resolve_string(?DW_FORM_line_strp, Offset, _Str, LineStr) ->
    read_debug_str(LineStr, Offset);
resolve_string(_, _, _, _) ->
    undefined.

-spec read_debug_str(binary(), non_neg_integer()) -> binary().
read_debug_str(StrSection, Offset) when Offset < byte_size(StrSection) ->
    <<_:Offset/binary, Rest/binary>> = StrSection,
    case binary:match(Rest, <<0>>) of
        {Pos, 1} -> binary:part(Rest, 0, Pos);
        nomatch -> Rest
    end;
read_debug_str(_, _) ->
    <<>>.

%% ---------------------------------------------------------------------------
%% Internal — Abbreviation table lookup
%% ---------------------------------------------------------------------------

%% Look up an abbreviation code in .debug_abbrev starting at AbbrevOff.
%% Returns {ok, Tag, [{Attr, Form}]} or error.
lookup_abbrev(AbbrevSection, AbbrevOff, TargetCode) when
    AbbrevOff < byte_size(AbbrevSection)
->
    <<_:AbbrevOff/binary, AbbrevData/binary>> = AbbrevSection,
    scan_abbrev(AbbrevData, TargetCode);
lookup_abbrev(_, _, _) ->
    error.

-spec scan_abbrev(binary(), non_neg_integer()) ->
    {ok, non_neg_integer(), [{non_neg_integer(), non_neg_integer()}]} | error.
scan_abbrev(<<>>, _Target) ->
    error;
scan_abbrev(Bin, Target) ->
    case decode_uleb128(Bin) of
        {0, _} ->
            %% End of abbreviation table
            error;
        {Code, Rest1} ->
            {Tag, Rest2} = decode_uleb128(Rest1),
            %% Skip has_children byte
            <<_HasChildren:8, Rest3/binary>> = Rest2,
            {AttrSpecs, Rest4} = read_attr_specs(Rest3, []),
            case Code of
                Target ->
                    {ok, Tag, AttrSpecs};
                _ ->
                    scan_abbrev(Rest4, Target)
            end
    end.

%% Read (attr, form) pairs until (0, 0) sentinel.
%% For DW_FORM_implicit_const, an extra SLEB128 value follows in the abbrev table.
-spec read_attr_specs(binary(), [{non_neg_integer(), non_neg_integer()}]) ->
    {[{non_neg_integer(), non_neg_integer()}], binary()}.
read_attr_specs(Bin, Acc) ->
    {Attr, Rest1} = decode_uleb128(Bin),
    {Form, Rest2} = decode_uleb128(Rest1),
    case {Attr, Form} of
        {0, 0} ->
            {lists:reverse(Acc), Rest2};
        _ ->
            %% For implicit_const, skip the SLEB128 constant in the abbrev table
            Rest3 =
                case Form of
                    ?DW_FORM_implicit_const ->
                        {_Const, R} = decode_sleb128(Rest2),
                        R;
                    _ ->
                        Rest2
                end,
            read_attr_specs(Rest3, [{Attr, Form} | Acc])
    end.

%% ---------------------------------------------------------------------------
%% Internal — Form value reading
%% ---------------------------------------------------------------------------

read_form_value(Bin, ?DW_FORM_addr, AddrSize, _Endian) when
    byte_size(Bin) >= AddrSize
->
    <<Val:AddrSize/unit:8, Rest/binary>> = Bin,
    {ok, Val, Rest};
read_form_value(Bin, ?DW_FORM_data1, _AddrSize, _Endian) when
    byte_size(Bin) >= 1
->
    <<Val:8, Rest/binary>> = Bin,
    {ok, Val, Rest};
read_form_value(Bin, ?DW_FORM_data2, _AddrSize, Endian) when
    byte_size(Bin) >= 2
->
    {Val, Rest} = read_u16(Bin, Endian),
    {ok, Val, Rest};
read_form_value(Bin, ?DW_FORM_data4, _AddrSize, Endian) when
    byte_size(Bin) >= 4
->
    {Val, Rest} = read_u32(Bin, Endian),
    {ok, Val, Rest};
read_form_value(Bin, ?DW_FORM_data8, _AddrSize, Endian) when
    byte_size(Bin) >= 8
->
    {Val, Rest} = read_u64(Bin, Endian),
    {ok, Val, Rest};
read_form_value(Bin, ?DW_FORM_string, _AddrSize, _Endian) ->
    case binary:match(Bin, <<0>>) of
        {Pos, 1} ->
            Str = binary:part(Bin, 0, Pos),
            <<_:Pos/binary, 0, Rest/binary>> = Bin,
            {ok, Str, Rest};
        nomatch ->
            {error, unterminated_string}
    end;
read_form_value(Bin, ?DW_FORM_strp, _AddrSize, Endian) when
    byte_size(Bin) >= 4
->
    {Offset, Rest} = read_u32(Bin, Endian),
    {ok, Offset, Rest};
read_form_value(Bin, ?DW_FORM_line_strp, _AddrSize, Endian) when
    byte_size(Bin) >= 4
->
    {Offset, Rest} = read_u32(Bin, Endian),
    {ok, Offset, Rest};
read_form_value(Bin, ?DW_FORM_sec_offset, _AddrSize, Endian) when
    byte_size(Bin) >= 4
->
    {Val, Rest} = read_u32(Bin, Endian),
    {ok, Val, Rest};
read_form_value(Bin, ?DW_FORM_flag_present, _AddrSize, _Endian) ->
    %% Implicit true, consumes no bytes
    {ok, 1, Bin};
read_form_value(Bin, ?DW_FORM_exprloc, _AddrSize, _Endian) ->
    {Len, Rest1} = decode_uleb128(Bin),
    case byte_size(Rest1) >= Len of
        true ->
            <<_Expr:Len/binary, Rest2/binary>> = Rest1,
            {ok, skipped, Rest2};
        false ->
            {error, truncated}
    end;
read_form_value(Bin, ?DW_FORM_implicit_const, _AddrSize, _Endian) ->
    %% Value was in the abbrev table, not in the DIE stream.
    %% We don't track it, just return 0 and consume no bytes.
    {ok, 0, Bin};
read_form_value(_Bin, Form, _AddrSize, _Endian) ->
    {error, {unsupported_form, Form}}.

%% ---------------------------------------------------------------------------
%% Internal — Language decoding
%% ---------------------------------------------------------------------------

-spec decode_language(non_neg_integer()) ->
    c
    | c89
    | c99
    | c11
    | c17
    | cpp
    | cpp11
    | cpp14
    | go
    | rust
    | {unknown, non_neg_integer()}.
decode_language(?DW_LANG_C89) -> c89;
decode_language(?DW_LANG_C) -> c;
decode_language(?DW_LANG_C_plus_plus) -> cpp;
decode_language(?DW_LANG_C99) -> c99;
decode_language(?DW_LANG_Go) -> go;
decode_language(?DW_LANG_C_plus_plus_11) -> cpp11;
decode_language(?DW_LANG_Rust) -> rust;
decode_language(?DW_LANG_C11) -> c11;
decode_language(?DW_LANG_C_plus_plus_14) -> cpp14;
decode_language(?DW_LANG_C17) -> c17;
decode_language(V) -> {unknown, V}.

%% ---------------------------------------------------------------------------
%% Internal — .debug_line source file parsing
%% ---------------------------------------------------------------------------

-spec parse_line_units(binary(), little | big, [binary()]) -> [binary()].
parse_line_units(<<>>, _Endian, Acc) ->
    lists:usort(Acc);
parse_line_units(Bin, _Endian, Acc) when byte_size(Bin) < 4 ->
    lists:usort(Acc);
parse_line_units(Bin, Endian, Acc) ->
    {UnitLen, AfterLen} = read_u32(Bin, Endian),
    case UnitLen of
        16#FFFFFFFF ->
            %% 64-bit DWARF — skip
            lists:usort(Acc);
        _ when byte_size(AfterLen) < UnitLen ->
            lists:usort(Acc);
        _ ->
            <<UnitBody:UnitLen/binary, Rest/binary>> = AfterLen,
            Files = parse_line_unit_files(UnitBody, Endian),
            parse_line_units(Rest, Endian, Files ++ Acc)
    end.

-spec parse_line_unit_files(binary(), little | big) -> [binary()].
parse_line_unit_files(UnitBody, _Endian) when byte_size(UnitBody) < 2 ->
    [];
parse_line_unit_files(UnitBody, Endian) ->
    {Version, After1} = read_u16(UnitBody, Endian),
    case Version of
        4 -> parse_line_v4_files(After1, Endian);
        %% DWARF-5 or unknown — skip
        _ -> []
    end.

-spec parse_line_v4_files(binary(), little | big) -> [binary()].
parse_line_v4_files(Bin, _Endian) when byte_size(Bin) < 4 ->
    [];
parse_line_v4_files(Bin, Endian) ->
    {HeaderLen, AfterHL} = read_u32(Bin, Endian),
    case byte_size(AfterHL) >= HeaderLen of
        false ->
            [];
        true ->
            <<HeaderBody:HeaderLen/binary, _/binary>> = AfterHL,
            parse_line_v4_header(HeaderBody)
    end.

%% Skip past standard opcode lengths, then read include_directories, then file_names.
-spec parse_line_v4_header(binary()) -> [binary()].
parse_line_v4_header(Bin) when byte_size(Bin) < 5 ->
    [];
parse_line_v4_header(Bin) ->
    %% minimum_instruction_length: 1
    %% maximum_operations_per_instruction: 1
    %% default_is_stmt: 1
    %% line_base: 1 (signed)
    %% line_range: 1
    %% opcode_base: 1
    <<_MinInstLen:8, _MaxOpsPerInst:8, _DefaultIsStmt:8, _LineBase:8/signed, _LineRange:8,
        OpcodeBase:8, Rest/binary>> = Bin,
    %% standard_opcode_lengths: (opcode_base - 1) bytes
    NumOpcodes = OpcodeBase - 1,
    case byte_size(Rest) >= NumOpcodes of
        false ->
            [];
        true ->
            <<_OpcLens:NumOpcodes/binary, AfterOpc/binary>> = Rest,
            %% include_directories: null-terminated strings, terminated by empty string (\0)
            AfterDirs = skip_nul_string_sequence(AfterOpc),
            %% file_names: (name\0, dir_idx_uleb, mtime_uleb, size_uleb), terminated by \0
            parse_line_v4_file_names(AfterDirs, [])
    end.

%% Skip a sequence of NUL-terminated strings, terminated by an empty entry (single \0).
-spec skip_nul_string_sequence(binary()) -> binary().
skip_nul_string_sequence(<<0, Rest/binary>>) ->
    Rest;
skip_nul_string_sequence(Bin) ->
    case binary:match(Bin, <<0>>) of
        {Pos, 1} ->
            <<_:Pos/binary, 0, Rest/binary>> = Bin,
            skip_nul_string_sequence(Rest);
        nomatch ->
            <<>>
    end.

%% Parse DWARF-4 file name entries from .debug_line.
-spec parse_line_v4_file_names(binary(), [binary()]) -> [binary()].
parse_line_v4_file_names(<<0, _/binary>>, Acc) ->
    lists:reverse(Acc);
parse_line_v4_file_names(<<>>, Acc) ->
    lists:reverse(Acc);
parse_line_v4_file_names(Bin, Acc) ->
    case binary:match(Bin, <<0>>) of
        {Pos, 1} ->
            Name = binary:part(Bin, 0, Pos),
            <<_:Pos/binary, 0, Rest1/binary>> = Bin,
            %% Skip dir_index, mtime, size (all ULEB128)
            {_, Rest2} = decode_uleb128(Rest1),
            {_, Rest3} = decode_uleb128(Rest2),
            {_, Rest4} = decode_uleb128(Rest3),
            parse_line_v4_file_names(Rest4, [Name | Acc]);
        nomatch ->
            lists:reverse(Acc)
    end.

%% ---------------------------------------------------------------------------
%% Internal — ULEB128 / SLEB128 / integer reading
%% ---------------------------------------------------------------------------

-spec decode_uleb128(binary()) -> {non_neg_integer(), binary()}.
decode_uleb128(Bin) ->
    decode_uleb128(Bin, 0, 0).

decode_uleb128(<<Byte:8, Rest/binary>>, Shift, Acc) ->
    Value = Acc bor ((Byte band 16#7F) bsl Shift),
    case Byte band 16#80 of
        0 -> {Value, Rest};
        _ -> decode_uleb128(Rest, Shift + 7, Value)
    end;
decode_uleb128(<<>>, _Shift, Acc) ->
    {Acc, <<>>}.

-spec decode_sleb128(binary()) -> {integer(), binary()}.
decode_sleb128(Bin) ->
    decode_sleb128(Bin, 0, 0).

decode_sleb128(<<Byte:8, Rest/binary>>, Shift, Acc) ->
    Value = Acc bor ((Byte band 16#7F) bsl Shift),
    case Byte band 16#80 of
        0 ->
            %% Sign extend if needed
            case Byte band 16#40 of
                0 -> {Value, Rest};
                _ -> {Value - (1 bsl (Shift + 7)), Rest}
            end;
        _ ->
            decode_sleb128(Rest, Shift + 7, Value)
    end;
decode_sleb128(<<>>, _Shift, Acc) ->
    {Acc, <<>>}.

read_u16(<<V:16/little, Rest/binary>>, little) -> {V, Rest};
read_u16(<<V:16/big, Rest/binary>>, big) -> {V, Rest}.

read_u32(<<V:32/little, Rest/binary>>, little) -> {V, Rest};
read_u32(<<V:32/big, Rest/binary>>, big) -> {V, Rest}.

read_u64(<<V:64/little, Rest/binary>>, little) -> {V, Rest};
read_u64(<<V:64/big, Rest/binary>>, big) -> {V, Rest}.
