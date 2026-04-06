-module(elf_lang_dwarf_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("elf_parse.hrl").
-include("elf_lang_dwarf.hrl").

%% ---------------------------------------------------------------------------
%% Test DWARF binary construction helpers
%% ---------------------------------------------------------------------------

%% Strings in .debug_str at known offsets:
%%   0: "clang version 15.0.0"
%%   21: "test.c"
%%   28: "/home/user/src"
-define(STR_PRODUCER, <<"clang version 15.0.0">>).
-define(STR_NAME, <<"test.c">>).
-define(STR_COMPDIR, <<"/home/user/src">>).
-define(STR_OFF_PRODUCER, 0).
-define(STR_OFF_NAME, 21).
-define(STR_OFF_COMPDIR, 28).

make_debug_str() ->
    <<?STR_PRODUCER/binary, 0, ?STR_NAME/binary, 0, ?STR_COMPDIR/binary, 0>>.

%% Build a .debug_abbrev section with one abbreviation:
%%   code=1, tag=DW_TAG_compile_unit(0x11), has_children=1
%%   attrs: producer/strp, language/data2, name/strp, comp_dir/strp
%%   terminated by (0,0)
make_debug_abbrev() ->
    %% abbrev code 1 (ULEB128)
    <<1,
        %% tag (ULEB128)
        ?DW_TAG_compile_unit,
        %% has_children = yes
        1, ?DW_AT_producer, ?DW_FORM_strp, ?DW_AT_language, ?DW_FORM_data2, ?DW_AT_name,
        ?DW_FORM_strp, ?DW_AT_comp_dir, ?DW_FORM_strp,
        %% end of attr specs
        0, 0,
        %% end of abbreviation table
        0>>.

%% Build a DWARF-4 .debug_info CU with one compile_unit DIE.
make_debug_info_v4() ->
    %% DIE: abbrev_code=1, producer strp, language data2 (C99=0x0C), name strp, comp_dir strp

    %% abbrev code 1 (ULEB128)
    Die =
        <<1, ?STR_OFF_PRODUCER:32/little, ?DW_LANG_C99:16/little, ?STR_OFF_NAME:32/little,
            ?STR_OFF_COMPDIR:32/little>>,
    %% CU header: version=4, abbrev_offset=0, address_size=8

    %% version
    CUHeader =
        <<4:16/little,
            %% abbrev_offset
            0:32/little,
            %% address_size
            8:8>>,
    CUBody = <<CUHeader/binary, Die/binary>>,
    UnitLen = byte_size(CUBody),
    <<UnitLen:32/little, CUBody/binary>>.

%% Build a DWARF-5 .debug_info CU.
make_debug_info_v5() ->
    Die =
        <<1, ?STR_OFF_PRODUCER:32/little,
            %% Go
            16#0016:16/little, ?STR_OFF_NAME:32/little, ?STR_OFF_COMPDIR:32/little>>,
    %% DWARF-5: version=5, unit_type=0x01 (DW_UT_compile), address_size=8, abbrev_offset=0
    CUHeader =
        <<5:16/little,
            %% unit_type
            16#01:8,
            %% address_size
            8:8,
            %% abbrev_offset
            0:32/little>>,
    CUBody = <<CUHeader/binary, Die/binary>>,
    UnitLen = byte_size(CUBody),
    <<UnitLen:32/little, CUBody/binary>>.

%% Build a minimal ELF with DWARF sections.
%% Sections: null, .debug_info, .debug_abbrev, .debug_str, .shstrtab
make_elf_with_dwarf(DebugInfo, DebugAbbrev, DebugStr) ->
    make_elf_with_dwarf(DebugInfo, DebugAbbrev, DebugStr, <<>>).

make_elf_with_dwarf(DebugInfo, DebugAbbrev, DebugStr, DebugLine) ->
    HasLine = byte_size(DebugLine) > 0,
    %% .shstrtab content
    ShStrTab =
        case HasLine of
            false ->
                <<0, ".debug_info", 0, ".debug_abbrev", 0, ".debug_str", 0, ".shstrtab", 0>>;
            true ->
                <<0, ".debug_info", 0, ".debug_abbrev", 0, ".debug_str", 0, ".debug_line", 0,
                    ".shstrtab", 0>>
        end,

    %% Name offsets in .shstrtab
    %% <<0, ".debug_info"(1..11), 0(12), ".debug_abbrev"(13..25), 0(26),
    %%   ".debug_str"(27..36), 0(37), ...>>
    DebugInfoNameIdx = 1,
    DebugAbbrevNameIdx = 13,
    DebugStrNameIdx = 27,
    {DebugLineNameIdx, ShstrtabNameIdx} =
        case HasLine of
            false -> {0, 38};
            true -> {38, 50}
        end,

    NumSections =
        case HasLine of
            false -> 5;
            true -> 6
        end,

    %% Layout:
    %%   0x000  ELF header (64)
    %%   0x040  .debug_info
    %%   0x040+DiSz  .debug_abbrev
    %%   ...    .debug_str
    %%   ...    .debug_line (optional)
    %%   ...    .shstrtab
    %%   aligned to 8  section headers
    DiOff = 64,
    DiSz = byte_size(DebugInfo),
    DaOff = DiOff + DiSz,
    DaSz = byte_size(DebugAbbrev),
    DsOff = DaOff + DaSz,
    DsSz = byte_size(DebugStr),
    {DlOff, DlSz, SsOff} =
        case HasLine of
            false ->
                {0, 0, DsOff + DsSz};
            true ->
                DlO = DsOff + DsSz,
                DlS = byte_size(DebugLine),
                {DlO, DlS, DlO + DlS}
        end,
    SsSz = byte_size(ShStrTab),
    ShdrOff0 = SsOff + SsSz,
    %% Align to 8
    ShdrOff = (ShdrOff0 + 7) band (bnot 7),
    PadSize = ShdrOff - ShdrOff0,

    Header = elf_header_le(
        16#02,
        16#3E,
        0,
        0,
        ShdrOff,
        0,
        NumSections,
        NumSections - 1
    ),

    Shdr0 = shdr_le(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    Shdr1 = shdr_le(DebugInfoNameIdx, 1, 0, 0, DiOff, DiSz, 0, 0, 1, 0),
    Shdr2 = shdr_le(DebugAbbrevNameIdx, 1, 0, 0, DaOff, DaSz, 0, 0, 1, 0),
    Shdr3 = shdr_le(DebugStrNameIdx, 3, 0, 0, DsOff, DsSz, 0, 0, 1, 0),
    LineShdrs =
        case HasLine of
            false -> <<>>;
            true -> shdr_le(DebugLineNameIdx, 1, 0, 0, DlOff, DlSz, 0, 0, 1, 0)
        end,
    ShdrLast = shdr_le(ShstrtabNameIdx, 3, 0, 0, SsOff, SsSz, 0, 0, 1, 0),

    Pad = <<0:(PadSize * 8)>>,
    <<Header/binary, DebugInfo/binary, DebugAbbrev/binary, DebugStr/binary,
        (case HasLine of
            false -> <<>>;
            true -> DebugLine
        end)/binary, ShStrTab/binary, Pad/binary, Shdr0/binary, Shdr1/binary, Shdr2/binary,
        Shdr3/binary, LineShdrs/binary, ShdrLast/binary>>.

%% Minimal ELF without any debug sections.
make_elf_no_debug() ->
    ShStrTab = <<0, ".shstrtab", 0>>,
    SsSz = byte_size(ShStrTab),
    SsOff = 64,
    ShdrOff0 = SsOff + SsSz,
    ShdrOff = (ShdrOff0 + 7) band (bnot 7),
    PadSize = ShdrOff - ShdrOff0,

    Header = elf_header_le(16#02, 16#3E, 0, 0, ShdrOff, 0, 2, 1),
    Shdr0 = shdr_le(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    Shdr1 = shdr_le(1, 3, 0, 0, SsOff, SsSz, 0, 0, 1, 0),
    Pad = <<0:(PadSize * 8)>>,
    <<Header/binary, ShStrTab/binary, Pad/binary, Shdr0/binary, Shdr1/binary>>.

%% ---------------------------------------------------------------------------
%% Binary construction helpers (LE only — matches existing test style)
%% ---------------------------------------------------------------------------

elf_header_le(Type, Machine, Entry, PhOff, ShOff, PhNum, ShNum, ShStrNdx) ->
    <<16#7F, "ELF", 2:8, 1:8, 1:8, 0:8, 0:64, Type:16/little, Machine:16/little, 1:32/little,
        Entry:64/little, PhOff:64/little, ShOff:64/little, 0:32/little, 64:16/little, 56:16/little,
        PhNum:16/little, 64:16/little, ShNum:16/little, ShStrNdx:16/little>>.

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

%% ---------------------------------------------------------------------------
%% Tests — has_debug_info
%% ---------------------------------------------------------------------------

has_debug_info_true_test() ->
    Bin = make_elf_with_dwarf(make_debug_info_v4(), make_debug_abbrev(), make_debug_str()),
    {ok, Elf} = elf_parse:from_binary(Bin),
    ?assert(elf_lang_dwarf:has_debug_info(Elf)).

has_debug_info_false_test() ->
    Bin = make_elf_no_debug(),
    {ok, Elf} = elf_parse:from_binary(Bin),
    ?assertNot(elf_lang_dwarf:has_debug_info(Elf)).

%% ---------------------------------------------------------------------------
%% Tests — compilation_units
%% ---------------------------------------------------------------------------

compilation_units_v4_test() ->
    Bin = make_elf_with_dwarf(make_debug_info_v4(), make_debug_abbrev(), make_debug_str()),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, [CU]} = elf_lang_dwarf:compilation_units(Elf),
    ?assertEqual(?STR_PRODUCER, CU#dwarf_cu.producer),
    ?assertEqual(c99, CU#dwarf_cu.language),
    ?assertEqual(?STR_NAME, CU#dwarf_cu.name),
    ?assertEqual(?STR_COMPDIR, CU#dwarf_cu.comp_dir),
    ?assertEqual(4, CU#dwarf_cu.version).

compilation_units_v5_test() ->
    Bin = make_elf_with_dwarf(make_debug_info_v5(), make_debug_abbrev(), make_debug_str()),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, [CU]} = elf_lang_dwarf:compilation_units(Elf),
    ?assertEqual(?STR_PRODUCER, CU#dwarf_cu.producer),
    ?assertEqual(go, CU#dwarf_cu.language),
    ?assertEqual(5, CU#dwarf_cu.version).

compilation_units_no_debug_test() ->
    Bin = make_elf_no_debug(),
    {ok, Elf} = elf_parse:from_binary(Bin),
    ?assertEqual({error, no_debug_info}, elf_lang_dwarf:compilation_units(Elf)).

compilation_units_multiple_test() ->
    %% Two CUs concatenated in .debug_info
    DI = <<(make_debug_info_v4())/binary, (make_debug_info_v5())/binary>>,
    Bin = make_elf_with_dwarf(DI, make_debug_abbrev(), make_debug_str()),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, CUs} = elf_lang_dwarf:compilation_units(Elf),
    ?assertEqual(2, length(CUs)),
    [CU1, CU2] = CUs,
    ?assertEqual(c99, CU1#dwarf_cu.language),
    ?assertEqual(go, CU2#dwarf_cu.language).

%% ---------------------------------------------------------------------------
%% Tests — DWARF-5 header field order
%% ---------------------------------------------------------------------------

dwarf5_header_parsing_test() ->
    %% Verify DWARF-5 CU parses correctly with different field order
    Bin = make_elf_with_dwarf(make_debug_info_v5(), make_debug_abbrev(), make_debug_str()),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, [CU]} = elf_lang_dwarf:compilation_units(Elf),
    ?assertEqual(5, CU#dwarf_cu.version),
    ?assertEqual(?STR_NAME, CU#dwarf_cu.name),
    ?assertEqual(?STR_COMPDIR, CU#dwarf_cu.comp_dir).

%% ---------------------------------------------------------------------------
%% Tests — ULEB128 edge cases
%% ---------------------------------------------------------------------------

uleb128_single_byte_test() ->
    %% 0x00 = 0
    {ok, Elf} = make_elf_with_null_die(),
    {ok, [CU]} = elf_lang_dwarf:compilation_units(Elf),
    %% Null DIE (abbrev code 0) → all fields undefined
    ?assertEqual(undefined, CU#dwarf_cu.producer).

uleb128_multibyte_test() ->
    %% Value 624485 = 0xE5, 0x8E, 0x26 in ULEB128
    %% Test via an abbreviation code that is multi-byte ULEB128
    %% We just verify the module handles it without crashing
    %% by building an abbrev with code 128 (requires 2 ULEB128 bytes: 0x80, 0x01)

    %% ULEB128 for 128
    AbbrevCode128 = <<128, 1>>,
    Abbrev =
        <<AbbrevCode128/binary, ?DW_TAG_compile_unit,
            %% has_children
            1, ?DW_AT_producer, ?DW_FORM_strp, ?DW_AT_language, ?DW_FORM_data2, 0, 0, 0>>,
    Die = <<AbbrevCode128/binary, ?STR_OFF_PRODUCER:32/little, ?DW_LANG_Rust:16/little>>,
    CUHeader = <<4:16/little, 0:32/little, 8:8>>,
    CUBody = <<CUHeader/binary, Die/binary>>,
    UnitLen = byte_size(CUBody),
    DebugInfo = <<UnitLen:32/little, CUBody/binary>>,
    Bin = make_elf_with_dwarf(DebugInfo, Abbrev, make_debug_str()),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, [CU]} = elf_lang_dwarf:compilation_units(Elf),
    ?assertEqual(rust, CU#dwarf_cu.language),
    ?assertEqual(?STR_PRODUCER, CU#dwarf_cu.producer).

%% ---------------------------------------------------------------------------
%% Tests — source_files
%% ---------------------------------------------------------------------------

source_files_no_section_test() ->
    Bin = make_elf_no_debug(),
    {ok, Elf} = elf_parse:from_binary(Bin),
    ?assertEqual({error, no_debug_line}, elf_lang_dwarf:source_files(Elf)).

source_files_v4_test() ->
    DebugLine = make_debug_line_v4(),
    Bin = make_elf_with_dwarf(
        make_debug_info_v4(),
        make_debug_abbrev(),
        make_debug_str(),
        DebugLine
    ),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Files} = elf_lang_dwarf:source_files(Elf),
    ?assert(lists:member(<<"main.c">>, Files)),
    ?assert(lists:member(<<"util.c">>, Files)).

%% ---------------------------------------------------------------------------
%% Tests — language decoding
%% ---------------------------------------------------------------------------

language_decoding_test() ->
    Langs = [
        {16#0001, c89},
        {16#0002, c},
        {16#0004, cpp},
        {16#000C, c99},
        {16#0016, go},
        {16#001A, cpp11},
        {16#001C, rust},
        {16#001D, c11},
        {16#0021, cpp14},
        {16#002C, c17},
        {16#FFFF, {unknown, 16#FFFF}}
    ],
    lists:foreach(
        fun({Code, Expected}) ->
            Die =
                <<1, ?STR_OFF_PRODUCER:32/little, Code:16/little, ?STR_OFF_NAME:32/little,
                    ?STR_OFF_COMPDIR:32/little>>,
            CUHeader = <<4:16/little, 0:32/little, 8:8>>,
            CUBody = <<CUHeader/binary, Die/binary>>,
            UnitLen = byte_size(CUBody),
            DebugInfo = <<UnitLen:32/little, CUBody/binary>>,
            ElfBin = make_elf_with_dwarf(DebugInfo, make_debug_abbrev(), make_debug_str()),
            {ok, Elf} = elf_parse:from_binary(ElfBin),
            {ok, [CU]} = elf_lang_dwarf:compilation_units(Elf),
            ?assertEqual(Expected, CU#dwarf_cu.language)
        end,
        Langs
    ).

%% ---------------------------------------------------------------------------
%% Internal test helpers
%% ---------------------------------------------------------------------------

%% Build an ELF with a null DIE (abbrev code 0) in .debug_info.
make_elf_with_null_die() ->
    %% null DIE
    Die = <<0>>,
    CUHeader = <<4:16/little, 0:32/little, 8:8>>,
    CUBody = <<CUHeader/binary, Die/binary>>,
    UnitLen = byte_size(CUBody),
    DebugInfo = <<UnitLen:32/little, CUBody/binary>>,
    Bin = make_elf_with_dwarf(DebugInfo, make_debug_abbrev(), make_debug_str()),
    elf_parse:from_binary(Bin).

%% Build a minimal DWARF-4 .debug_line section with two files.
make_debug_line_v4() ->
    %% include_directories: "/src\0" terminated by \0
    IncDirs = <<"/src", 0, 0>>,
    %% file_names: "main.c\0" dir=1 mtime=0 size=0, "util.c\0" dir=1 mtime=0 size=0, \0
    FileNames = <<"main.c", 0, 1, 0, 0, "util.c", 0, 1, 0, 0, 0>>,
    %% Header fields (after version and header_length):
    %% min_inst_len=1, max_ops=1, default_is_stmt=1, line_base=-5, line_range=14, opcode_base=13
    %% standard_opcode_lengths: 12 bytes (opcode_base - 1 = 12)
    StdOpcLens = <<0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1>>,
    HeaderBody =
        <<1:8, 1:8, 1:8, (256 - 5):8, 14:8, 13:8, StdOpcLens/binary, IncDirs/binary,
            FileNames/binary>>,
    HeaderLen = byte_size(HeaderBody),
    %% A minimal line program (just end sequence): extended opcode 1 (DW_LNE_end_sequence)
    LineProgram = <<0, 1, 1>>,
    UnitBody = <<4:16/little, HeaderLen:32/little, HeaderBody/binary, LineProgram/binary>>,
    UnitLen = byte_size(UnitBody),
    <<UnitLen:32/little, UnitBody/binary>>.
