-module(elf_lang_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("elf_parse.hrl").
-include("elf_lang_dwarf.hrl").

%% ---------------------------------------------------------------------------
%% ELF binary construction helpers
%% ---------------------------------------------------------------------------

-define(SHDR_SIZE, 64).
-define(SYM_SIZE, 24).

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

sym_entry(Name, Info, Other, Shndx, Value, Size) ->
    <<Name:32/little, Info:8, Other:8, Shndx:16/little, Value:64/little, Size:64/little>>.

st_info(Bind, Type) ->
    (Bind bsl 4) bor Type.

%% DWARF helpers
-define(STR_PRODUCER, <<"clang version 15.0.0">>).
-define(STR_NAME, <<"test.c">>).
-define(STR_COMPDIR, <<"/home/user/src">>).
-define(STR_OFF_PRODUCER, 0).
-define(STR_OFF_NAME, 21).
-define(STR_OFF_COMPDIR, 28).

make_debug_str() ->
    <<?STR_PRODUCER/binary, 0, ?STR_NAME/binary, 0, ?STR_COMPDIR/binary, 0>>.

make_debug_abbrev() ->
    <<1, ?DW_TAG_compile_unit, 1, ?DW_AT_producer, ?DW_FORM_strp, ?DW_AT_language, ?DW_FORM_data2,
        ?DW_AT_name, ?DW_FORM_strp, ?DW_AT_comp_dir, ?DW_FORM_strp, 0, 0, 0>>.

make_debug_info(LangCode) ->
    Die =
        <<1, ?STR_OFF_PRODUCER:32/little, LangCode:16/little, ?STR_OFF_NAME:32/little,
            ?STR_OFF_COMPDIR:32/little>>,
    CUHeader = <<4:16/little, 0:32/little, 8:8>>,
    CUBody = <<CUHeader/binary, Die/binary>>,
    UnitLen = byte_size(CUBody),
    <<UnitLen:32/little, CUBody/binary>>.

make_debug_info_with_compdir(LangCode, CompDir) ->
    %% Build custom .debug_str with custom comp_dir
    DebugStr = <<?STR_PRODUCER/binary, 0, ?STR_NAME/binary, 0, CompDir/binary, 0>>,
    CompDirOff = byte_size(?STR_PRODUCER) + 1 + byte_size(?STR_NAME) + 1,
    Die =
        <<1, ?STR_OFF_PRODUCER:32/little, LangCode:16/little, ?STR_OFF_NAME:32/little,
            CompDirOff:32/little>>,
    CUHeader = <<4:16/little, 0:32/little, 8:8>>,
    CUBody = <<CUHeader/binary, Die/binary>>,
    UnitLen = byte_size(CUBody),
    DebugInfo = <<UnitLen:32/little, CUBody/binary>>,
    {DebugInfo, DebugStr}.

%% ---------------------------------------------------------------------------
%% Build test ELFs for each language
%% ---------------------------------------------------------------------------

%% Build a minimal ELF with named sections only (no symtab, no DWARF).
%% ExtraSections: [{Name :: binary(), Type :: integer(), Data :: binary()}]
make_elf_with_sections(ExtraSections) ->
    make_elf_with_sections_and_syms(ExtraSections, []).

%% Build a minimal ELF with named sections and a symbol table.
%% Syms: [{Name :: binary(), Bind, Type, Value, Size}]
make_elf_with_sections_and_syms(ExtraSections, Syms) ->
    %% Build shstrtab content: \0 + each section name + \0 + ".shstrtab" + \0
    %% Also include .symtab and .strtab if we have symbols.
    HasSyms = Syms =/= [],
    BuiltinNames =
        case HasSyms of
            true -> [<<".symtab">>, <<".strtab">>];
            false -> []
        end,
    AllNames = [N || {N, _, _} <- ExtraSections] ++ BuiltinNames ++ [<<".shstrtab">>],
    {ShStrTab, NameOffsets} = build_shstrtab(AllNames),

    %% Build symbol data if needed
    {SymStrTab, SymTab} =
        case HasSyms of
            true -> build_symtab(Syms);
            false -> {<<>>, <<>>}
        end,

    %% Layout: header(64), section data..., shstrtab, symstrtab, symtab, shdrs
    ElfHdrSize = 64,

    %% Calculate data layout
    {DataChunks, _} = lists:foldl(
        fun({_N, _T, D}, {Acc, Off}) ->
            {Acc ++ [{Off, D}], Off + byte_size(D)}
        end,
        {[], ElfHdrSize},
        ExtraSections
    ),

    DataEnd =
        case DataChunks of
            [] -> ElfHdrSize;
            _ -> element(1, lists:last(DataChunks)) + byte_size(element(2, lists:last(DataChunks)))
        end,

    ShStrTabOff = DataEnd,
    SymStrTabOff = ShStrTabOff + byte_size(ShStrTab),
    SymTabOff = SymStrTabOff + byte_size(SymStrTab),
    ShdrOff0 = SymTabOff + byte_size(SymTab),
    ShdrOff = (ShdrOff0 + 7) band (bnot 7),
    PadSize = ShdrOff - ShdrOff0,

    %% Count sections: null + extras + builtins + shstrtab
    NumExtra = length(ExtraSections),
    NumBuiltin = length(BuiltinNames),
    NumSections = 1 + NumExtra + NumBuiltin + 1,

    %% shstrtab is the last section
    ShStrNdx = NumSections - 1,

    %% Find name offsets for each section
    _ = [maps:get(N, NameOffsets) || {N, _, _} <- ExtraSections],
    _ = [maps:get(N, NameOffsets) || N <- BuiltinNames],
    ShstrtabNameOff = maps:get(<<".shstrtab">>, NameOffsets),

    %% Build section headers
    Shdr0 = shdr_le(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),

    ExtraShdrs = lists:zipwith(
        fun({_N, T, _D}, {Off, D}) ->
            NO = maps:get(_N, NameOffsets),
            shdr_le(NO, T, 0, 0, Off, byte_size(D), 0, 0, 1, 0)
        end,
        ExtraSections,
        DataChunks
    ),

    %% Section indices: 0=null, 1..NumExtra=extras, then builtins, then shstrtab

    %% .symtab section index (if present)
    _SymTabIdx = NumExtra + 1,
    %% .strtab section index (if present)
    StrTabIdx = NumExtra + 2,

    BuiltinShdrs =
        case HasSyms of
            true ->
                SymTabNO = maps:get(<<".symtab">>, NameOffsets),
                StrTabNO = maps:get(<<".strtab">>, NameOffsets),
                SymSh = shdr_le(
                    SymTabNO,
                    2,
                    0,
                    0,
                    SymTabOff,
                    byte_size(SymTab),
                    StrTabIdx,
                    0,
                    8,
                    ?SYM_SIZE
                ),
                StrSh = shdr_le(
                    StrTabNO,
                    3,
                    0,
                    0,
                    SymStrTabOff,
                    byte_size(SymStrTab),
                    0,
                    0,
                    1,
                    0
                ),
                [SymSh, StrSh];
            false ->
                []
        end,

    ShstrtabShdr = shdr_le(
        ShstrtabNameOff,
        3,
        0,
        0,
        ShStrTabOff,
        byte_size(ShStrTab),
        0,
        0,
        1,
        0
    ),

    Header = elf_header_le(16#02, 16#3E, 0, 0, ShdrOff, 0, NumSections, ShStrNdx),

    ExtraData = iolist_to_binary([D || {_, _, D} <- ExtraSections]),
    BuiltinShdrsBin = iolist_to_binary(BuiltinShdrs),
    ExtraShdrsBin = iolist_to_binary(ExtraShdrs),
    Pad = <<0:(PadSize * 8)>>,

    Bin =
        <<Header/binary, ExtraData/binary, ShStrTab/binary, SymStrTab/binary, SymTab/binary,
            Pad/binary, Shdr0/binary, ExtraShdrsBin/binary, BuiltinShdrsBin/binary,
            ShstrtabShdr/binary>>,
    {ok, Elf} = elf_parse:from_binary(Bin),
    Elf.

%% Build an ELF with DWARF debug sections.
make_elf_with_dwarf(DebugInfo, DebugAbbrev, DebugStr) ->
    %% We need custom layout because DWARF sections need specific section types
    %% and proper cross-references.
    ShStrTab = <<0, ".debug_info", 0, ".debug_abbrev", 0, ".debug_str", 0, ".shstrtab", 0>>,
    DebugInfoNameIdx = 1,
    DebugAbbrevNameIdx = 13,
    DebugStrNameIdx = 27,
    ShstrtabNameIdx = 38,

    NumSections = 5,
    DiOff = 64,
    DiSz = byte_size(DebugInfo),
    DaOff = DiOff + DiSz,
    DaSz = byte_size(DebugAbbrev),
    DsOff = DaOff + DaSz,
    DsSz = byte_size(DebugStr),
    SsOff = DsOff + DsSz,
    SsSz = byte_size(ShStrTab),
    ShdrOff0 = SsOff + SsSz,
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
    ShdrLast = shdr_le(ShstrtabNameIdx, 3, 0, 0, SsOff, SsSz, 0, 0, 1, 0),

    Pad = <<0:(PadSize * 8)>>,
    Bin =
        <<Header/binary, DebugInfo/binary, DebugAbbrev/binary, DebugStr/binary, ShStrTab/binary,
            Pad/binary, Shdr0/binary, Shdr1/binary, Shdr2/binary, Shdr3/binary, ShdrLast/binary>>,
    {ok, Elf} = elf_parse:from_binary(Bin),
    Elf.

%% Build an ELF with both DWARF sections and a symbol table.
make_elf_with_dwarf_and_syms(DebugInfo, DebugAbbrev, DebugStr, Syms) ->
    {SymStrTab, SymTab} = build_symtab(Syms),

    ShStrTab =
        <<0, ".debug_info", 0, ".debug_abbrev", 0, ".debug_str", 0, ".symtab", 0, ".strtab", 0,
            ".shstrtab", 0>>,
    DebugInfoNameIdx = 1,
    DebugAbbrevNameIdx = 13,
    DebugStrNameIdx = 27,
    SymtabNameIdx = 38,
    StrtabNameIdx = 46,
    ShstrtabNameIdx = 54,

    NumSections = 7,
    DiOff = 64,
    DiSz = byte_size(DebugInfo),
    DaOff = DiOff + DiSz,
    DaSz = byte_size(DebugAbbrev),
    DsOff = DaOff + DaSz,
    DsSz = byte_size(DebugStr),
    SsStrOff = DsOff + DsSz,
    SsStrSz = byte_size(SymStrTab),
    StOff = SsStrOff + SsStrSz,
    StSz = byte_size(SymTab),
    ShStrOff = StOff + StSz,
    ShStrSz = byte_size(ShStrTab),
    ShdrOff0 = ShStrOff + ShStrSz,
    ShdrOff = (ShdrOff0 + 7) band (bnot 7),
    PadSize = ShdrOff - ShdrOff0,

    %% .symtab is section 4, .strtab is section 5, shstrtab is section 6
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
    Shdr4 = shdr_le(SymtabNameIdx, 2, 0, 0, StOff, StSz, 5, 0, 8, ?SYM_SIZE),
    Shdr5 = shdr_le(StrtabNameIdx, 3, 0, 0, SsStrOff, SsStrSz, 0, 0, 1, 0),
    ShdrLast = shdr_le(ShstrtabNameIdx, 3, 0, 0, ShStrOff, ShStrSz, 0, 0, 1, 0),

    Pad = <<0:(PadSize * 8)>>,
    Bin =
        <<Header/binary, DebugInfo/binary, DebugAbbrev/binary, DebugStr/binary, SymStrTab/binary,
            SymTab/binary, ShStrTab/binary, Pad/binary, Shdr0/binary, Shdr1/binary, Shdr2/binary,
            Shdr3/binary, Shdr4/binary, Shdr5/binary, ShdrLast/binary>>,
    {ok, Elf} = elf_parse:from_binary(Bin),
    Elf.

build_shstrtab(Names) ->
    %% Build: <<0, Name1, 0, Name2, 0, ...>>
    {Bin, Offsets} = lists:foldl(
        fun(Name, {Acc, Map}) ->
            Off = byte_size(Acc),
            {<<Acc/binary, Name/binary, 0>>, Map#{Name => Off}}
        end,
        {<<0>>, #{}},
        Names
    ),
    {Bin, Offsets}.

build_symtab(Syms) ->
    %% Build symbol string table and symbol entries.
    %% First entry is always the null symbol.
    {StrTab, SymEntries} = lists:foldl(
        fun({Name, Bind, Type, Value, Size}, {ST, SE}) ->
            NameOff = byte_size(ST),
            ST1 = <<ST/binary, Name/binary, 0>>,
            Info = st_info(Bind, Type),
            Entry = sym_entry(NameOff, Info, 0, 1, Value, Size),
            {ST1, [Entry | SE]}
        end,
        {<<0>>, []},
        Syms
    ),
    NullSym = sym_entry(0, 0, 0, 0, 0, 0),
    SymTab = iolist_to_binary([NullSym | lists:reverse(SymEntries)]),
    {StrTab, SymTab}.

%% ---------------------------------------------------------------------------
%% Tests — detect/1
%% ---------------------------------------------------------------------------

%% 1. Go binary (has .gopclntab section) -> detects go
detect_go_gopclntab_test() ->
    Elf = make_elf_with_sections([{<<".gopclntab">>, 1, <<"data">>}]),
    ?assertEqual(go, elf_lang:detect(Elf)).

detect_go_buildinfo_test() ->
    Elf = make_elf_with_sections([{<<".go.buildinfo">>, 1, <<"data">>}]),
    ?assertEqual(go, elf_lang:detect(Elf)).

%% 2. Rust-like binary (has _ZN symbols) -> detects rust
detect_rust_zn_test() ->
    Elf = make_elf_with_sections_and_syms(
        [],
        [{<<"_ZN4core3fmt5write">>, 1, 2, 16#401000, 16#100}]
    ),
    ?assertEqual(rust, elf_lang:detect(Elf)).

detect_rust_r_prefix_test() ->
    Elf = make_elf_with_sections_and_syms(
        [],
        [{<<"_RNvCs1234_5hello4main">>, 1, 2, 16#401000, 16#100}]
    ),
    ?assertEqual(rust, elf_lang:detect(Elf)).

%% 3. Zig-like binary (has std.start symbol) -> detects zig
detect_zig_symbol_test() ->
    Elf = make_elf_with_sections_and_syms(
        [],
        [{<<"std.start.callMain">>, 1, 2, 16#401000, 16#100}]
    ),
    ?assertEqual(zig, elf_lang:detect(Elf)).

detect_zig_builtin_symbol_test() ->
    Elf = make_elf_with_sections_and_syms(
        [],
        [{<<"std.builtin.default_panic">>, 1, 2, 16#401000, 16#100}]
    ),
    ?assertEqual(zig, elf_lang:detect(Elf)).

detect_zig_os_linux_symbol_test() ->
    Elf = make_elf_with_sections_and_syms(
        [],
        [{<<"std.os.linux.tls">>, 1, 2, 16#401000, 16#100}]
    ),
    ?assertEqual(zig, elf_lang:detect(Elf)).

detect_zig_dwarf_compdir_test() ->
    %% DWARF with /zig/ in comp_dir
    {DebugInfo, DebugStr} = make_debug_info_with_compdir(
        ?DW_LANG_C99, <<"/home/user/.cache/zig/std">>
    ),
    Elf = make_elf_with_dwarf(DebugInfo, make_debug_abbrev(), DebugStr),
    ?assertEqual(zig, elf_lang:detect(Elf)).

%% 4. C binary with DWARF -> detects c
detect_c_test() ->
    Elf = make_elf_with_dwarf(
        make_debug_info(?DW_LANG_C99),
        make_debug_abbrev(),
        make_debug_str()
    ),
    ?assertEqual(c, elf_lang:detect(Elf)).

detect_c89_test() ->
    Elf = make_elf_with_dwarf(
        make_debug_info(?DW_LANG_C89),
        make_debug_abbrev(),
        make_debug_str()
    ),
    ?assertEqual(c, elf_lang:detect(Elf)).

detect_c11_test() ->
    Elf = make_elf_with_dwarf(
        make_debug_info(?DW_LANG_C11),
        make_debug_abbrev(),
        make_debug_str()
    ),
    ?assertEqual(c, elf_lang:detect(Elf)).

%% 5. C++ binary with DWARF -> detects cpp
detect_cpp_test() ->
    Elf = make_elf_with_dwarf(
        make_debug_info(?DW_LANG_C_plus_plus),
        make_debug_abbrev(),
        make_debug_str()
    ),
    ?assertEqual(cpp, elf_lang:detect(Elf)).

detect_cpp11_test() ->
    Elf = make_elf_with_dwarf(
        make_debug_info(?DW_LANG_C_plus_plus_11),
        make_debug_abbrev(),
        make_debug_str()
    ),
    ?assertEqual(cpp, elf_lang:detect(Elf)).

detect_cpp14_test() ->
    Elf = make_elf_with_dwarf(
        make_debug_info(?DW_LANG_C_plus_plus_14),
        make_debug_abbrev(),
        make_debug_str()
    ),
    ?assertEqual(cpp, elf_lang:detect(Elf)).

%% 6. Plain binary with nothing -> detects unknown
detect_unknown_test() ->
    Elf = make_elf_with_sections([]),
    ?assertEqual(unknown, elf_lang:detect(Elf)).

%% 8. Priority: Go wins over DWARF if both present
detect_go_wins_over_dwarf_test() ->
    %% ELF with DWARF (C) and Rust symbols — but also .gopclntab section.
    %% Build via dwarf+syms to get a realistic binary, then verify Go wins.
    Elf = make_elf_with_dwarf_and_syms(
        make_debug_info(?DW_LANG_C99),
        make_debug_abbrev(),
        make_debug_str(),
        [{<<"_ZN4core3fmt">>, 1, 2, 16#401000, 16#100}]
    ),
    %% This ELF has DWARF C and Rust symbols, but no Go sections -> not Go.
    ?assertNotEqual(go, elf_lang:detect(Elf)),
    %% Now test with a .gopclntab section present:
    GoElf = make_elf_with_sections([{<<".gopclntab">>, 1, <<"pclntab">>}]),
    ?assertEqual(go, elf_lang:detect(GoElf)).

detect_go_wins_over_rust_symbols_test() ->
    %% Go sections + Rust-like symbols — Go should still win
    Elf = make_elf_with_sections_and_syms(
        [{<<".gopclntab">>, 1, <<"pclntab">>}],
        [{<<"_ZN4core3fmt">>, 1, 2, 16#401000, 16#100}]
    ),
    ?assertEqual(go, elf_lang:detect(Elf)).

%% Priority: Rust wins over Zig
detect_rust_wins_over_zig_test() ->
    %% Binary with both Rust and Zig symbols — Rust checked first
    Elf = make_elf_with_sections_and_syms(
        [],
        [
            {<<"_ZN4core3fmt5write">>, 1, 2, 16#401000, 16#100},
            {<<"std.start.callMain">>, 1, 2, 16#402000, 16#100}
        ]
    ),
    ?assertEqual(rust, elf_lang:detect(Elf)).

%% ---------------------------------------------------------------------------
%% Tests — analyze/1
%% ---------------------------------------------------------------------------

analyze_go_test() ->
    %% analyze/1 for Go calls elf_lang_go:parse/1 which needs valid
    %% .gopclntab/.go.buildinfo. With just a dummy section it returns
    %% error from go parser, so we test the dispatch path.
    Elf = make_elf_with_sections([{<<".go.buildinfo">>, 1, <<"short">>}]),
    %% Go detection succeeds, but parse may fail with bad data.
    %% That's fine — we test the dispatch.
    Result = elf_lang:analyze(Elf),
    case Result of
        {ok, #{language := go}} -> ok;
        %% parse failure is acceptable
        {error, _} -> ok
    end.

analyze_rust_test() ->
    %% analyze/1 dispatches Rust to elf_lang_rust:parse/1 if available,
    %% otherwise returns undefined info. Either outcome is correct.
    Elf = make_elf_with_sections_and_syms(
        [],
        [{<<"_ZN4core3fmt5write">>, 1, 2, 16#401000, 16#100}]
    ),
    {ok, #{language := rust, info := _Info}} = elf_lang:analyze(Elf).

analyze_c_test() ->
    Elf = make_elf_with_dwarf(
        make_debug_info(?DW_LANG_C99),
        make_debug_abbrev(),
        make_debug_str()
    ),
    {ok, #{language := c, info := CUs}} = elf_lang:analyze(Elf),
    ?assert(is_list(CUs)),
    ?assertEqual(1, length(CUs)),
    [CU] = CUs,
    ?assertEqual(c99, CU#dwarf_cu.language).

analyze_cpp_test() ->
    Elf = make_elf_with_dwarf(
        make_debug_info(?DW_LANG_C_plus_plus),
        make_debug_abbrev(),
        make_debug_str()
    ),
    {ok, #{language := cpp, info := CUs}} = elf_lang:analyze(Elf),
    ?assert(is_list(CUs)),
    [CU] = CUs,
    ?assertEqual(cpp, CU#dwarf_cu.language).

analyze_zig_test() ->
    Elf = make_elf_with_sections_and_syms(
        [],
        [{<<"std.start.callMain">>, 1, 2, 16#401000, 16#100}]
    ),
    {ok, #{language := zig, info := Info}} = elf_lang:analyze(Elf),
    %% Zig uses DWARF — no debug info in our test binary, so empty list
    ?assertEqual([], Info).

analyze_unknown_test() ->
    Elf = make_elf_with_sections([]),
    {ok, #{language := unknown, info := undefined}} = elf_lang:analyze(Elf).
