-module(elf_lang_go_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("elf_parse.hrl").
-include("elf_lang_go.hrl").

%% ---------------------------------------------------------------------------
%% ELF binary construction helpers (LE, x86_64)
%% ---------------------------------------------------------------------------

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

%% ---------------------------------------------------------------------------
%% Varint encoding helper
%% ---------------------------------------------------------------------------

encode_varint(N) when N < 128 ->
    <<N:8>>;
encode_varint(N) ->
    Low = (N band 16#7F) bor 16#80,
    Rest = N bsr 7,
    <<Low:8, (encode_varint(Rest))/binary>>.

encode_varint_string(Str) when is_binary(Str) ->
    Len = byte_size(Str),
    LenEnc = encode_varint(Len),
    <<LenEnc/binary, Str/binary>>.

%% ---------------------------------------------------------------------------
%% .go.buildinfo section construction (inline strings, flags bit1 set)
%% ---------------------------------------------------------------------------

make_buildinfo_section(Version, ModInfo) ->
    %% 14-byte magic + 1 byte PtrSize + 1 byte Flags
    Magic = <<16#FF, " Go buildinf:">>,
    PtrSize = 8,
    %% bit1 set = inline strings
    Flags = 2,
    Header16 = <<Magic/binary, PtrSize:8, Flags:8>>,
    %% Pad to 32 bytes
    PadLen = 32 - byte_size(Header16),
    Pad = <<0:(PadLen * 8)>>,
    VerStr = encode_varint_string(Version),
    ModStr = encode_varint_string(ModInfo),
    <<Header16/binary, Pad/binary, VerStr/binary, ModStr/binary>>.

%% ---------------------------------------------------------------------------
%% .gopclntab section construction (Go 1.20+ format)
%% ---------------------------------------------------------------------------

%% Build a minimal gopclntab with function entries.
%% FuncSpecs: [{Name :: binary(), EntryOffset :: non_neg_integer()}]
make_gopclntab(FuncSpecs, TextStart) ->
    PtrSize = 8,
    PtrBits = PtrSize * 8,
    Nfunc = length(FuncSpecs),
    Nfiles = 0,

    %% We need to calculate offsets. Layout within gopclntab:
    %%   0:    magic (4) + pad (2) + minLC (1) + ptrSize (1) = 8 bytes
    %%   8:    nfunc (P) + nfiles (P) + textStart (P) +
    %%         funcnameOff (P) + cutabOff (P) + filetabOff (P) +
    %%         pctabOff (P) + pcDataOff (P) = 8*P bytes
    %%   8+8P: func table: Nfunc * 8 bytes (2 * uint32 per entry)
    %%   After func table: funcname table (null-terminated strings)
    %%   After funcname table: pcData area (func metadata, 8 bytes each)
    HeaderSize = 8 + 8 * PtrSize,
    FuncTabSize = Nfunc * 8,
    FuncTabStart = HeaderSize,

    %% Build funcname table: concatenate null-terminated strings
    {FuncnameTab, NameOffsets} = build_funcname_table(FuncSpecs),
    FuncnameTabStart = FuncTabStart + FuncTabSize,

    %% Build pcData area: for each func, 4-byte entryOff + 4-byte nameOff
    PcDataStart = FuncnameTabStart + byte_size(FuncnameTab),
    PcDataEntries = build_pcdata_entries(FuncSpecs, NameOffsets),

    %% Now build header
    FuncnameOff = FuncnameTabStart,
    CutabOff = 0,
    FiletabOff = 0,
    PctabOff = 0,
    PcDataOff = PcDataStart,

    Magic = <<16#F1, 16#FF, 16#FF, 16#FF>>,
    Pad = <<0, 0>>,
    MinLC = 1,

    Header =
        <<Magic/binary, Pad/binary, MinLC:8, PtrSize:8, Nfunc:PtrBits/little, Nfiles:PtrBits/little,
            TextStart:PtrBits/little, FuncnameOff:PtrBits/little, CutabOff:PtrBits/little,
            FiletabOff:PtrBits/little, PctabOff:PtrBits/little, PcDataOff:PtrBits/little>>,

    %% Build func table entries
    FuncTab = build_func_table(FuncSpecs, Nfunc),

    <<Header/binary, FuncTab/binary, FuncnameTab/binary, PcDataEntries/binary>>.

build_funcname_table(FuncSpecs) ->
    build_funcname_table(FuncSpecs, <<>>, []).

build_funcname_table([], Acc, Offsets) ->
    {Acc, lists:reverse(Offsets)};
build_funcname_table([{Name, _EntryOff} | Rest], Acc, Offsets) ->
    Offset = byte_size(Acc),
    NewAcc = <<Acc/binary, Name/binary, 0>>,
    build_funcname_table(Rest, NewAcc, [Offset | Offsets]).

build_func_table(FuncSpecs, _Nfunc) ->
    build_func_table_entries(FuncSpecs, 0, <<>>).

build_func_table_entries([], _Idx, Acc) ->
    Acc;
build_func_table_entries([{_Name, EntryOff} | Rest], Idx, Acc) ->
    %% FuncDataOff = Idx * 8 (each metadata entry is 8 bytes)
    FuncDataOff = Idx * 8,
    Entry = <<EntryOff:32/little, FuncDataOff:32/little>>,
    build_func_table_entries(Rest, Idx + 1, <<Acc/binary, Entry/binary>>).

build_pcdata_entries(FuncSpecs, NameOffsets) ->
    build_pcdata_entries(FuncSpecs, NameOffsets, <<>>).

build_pcdata_entries([], [], Acc) ->
    Acc;
build_pcdata_entries([{_Name, EntryOff} | FRest], [NameOff | NRest], Acc) ->
    Entry = <<EntryOff:32/little, NameOff:32/little>>,
    build_pcdata_entries(FRest, NRest, <<Acc/binary, Entry/binary>>).

%% ---------------------------------------------------------------------------
%% Full ELF binary construction with Go sections
%% ---------------------------------------------------------------------------

-define(TEXT_VADDR, 16#400000).

make_go_elf(BuildInfoData, GopclntabData) ->
    %% Strtab: "\0.text\0.go.buildinfo\0.gopclntab\0.shstrtab\0"
    StrTab = <<0, ".text", 0, ".go.buildinfo", 0, ".gopclntab", 0, ".shstrtab", 0>>,
    StrTabSize = byte_size(StrTab),

    TextContent = <<16#90, 16#90, 16#90, 16#C3>>,
    TextSize = byte_size(TextContent),
    BuildInfoSize = byte_size(BuildInfoData),
    GopclntabSize = byte_size(GopclntabData),

    %% Layout:
    %%   0x000  ELF header (64)
    %%   0x040  Phdr: PT_LOAD (56)
    %%   0x078  .text (4)
    %%   0x07C  .go.buildinfo (variable)
    %%   ...    .gopclntab (variable)
    %%   ...    .shstrtab (variable)
    %%   ...    pad to 8-byte alignment
    %%   ...    Section headers (5 * 64 = 320)
    TextOff = 16#078,
    BuildInfoOff = TextOff + TextSize,
    GopclntabOff = BuildInfoOff + BuildInfoSize,
    StrtabOff = GopclntabOff + GopclntabSize,
    ShdrOffUnaligned = StrtabOff + StrTabSize,
    %% Align to 8 bytes
    ShdrOff = (ShdrOffUnaligned + 7) band (bnot 7),
    PadSize = ShdrOff - ShdrOffUnaligned,

    NumSections = 5,
    Header = elf_header_le(
        ?ET_EXEC,
        ?EM_X86_64,
        ?TEXT_VADDR,
        64,
        ShdrOff,
        1,
        NumSections,
        4
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

    %% Section 0: null
    Shdr0 = shdr_le(0, ?SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0),
    %% Section 1: .text (name_idx=1)
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
    %% Section 2: .go.buildinfo (name_idx=7)
    Shdr2 = shdr_le(
        7,
        ?SHT_PROGBITS,
        0,
        0,
        BuildInfoOff,
        BuildInfoSize,
        0,
        0,
        1,
        0
    ),
    %% Section 3: .gopclntab (name_idx=21)
    Shdr3 = shdr_le(
        21,
        ?SHT_PROGBITS,
        0,
        0,
        GopclntabOff,
        GopclntabSize,
        0,
        0,
        1,
        0
    ),
    %% Section 4: .shstrtab (name_idx=32)
    Shdr4 = shdr_le(32, ?SHT_STRTAB, 0, 0, StrtabOff, StrTabSize, 0, 0, 1, 0),

    Pad = <<0:(PadSize * 8)>>,
    <<Header/binary, Phdr/binary, TextContent/binary, BuildInfoData/binary, GopclntabData/binary,
        StrTab/binary, Pad/binary, Shdr0/binary, Shdr1/binary, Shdr2/binary, Shdr3/binary,
        Shdr4/binary>>.

%% Build ELF with only .go.buildinfo (no gopclntab)
make_go_elf_buildinfo_only(BuildInfoData) ->
    StrTab = <<0, ".text", 0, ".go.buildinfo", 0, ".shstrtab", 0>>,
    StrTabSize = byte_size(StrTab),

    TextContent = <<16#90, 16#90, 16#90, 16#C3>>,
    TextSize = byte_size(TextContent),
    BuildInfoSize = byte_size(BuildInfoData),

    TextOff = 16#078,
    BuildInfoOff = TextOff + TextSize,
    StrtabOff = BuildInfoOff + BuildInfoSize,
    ShdrOffUnaligned = StrtabOff + StrTabSize,
    ShdrOff = (ShdrOffUnaligned + 7) band (bnot 7),
    PadSize = ShdrOff - ShdrOffUnaligned,

    NumSections = 4,
    Header = elf_header_le(
        ?ET_EXEC,
        ?EM_X86_64,
        ?TEXT_VADDR,
        64,
        ShdrOff,
        1,
        NumSections,
        3
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
    Shdr2 = shdr_le(
        7,
        ?SHT_PROGBITS,
        0,
        0,
        BuildInfoOff,
        BuildInfoSize,
        0,
        0,
        1,
        0
    ),
    Shdr3 = shdr_le(21, ?SHT_STRTAB, 0, 0, StrtabOff, StrTabSize, 0, 0, 1, 0),

    Pad = <<0:(PadSize * 8)>>,
    <<Header/binary, Phdr/binary, TextContent/binary, BuildInfoData/binary, StrTab/binary,
        Pad/binary, Shdr0/binary, Shdr1/binary, Shdr2/binary, Shdr3/binary>>.

%% Plain ELF with no Go sections
make_plain_elf() ->
    StrTab = <<0, ".text", 0, ".shstrtab", 0>>,
    StrTabSize = byte_size(StrTab),
    TextContent = <<16#90, 16#90, 16#90, 16#C3>>,
    TextSize = byte_size(TextContent),

    TextOff = 16#078,
    StrtabOff = TextOff + TextSize,
    ShdrOffUnaligned = StrtabOff + StrTabSize,
    ShdrOff = (ShdrOffUnaligned + 7) band (bnot 7),
    PadSize = ShdrOff - ShdrOffUnaligned,

    Header = elf_header_le(
        ?ET_EXEC,
        ?EM_X86_64,
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

%% ---------------------------------------------------------------------------
%% Test data
%% ---------------------------------------------------------------------------

sample_mod_info() ->
    <<
        "path\tgithub.com/user/app\n"
        "mod\tgithub.com/user/app\t(devel)\t\n"
        "dep\tgithub.com/lib/pq\tv1.10.9\th1:abc123=\n"
        "dep\tgolang.org/x/text\tv0.14.0\th1:def456=\n"
        "build\tGOOS=linux\n"
        "build\tGOARCH=amd64\n"
    >>.

sample_func_specs() ->
    [
        {<<"runtime.goexit">>, 16#1000},
        {<<"main.main">>, 16#2000},
        {<<"github.com/user/pkg.Handler">>, 16#3000},
        {<<"github.com/user/pkg.init">>, 16#3100}
    ].

%% ===========================================================================
%% Tests
%% ===========================================================================

%% --- is_go/1 ---

is_go_detects_go_binary_test() ->
    BuildInfo = make_buildinfo_section(<<"go1.22.1">>, sample_mod_info()),
    Gopclntab = make_gopclntab(sample_func_specs(), ?TEXT_VADDR),
    Bin = make_go_elf(BuildInfo, Gopclntab),
    {ok, Elf} = elf_parse:from_binary(Bin),
    ?assert(elf_lang_go:is_go(Elf)).

is_go_false_for_plain_binary_test() ->
    Bin = make_plain_elf(),
    {ok, Elf} = elf_parse:from_binary(Bin),
    ?assertNot(elf_lang_go:is_go(Elf)).

%% --- not_go error ---

not_go_parse_error_test() ->
    Bin = make_plain_elf(),
    {ok, Elf} = elf_parse:from_binary(Bin),
    ?assertEqual({error, not_go}, elf_lang_go:parse(Elf)).

not_go_functions_error_test() ->
    Bin = make_plain_elf(),
    {ok, Elf} = elf_parse:from_binary(Bin),
    ?assertEqual({error, not_found}, elf_lang_go:functions(Elf)).

not_go_deps_error_test() ->
    Bin = make_plain_elf(),
    {ok, Elf} = elf_parse:from_binary(Bin),
    ?assertEqual({error, not_found}, elf_lang_go:deps(Elf)).

%% --- buildinfo parsing ---

buildinfo_version_test() ->
    BuildInfo = make_buildinfo_section(<<"go1.22.1">>, sample_mod_info()),
    Bin = make_go_elf_buildinfo_only(BuildInfo),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Info} = elf_lang_go:parse(Elf),
    ?assertEqual(<<"go1.22.1">>, Info#go_info.version),
    ?assertEqual(<<"go1.22.1">>, Info#go_info.go_version_raw).

buildinfo_module_test() ->
    BuildInfo = make_buildinfo_section(<<"go1.22.1">>, sample_mod_info()),
    Bin = make_go_elf_buildinfo_only(BuildInfo),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Info} = elf_lang_go:parse(Elf),
    ?assertEqual(<<"github.com/user/app">>, Info#go_info.main_module),
    ?assertEqual(<<"(devel)">>, Info#go_info.mod_version).

buildinfo_deps_test() ->
    BuildInfo = make_buildinfo_section(<<"go1.22.1">>, sample_mod_info()),
    Bin = make_go_elf_buildinfo_only(BuildInfo),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Deps} = elf_lang_go:deps(Elf),
    ?assertEqual(2, length(Deps)),
    [Dep1, Dep2] = Deps,
    ?assertEqual(<<"github.com/lib/pq">>, Dep1#go_dep.path),
    ?assertEqual(<<"v1.10.9">>, Dep1#go_dep.version),
    ?assertEqual(<<"h1:abc123=">>, Dep1#go_dep.hash),
    ?assertEqual(<<"golang.org/x/text">>, Dep2#go_dep.path),
    ?assertEqual(<<"v0.14.0">>, Dep2#go_dep.version).

buildinfo_settings_test() ->
    BuildInfo = make_buildinfo_section(<<"go1.22.1">>, sample_mod_info()),
    Bin = make_go_elf_buildinfo_only(BuildInfo),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Info} = elf_lang_go:parse(Elf),
    Settings = Info#go_info.build_settings,
    ?assert(lists:member({<<"GOOS">>, <<"linux">>}, Settings)),
    ?assert(lists:member({<<"GOARCH">>, <<"amd64">>}, Settings)).

%% --- gopclntab parsing ---

gopclntab_functions_test() ->
    BuildInfo = make_buildinfo_section(<<"go1.22.1">>, <<>>),
    FuncSpecs = sample_func_specs(),
    Gopclntab = make_gopclntab(FuncSpecs, ?TEXT_VADDR),
    Bin = make_go_elf(BuildInfo, Gopclntab),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Funcs} = elf_lang_go:functions(Elf),
    ?assertEqual(4, length(Funcs)),
    [F1, F2, F3, F4] = Funcs,
    ?assertEqual(<<"runtime.goexit">>, F1#go_func.name),
    ?assertEqual(?TEXT_VADDR + 16#1000, F1#go_func.entry),
    ?assertEqual(<<"runtime">>, F1#go_func.package),
    ?assertEqual(<<"main.main">>, F2#go_func.name),
    ?assertEqual(?TEXT_VADDR + 16#2000, F2#go_func.entry),
    ?assertEqual(<<"main">>, F2#go_func.package),
    ?assertEqual(<<"github.com/user/pkg.Handler">>, F3#go_func.name),
    ?assertEqual(?TEXT_VADDR + 16#3000, F3#go_func.entry),
    ?assertEqual(<<"github.com/user/pkg">>, F3#go_func.package),
    ?assertEqual(<<"github.com/user/pkg.init">>, F4#go_func.name),
    ?assertEqual(<<"github.com/user/pkg">>, F4#go_func.package).

%% --- function_package_map/1 ---

function_package_map_test() ->
    BuildInfo = make_buildinfo_section(<<"go1.22.1">>, <<>>),
    Gopclntab = make_gopclntab(sample_func_specs(), ?TEXT_VADDR),
    Bin = make_go_elf(BuildInfo, Gopclntab),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Map} = elf_lang_go:function_package_map(Elf),
    ?assertEqual(3, maps:size(Map)),
    ?assert(maps:is_key(<<"runtime">>, Map)),
    ?assert(maps:is_key(<<"main">>, Map)),
    ?assert(maps:is_key(<<"github.com/user/pkg">>, Map)),
    PkgFuncs = maps:get(<<"github.com/user/pkg">>, Map),
    ?assertEqual(2, length(PkgFuncs)).

%% --- parse/1 combines both sources ---

parse_full_test() ->
    BuildInfo = make_buildinfo_section(<<"go1.22.1">>, sample_mod_info()),
    Gopclntab = make_gopclntab(sample_func_specs(), ?TEXT_VADDR),
    Bin = make_go_elf(BuildInfo, Gopclntab),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Info} = elf_lang_go:parse(Elf),
    %% Version from buildinfo
    ?assertEqual(<<"go1.22.1">>, Info#go_info.version),
    %% Module from buildinfo
    ?assertEqual(<<"github.com/user/app">>, Info#go_info.main_module),
    %% Deps from buildinfo
    ?assertEqual(2, length(Info#go_info.deps)),
    %% Functions from gopclntab
    ?assertEqual(4, length(Info#go_info.functions)),
    %% Build settings from buildinfo
    ?assert(length(Info#go_info.build_settings) > 0).

%% --- varint encoding edge cases ---

varint_small_test() ->
    %% 5 encodes as <<5>>
    Encoded = encode_varint(5),
    ?assertEqual(<<5>>, Encoded).

varint_300_test() ->
    %% 300 = 0b100101100
    %% Lower 7 bits: 0101100 = 44, with continuation: 44 + 128 = 172
    %% Upper bits: 10 = 2
    Encoded = encode_varint(300),
    ?assertEqual(<<172, 2>>, Encoded).

%% --- buildinfo with empty module info ---

buildinfo_empty_modinfo_test() ->
    BuildInfo = make_buildinfo_section(<<"go1.21.0">>, <<>>),
    Bin = make_go_elf_buildinfo_only(BuildInfo),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Info} = elf_lang_go:parse(Elf),
    ?assertEqual(<<"go1.21.0">>, Info#go_info.version),
    ?assertEqual(undefined, Info#go_info.main_module),
    ?assertEqual([], Info#go_info.deps).
