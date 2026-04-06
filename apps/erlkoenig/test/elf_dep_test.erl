-module(elf_dep_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("elf_parse.hrl").
-include("elf_lang_go.hrl").
-include("elf_lang_rust.hrl").

%% ---------------------------------------------------------------------------
%% ELF binary construction helpers (LE, x86_64)
%% ---------------------------------------------------------------------------

-define(TEXT_VADDR, 16#400000).

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
%% .go.buildinfo section construction
%% ---------------------------------------------------------------------------

make_buildinfo_section(Version, ModInfo) ->
    Magic = <<16#FF, " Go buildinf:">>,
    PtrSize = 8,
    Flags = 2,
    Header16 = <<Magic/binary, PtrSize:8, Flags:8>>,
    PadLen = 32 - byte_size(Header16),
    Pad = <<0:(PadLen * 8)>>,
    VerStr = encode_varint_string(Version),
    ModStr = encode_varint_string(ModInfo),
    <<Header16/binary, Pad/binary, VerStr/binary, ModStr/binary>>.

%% ---------------------------------------------------------------------------
%% .gopclntab section construction (Go 1.20+ format)
%% ---------------------------------------------------------------------------

make_gopclntab(FuncSpecs, TextStart) ->
    PtrSize = 8,
    PtrBits = PtrSize * 8,
    Nfunc = length(FuncSpecs),
    Nfiles = 0,

    HeaderSize = 8 + 8 * PtrSize,
    FuncTabSize = Nfunc * 8,
    FuncTabStart = HeaderSize,

    {FuncnameTab, NameOffsets} = build_funcname_table(FuncSpecs),
    FuncnameTabStart = FuncTabStart + FuncTabSize,

    PcDataStart = FuncnameTabStart + byte_size(FuncnameTab),
    PcDataEntries = build_pcdata_entries(FuncSpecs, NameOffsets),

    FuncnameOff = FuncnameTabStart,
    CutabOff = 0,
    FiletabOff = 0,
    PctabOff = 0,
    PcDataOff = PcDataStart,

    Magic = <<16#F1, 16#FF, 16#FF, 16#FF>>,
    PadBytes = <<0, 0>>,
    MinLC = 1,

    Header =
        <<Magic/binary, PadBytes/binary, MinLC:8, PtrSize:8, Nfunc:PtrBits/little,
            Nfiles:PtrBits/little, TextStart:PtrBits/little, FuncnameOff:PtrBits/little,
            CutabOff:PtrBits/little, FiletabOff:PtrBits/little, PctabOff:PtrBits/little,
            PcDataOff:PtrBits/little>>,

    FuncTab = build_func_table(FuncSpecs),

    <<Header/binary, FuncTab/binary, FuncnameTab/binary, PcDataEntries/binary>>.

build_funcname_table(FuncSpecs) ->
    build_funcname_table(FuncSpecs, <<>>, []).

build_funcname_table([], Acc, Offsets) ->
    {Acc, lists:reverse(Offsets)};
build_funcname_table([{Name, _EntryOff} | Rest], Acc, Offsets) ->
    Offset = byte_size(Acc),
    NewAcc = <<Acc/binary, Name/binary, 0>>,
    build_funcname_table(Rest, NewAcc, [Offset | Offsets]).

build_func_table(FuncSpecs) ->
    build_func_table_entries(FuncSpecs, 0, <<>>).

build_func_table_entries([], _Idx, Acc) ->
    Acc;
build_func_table_entries([{_Name, EntryOff} | Rest], Idx, Acc) ->
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
%% x86-64 syscall sequence: MOV EAX, <imm32> ; SYSCALL
%% ---------------------------------------------------------------------------

x86_64_syscall_seq(Nr) ->
    <<16#B8, Nr:32/little, 16#0F, 16#05>>.

%% ---------------------------------------------------------------------------
%% Full ELF binary construction with Go sections + .text with syscalls
%% ---------------------------------------------------------------------------

%% Build a Go ELF with .text containing syscall instructions at specific
%% addresses aligned with gopclntab function entries.
make_go_elf_with_syscalls(BuildInfoData, GopclntabData, TextContent, TextSize) ->
    StrTab = <<0, ".text", 0, ".go.buildinfo", 0, ".gopclntab", 0, ".shstrtab", 0>>,
    StrTabSize = byte_size(StrTab),

    BuildInfoSize = byte_size(BuildInfoData),
    GopclntabSize = byte_size(GopclntabData),

    TextOff = 16#078,
    BuildInfoOff = TextOff + TextSize,
    GopclntabOff = BuildInfoOff + BuildInfoSize,
    StrtabOff = GopclntabOff + GopclntabSize,
    ShdrOffUnaligned = StrtabOff + StrTabSize,
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
    Shdr4 = shdr_le(32, ?SHT_STRTAB, 0, 0, StrtabOff, StrTabSize, 0, 0, 1, 0),

    Pad = <<0:(PadSize * 8)>>,
    <<Header/binary, Phdr/binary, TextContent/binary, BuildInfoData/binary, GopclntabData/binary,
        StrTab/binary, Pad/binary, Shdr0/binary, Shdr1/binary, Shdr2/binary, Shdr3/binary,
        Shdr4/binary>>.

%% Standard Go ELF with NOP .text (no syscalls)
make_go_elf(BuildInfoData, GopclntabData) ->
    TextContent = <<16#90, 16#90, 16#90, 16#C3>>,
    TextSize = byte_size(TextContent),
    make_go_elf_with_syscalls(BuildInfoData, GopclntabData, TextContent, TextSize).

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

%% ===========================================================================
%% Tests — deps/1
%% ===========================================================================

deps_go_binary_test() ->
    BuildInfo = make_buildinfo_section(<<"go1.22.1">>, sample_mod_info()),
    FuncSpecs = [
        {<<"runtime.goexit">>, 16#1000},
        {<<"main.main">>, 16#2000}
    ],
    Gopclntab = make_gopclntab(FuncSpecs, ?TEXT_VADDR),
    Bin = make_go_elf(BuildInfo, Gopclntab),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Deps} = elf_dep:deps(Elf),
    ?assertEqual(2, length(Deps)),
    [D1, D2] = Deps,
    ?assertEqual(<<"github.com/lib/pq">>, maps:get(name, D1)),
    ?assertEqual(<<"v1.10.9">>, maps:get(version, D1)),
    ?assertEqual(go_buildinfo, maps:get(source, D1)),
    ?assertEqual(<<"golang.org/x/text">>, maps:get(name, D2)),
    ?assertEqual(<<"v0.14.0">>, maps:get(version, D2)).

deps_go_no_deps_test() ->
    BuildInfo = make_buildinfo_section(<<"go1.22.1">>, <<>>),
    FuncSpecs = [{<<"main.main">>, 16#1000}],
    Gopclntab = make_gopclntab(FuncSpecs, ?TEXT_VADDR),
    Bin = make_go_elf(BuildInfo, Gopclntab),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Deps} = elf_dep:deps(Elf),
    ?assertEqual([], Deps).

deps_plain_binary_test() ->
    Bin = make_plain_elf(),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Deps} = elf_dep:deps(Elf),
    ?assertEqual([], Deps).

deps_go_buildinfo_only_test() ->
    BuildInfo = make_buildinfo_section(<<"go1.22.1">>, sample_mod_info()),
    Bin = make_go_elf_buildinfo_only(BuildInfo),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Deps} = elf_dep:deps(Elf),
    ?assertEqual(2, length(Deps)).

%% ===========================================================================
%% Tests — capabilities/1
%% ===========================================================================

capabilities_go_basic_test() ->
    %% Create a Go binary where:
    %% - Function "net/http.Get" at offset 0x0000 (vaddr TEXT_VADDR + 0)
    %%   contains a socket(41) syscall
    %% - Function "fmt.Sprintf" at offset 0x0020 (vaddr TEXT_VADDR + 0x20)
    %%   contains a mmap(9) syscall
    %%
    %% .text layout (using small offsets and NOP padding):
    %%   0x0000: MOV EAX, 41; SYSCALL  (7 bytes: socket)
    %%   0x0007..0x001F: NOPs (padding)
    %%   0x0020: MOV EAX, 9; SYSCALL   (7 bytes: mmap)
    %%   0x0027..0x003F: NOPs (padding)

    %% socket
    SyscallNet = x86_64_syscall_seq(41),
    %% mmap
    SyscallMem = x86_64_syscall_seq(9),
    Pad1 = binary:copy(<<16#90>>, 16#20 - byte_size(SyscallNet)),
    Pad2 = binary:copy(<<16#90>>, 16#20 - byte_size(SyscallMem)),
    TextContent = <<SyscallNet/binary, Pad1/binary, SyscallMem/binary, Pad2/binary>>,
    TextSize = byte_size(TextContent),

    FuncSpecs = [
        {<<"net/http.Get">>, 16#0000},
        {<<"fmt.Sprintf">>, 16#0020}
    ],
    Gopclntab = make_gopclntab(FuncSpecs, ?TEXT_VADDR),
    BuildInfo = make_buildinfo_section(<<"go1.22.1">>, <<>>),
    Bin = make_go_elf_with_syscalls(BuildInfo, Gopclntab, TextContent, TextSize),
    {ok, Elf} = elf_parse:from_binary(Bin),

    {ok, Caps} = elf_dep:capabilities(Elf),

    %% net/http should have network capability (socket)
    ?assert(maps:is_key(<<"net/http">>, Caps)),
    NetCaps = maps:get(<<"net/http">>, Caps),
    ?assert(lists:member(network, maps:get(categories, NetCaps))),
    ?assert(lists:member(<<"socket">>, maps:get(syscalls, NetCaps))),

    %% fmt should have memory capability (mmap)
    ?assert(maps:is_key(<<"fmt">>, Caps)),
    FmtCaps = maps:get(<<"fmt">>, Caps),
    ?assert(lists:member(memory, maps:get(categories, FmtCaps))),
    ?assert(lists:member(<<"mmap">>, maps:get(syscalls, FmtCaps))).

capabilities_unsupported_language_test() ->
    Bin = make_plain_elf(),
    {ok, Elf} = elf_parse:from_binary(Bin),
    ?assertEqual({error, unsupported_language}, elf_dep:capabilities(Elf)).

capabilities_no_syscalls_test() ->
    %% Go binary with no syscalls in .text
    FuncSpecs = [{<<"main.main">>, 16#0000}],
    Gopclntab = make_gopclntab(FuncSpecs, ?TEXT_VADDR),
    BuildInfo = make_buildinfo_section(<<"go1.22.1">>, <<>>),
    Bin = make_go_elf(BuildInfo, Gopclntab),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Caps} = elf_dep:capabilities(Elf),
    ?assertEqual(#{}, Caps).

capabilities_multiple_syscalls_same_package_test() ->
    %% Two syscalls in the same package range

    %% socket
    Syscall1 = x86_64_syscall_seq(41),
    %% connect
    Syscall2 = x86_64_syscall_seq(42),
    Pad = binary:copy(<<16#90>>, 16#20 - byte_size(Syscall1) - byte_size(Syscall2)),
    TextContent = <<Syscall1/binary, Syscall2/binary, Pad/binary>>,
    TextSize = byte_size(TextContent),

    FuncSpecs = [{<<"net/http.Get">>, 16#0000}],
    Gopclntab = make_gopclntab(FuncSpecs, ?TEXT_VADDR),
    BuildInfo = make_buildinfo_section(<<"go1.22.1">>, <<>>),
    Bin = make_go_elf_with_syscalls(BuildInfo, Gopclntab, TextContent, TextSize),
    {ok, Elf} = elf_parse:from_binary(Bin),

    {ok, Caps} = elf_dep:capabilities(Elf),
    NetCaps = maps:get(<<"net/http">>, Caps),
    %% Both socket and connect should be listed
    ?assert(lists:member(<<"socket">>, maps:get(syscalls, NetCaps))),
    ?assert(lists:member(<<"connect">>, maps:get(syscalls, NetCaps))),
    %% But only one category: network
    ?assertEqual([network], maps:get(categories, NetCaps)).

%% ===========================================================================
%% Tests — anomalies/2
%% ===========================================================================

anomalies_detects_unexpected_capability_test() ->
    %% "encoding/json" package with a socket syscall is anomalous

    %% socket = network
    Syscall = x86_64_syscall_seq(41),
    Pad = binary:copy(<<16#90>>, 16#20 - byte_size(Syscall)),
    TextContent = <<Syscall/binary, Pad/binary>>,
    TextSize = byte_size(TextContent),

    FuncSpecs = [{<<"encoding/json.Marshal">>, 16#0000}],
    Gopclntab = make_gopclntab(FuncSpecs, ?TEXT_VADDR),
    BuildInfo = make_buildinfo_section(<<"go1.22.1">>, <<>>),
    Bin = make_go_elf_with_syscalls(BuildInfo, Gopclntab, TextContent, TextSize),
    {ok, Elf} = elf_parse:from_binary(Bin),

    Expected = #{<<"encoding/json">> => [memory]},
    Anomalies = elf_dep:anomalies(Elf, Expected),
    ?assertEqual(1, length(Anomalies)),
    [A] = Anomalies,
    ?assertEqual(<<"encoding/json">>, maps:get(package, A)),
    ?assert(lists:member(network, maps:get(unexpected, A))),
    ?assert(lists:member(<<"socket">>, maps:get(syscalls, A))).

anomalies_no_anomalies_when_expected_test() ->
    %% "net/http" package with socket is expected
    Syscall = x86_64_syscall_seq(41),
    Pad = binary:copy(<<16#90>>, 16#20 - byte_size(Syscall)),
    TextContent = <<Syscall/binary, Pad/binary>>,
    TextSize = byte_size(TextContent),

    FuncSpecs = [{<<"net/http.Get">>, 16#0000}],
    Gopclntab = make_gopclntab(FuncSpecs, ?TEXT_VADDR),
    BuildInfo = make_buildinfo_section(<<"go1.22.1">>, <<>>),
    Bin = make_go_elf_with_syscalls(BuildInfo, Gopclntab, TextContent, TextSize),
    {ok, Elf} = elf_parse:from_binary(Bin),

    Expected = #{<<"net/http">> => [network, filesystem, memory]},
    Anomalies = elf_dep:anomalies(Elf, Expected),
    ?assertEqual([], Anomalies).

anomalies_empty_expected_flags_everything_test() ->
    %% Unknown package with any syscall is anomalous

    %% mmap = memory
    Syscall = x86_64_syscall_seq(9),
    Pad = binary:copy(<<16#90>>, 16#20 - byte_size(Syscall)),
    TextContent = <<Syscall/binary, Pad/binary>>,
    TextSize = byte_size(TextContent),

    FuncSpecs = [{<<"evil/backdoor.Init">>, 16#0000}],
    Gopclntab = make_gopclntab(FuncSpecs, ?TEXT_VADDR),
    BuildInfo = make_buildinfo_section(<<"go1.22.1">>, <<>>),
    Bin = make_go_elf_with_syscalls(BuildInfo, Gopclntab, TextContent, TextSize),
    {ok, Elf} = elf_parse:from_binary(Bin),

    %% Empty expectations: everything is unexpected
    Anomalies = elf_dep:anomalies(Elf, #{}),
    ?assertEqual(1, length(Anomalies)),
    [A] = Anomalies,
    ?assertEqual(<<"evil/backdoor">>, maps:get(package, A)),
    ?assert(lists:member(memory, maps:get(unexpected, A))).

%% ===========================================================================
%% Tests — anomalies/1 (default expectations)
%% ===========================================================================

anomalies_default_expectations_test() ->
    %% "encoding/json" package with socket syscall: flagged by defaults
    %% (encoding/ prefix maps to [memory], network is unexpected)

    %% socket = network
    Syscall = x86_64_syscall_seq(41),
    Pad = binary:copy(<<16#90>>, 16#20 - byte_size(Syscall)),
    TextContent = <<Syscall/binary, Pad/binary>>,
    TextSize = byte_size(TextContent),

    FuncSpecs = [{<<"encoding/json.Marshal">>, 16#0000}],
    Gopclntab = make_gopclntab(FuncSpecs, ?TEXT_VADDR),
    BuildInfo = make_buildinfo_section(<<"go1.22.1">>, <<>>),
    Bin = make_go_elf_with_syscalls(BuildInfo, Gopclntab, TextContent, TextSize),
    {ok, Elf} = elf_parse:from_binary(Bin),

    Anomalies = elf_dep:anomalies(Elf),
    ?assertEqual(1, length(Anomalies)),
    [A] = Anomalies,
    ?assertEqual(<<"encoding/json">>, maps:get(package, A)),
    ?assert(lists:member(network, maps:get(unexpected, A))).

anomalies_default_runtime_not_flagged_test() ->
    %% "runtime" package with memory syscall: not flagged

    %% mmap = memory
    Syscall = x86_64_syscall_seq(9),
    Pad = binary:copy(<<16#90>>, 16#20 - byte_size(Syscall)),
    TextContent = <<Syscall/binary, Pad/binary>>,
    TextSize = byte_size(TextContent),

    FuncSpecs = [{<<"runtime.mallocgc">>, 16#0000}],
    Gopclntab = make_gopclntab(FuncSpecs, ?TEXT_VADDR),
    BuildInfo = make_buildinfo_section(<<"go1.22.1">>, <<>>),
    Bin = make_go_elf_with_syscalls(BuildInfo, Gopclntab, TextContent, TextSize),
    {ok, Elf} = elf_parse:from_binary(Bin),

    Anomalies = elf_dep:anomalies(Elf),
    ?assertEqual([], Anomalies).

anomalies_plain_binary_returns_empty_test() ->
    Bin = make_plain_elf(),
    {ok, Elf} = elf_parse:from_binary(Bin),
    ?assertEqual([], elf_dep:anomalies(Elf)).

%% ===========================================================================
%% Tests — prefix matching in default expectations
%% ===========================================================================

anomalies_prefix_matching_test() ->
    %% "net/http" matches "net" prefix => network is expected

    %% socket = network
    Syscall = x86_64_syscall_seq(41),
    Pad = binary:copy(<<16#90>>, 16#20 - byte_size(Syscall)),
    TextContent = <<Syscall/binary, Pad/binary>>,
    TextSize = byte_size(TextContent),

    FuncSpecs = [{<<"net/http.Get">>, 16#0000}],
    Gopclntab = make_gopclntab(FuncSpecs, ?TEXT_VADDR),
    BuildInfo = make_buildinfo_section(<<"go1.22.1">>, <<>>),
    Bin = make_go_elf_with_syscalls(BuildInfo, Gopclntab, TextContent, TextSize),
    {ok, Elf} = elf_parse:from_binary(Bin),

    Anomalies = elf_dep:anomalies(Elf),
    ?assertEqual([], Anomalies).
