-module(elf_parse_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("elf_parse.hrl").

%% ---------------------------------------------------------------------------
%% Test ELF binary construction helpers
%% ---------------------------------------------------------------------------

%% Build a minimal valid ELF64 LE binary with:
%%   - 1 PT_LOAD program header
%%   - 3 section headers: SHN_UNDEF (null), .text (progbits), .shstrtab (strtab)
%%
%% Layout (byte offsets):
%%   0x000 - 0x03F  ELF header       (64 bytes)
%%   0x040 - 0x077  Program header    (56 bytes)
%%   0x078 - 0x07B  .text content     (4 bytes: NOP sled)
%%   0x07C - 0x08F  .shstrtab content (20 bytes)
%%   0x090 - 0x14F  Section headers   (3 * 64 = 192 bytes)
%%
%% Total: 0x150 = 336 bytes

-define(TEXT_OFF, 16#078).
-define(TEXT_SIZE, 4).
-define(TEXT_VADDR, 16#400000).
-define(STRTAB_OFF, 16#07C).
-define(STRTAB_SIZE, 17).
-define(SHDR_OFF, 16#090).

minimal_elf64_le() ->
    %% .shstrtab content: "\0.text\0.shstrtab\0"
    StrTab = <<0, ".text", 0, ".shstrtab", 0>>,
    ?STRTAB_SIZE = byte_size(StrTab),

    % 3x NOP + RET
    TextContent = <<16#90, 16#90, 16#90, 16#C3>>,
    ?TEXT_SIZE = byte_size(TextContent),

    Header = elf_header_le(
        _Type = ?ET_EXEC,
        _Machine = ?EM_X86_64,
        _Entry = ?TEXT_VADDR,
        _PhOff = 64,
        _ShOff = ?SHDR_OFF,
        _PhNum = 1,
        _ShNum = 3,
        _ShStrNdx = 2
    ),
    64 = byte_size(Header),

    %% PT_LOAD covering .text: vaddr 0x400000, offset 0x78, size 4
    Phdr = phdr_le(
        _PType = ?PT_LOAD,
        _PFlags = ?PF_R bor ?PF_X,
        _POffset = ?TEXT_OFF,
        _PVaddr = ?TEXT_VADDR,
        _PPaddr = ?TEXT_VADDR,
        _PFilesz = ?TEXT_SIZE,
        _PMemsz = ?TEXT_SIZE,
        _PAlign = 16#1000
    ),
    56 = byte_size(Phdr),

    %% Section 0: SHN_UNDEF (null, all zeros)
    Shdr0 = shdr_le(0, ?SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0),
    %% Section 1: .text (name_idx=1 in strtab)
    Shdr1 = shdr_le(
        1,
        ?SHT_PROGBITS,
        ?SHF_ALLOC bor ?SHF_EXECINSTR,
        ?TEXT_VADDR,
        ?TEXT_OFF,
        ?TEXT_SIZE,
        0,
        0,
        16,
        0
    ),
    %% Section 2: .shstrtab (name_idx=7 in strtab)
    Shdr2 = shdr_le(7, ?SHT_STRTAB, 0, 0, ?STRTAB_OFF, ?STRTAB_SIZE, 0, 0, 1, 0),

    %% Pad from end of strtab (0x07C + 17 = 0x08D) to SHDR_OFF (0x090)
    PadSize = ?SHDR_OFF - (?STRTAB_OFF + ?STRTAB_SIZE),
    Pad = <<0:(PadSize * 8)>>,
    <<Header/binary, Phdr/binary, TextContent/binary, StrTab/binary, Pad/binary, Shdr0/binary,
        Shdr1/binary, Shdr2/binary>>.

%% Same binary but as ET_DYN (PIE) without PT_INTERP → static PIE
minimal_elf64_le_dyn() ->
    Bin = minimal_elf64_le(),
    %% Patch e_type at offset 16 from ET_EXEC (2) to ET_DYN (3)
    <<Pre:16/binary, _:16, Post/binary>> = Bin,
    <<Pre/binary, ?ET_DYN:16/little, Post/binary>>.

%% Same binary but with PT_INTERP added → dynamically linked
minimal_elf64_le_dynamic() ->
    StrTab = <<0, ".text", 0, ".shstrtab", 0>>,
    % 17
    StrTabSize = byte_size(StrTab),
    TextContent = <<16#90, 16#90, 16#90, 16#C3>>,
    InterpPath = <<"/lib64/ld-linux-x86-64.so.2", 0>>,
    % 28
    InterpSize = byte_size(InterpPath),

    %% Layout:
    %%   0x000  ELF header (64)
    %%   0x040  Phdr 0: PT_LOAD (56)
    %%   0x078  Phdr 1: PT_INTERP (56)
    %%   0x0B0  .text (4)
    %%   0x0B4  interp string (28)
    %%   0x0D0  .shstrtab (17)
    %%   0x0E1  pad to 0x0E8 (7 bytes)
    %%   0x0E8  Section headers (3 * 64 = 192)
    TextOff = 16#0B0,
    InterpOff = 16#0B4,
    StrtabOff = 16#0D0,
    ShdrOff = 16#0E8,

    Header = elf_header_le(
        ?ET_EXEC,
        ?EM_X86_64,
        ?TEXT_VADDR,
        64,
        ShdrOff,
        2,
        3,
        2
    ),
    Phdr0 = phdr_le(
        ?PT_LOAD,
        ?PF_R bor ?PF_X,
        TextOff,
        ?TEXT_VADDR,
        ?TEXT_VADDR,
        4,
        4,
        16#1000
    ),
    Phdr1 = phdr_le(
        ?PT_INTERP,
        ?PF_R,
        InterpOff,
        0,
        0,
        InterpSize,
        InterpSize,
        1
    ),

    Shdr0 = shdr_le(0, ?SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0),
    Shdr1 = shdr_le(
        1,
        ?SHT_PROGBITS,
        ?SHF_ALLOC bor ?SHF_EXECINSTR,
        ?TEXT_VADDR,
        TextOff,
        4,
        0,
        0,
        16,
        0
    ),
    Shdr2 = shdr_le(7, ?SHT_STRTAB, 0, 0, StrtabOff, StrTabSize, 0, 0, 1, 0),

    PadSize = ShdrOff - (StrtabOff + StrTabSize),
    Pad = <<0:(PadSize * 8)>>,
    <<Header/binary, Phdr0/binary, Phdr1/binary, TextContent/binary, InterpPath/binary,
        StrTab/binary, Pad/binary, Shdr0/binary, Shdr1/binary, Shdr2/binary>>.

%% Minimal big-endian ELF64 (SPARC-like, but we use x86_64 machine for simplicity).
minimal_elf64_be() ->
    StrTab = <<0, ".text", 0, ".shstrtab", 0>>,
    TextContent = <<16#90, 16#90, 16#90, 16#C3>>,

    Header = elf_header_be(
        ?ET_EXEC,
        ?EM_X86_64,
        ?TEXT_VADDR,
        64,
        ?SHDR_OFF,
        1,
        3,
        2
    ),
    Phdr = phdr_be(
        ?PT_LOAD,
        ?PF_R bor ?PF_X,
        ?TEXT_OFF,
        ?TEXT_VADDR,
        ?TEXT_VADDR,
        ?TEXT_SIZE,
        ?TEXT_SIZE,
        16#1000
    ),

    Shdr0 = shdr_be(0, ?SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0),
    Shdr1 = shdr_be(
        1,
        ?SHT_PROGBITS,
        ?SHF_ALLOC bor ?SHF_EXECINSTR,
        ?TEXT_VADDR,
        ?TEXT_OFF,
        ?TEXT_SIZE,
        0,
        0,
        16,
        0
    ),
    Shdr2 = shdr_be(7, ?SHT_STRTAB, 0, 0, ?STRTAB_OFF, ?STRTAB_SIZE, 0, 0, 1, 0),

    PadSize = ?SHDR_OFF - (?STRTAB_OFF + ?STRTAB_SIZE),
    Pad = <<0:(PadSize * 8)>>,
    <<Header/binary, Phdr/binary, TextContent/binary, StrTab/binary, Pad/binary, Shdr0/binary,
        Shdr1/binary, Shdr2/binary>>.

%% With .debug_info section
minimal_elf64_le_debug() ->
    %% strtab: "\0.text\0.debug_info\0.shstrtab\0"
    StrTab = <<0, ".text", 0, ".debug_info", 0, ".shstrtab", 0>>,
    % 31
    StrTabSize = byte_size(StrTab),

    TextContent = <<16#90, 16#90, 16#90, 16#C3>>,
    DebugContent = <<"DWARF">>,
    DebugSize = byte_size(DebugContent),

    %% Layout:
    %%   0x000  header (64)
    %%   0x040  phdr (56)
    %%   0x078  .text (4)
    %%   0x07C  .debug_info (5)
    %%   0x081  strtab (31)
    %%   0x0A0  section headers (4 * 64 = 256)
    TextOff = 16#078,
    DebugOff = 16#07C,
    StrtabOff = 16#081,
    %% Align section headers to 16 bytes
    ShdrOff = 16#0A0,

    Header = elf_header_le(
        ?ET_EXEC,
        ?EM_X86_64,
        ?TEXT_VADDR,
        64,
        ShdrOff,
        1,
        4,
        3
    ),
    Phdr = phdr_le(
        ?PT_LOAD,
        ?PF_R bor ?PF_X,
        TextOff,
        ?TEXT_VADDR,
        ?TEXT_VADDR,
        4,
        4,
        16#1000
    ),

    Shdr0 = shdr_le(0, ?SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0),
    Shdr1 = shdr_le(
        1,
        ?SHT_PROGBITS,
        ?SHF_ALLOC bor ?SHF_EXECINSTR,
        ?TEXT_VADDR,
        TextOff,
        4,
        0,
        0,
        16,
        0
    ),
    Shdr2 = shdr_le(7, ?SHT_PROGBITS, 0, 0, DebugOff, DebugSize, 0, 0, 1, 0),
    %% .shstrtab name_idx = 19 (after "\0.text\0.debug_info\0")
    Shdr3 = shdr_le(19, ?SHT_STRTAB, 0, 0, StrtabOff, StrTabSize, 0, 0, 1, 0),

    %% Padding between strtab end and shdr start
    PadSize = ShdrOff - (StrtabOff + StrTabSize),
    Pad = <<0:(PadSize * 8)>>,

    <<Header/binary, Phdr/binary, TextContent/binary, DebugContent/binary, StrTab/binary,
        Pad/binary, Shdr0/binary, Shdr1/binary, Shdr2/binary, Shdr3/binary>>.

%% ---------------------------------------------------------------------------
%% Binary construction helpers (LE)
%% ---------------------------------------------------------------------------

elf_header_le(Type, Machine, Entry, PhOff, ShOff, PhNum, ShNum, ShStrNdx) ->
    <<16#7F, "ELF",
        % ELFCLASS64
        2:8,
        % ELFDATA2LSB
        1:8,
        % EV_CURRENT
        1:8,
        % ELFOSABI_NONE
        0:8,
        % padding
        0:64, Type:16/little, Machine:16/little,
        % e_version
        1:32/little, Entry:64/little, PhOff:64/little, ShOff:64/little,
        % e_flags
        0:32/little,
        % e_ehsize
        64:16/little,
        % e_phentsize
        56:16/little, PhNum:16/little,
        % e_shentsize
        64:16/little, ShNum:16/little, ShStrNdx:16/little>>.

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
%% Binary construction helpers (BE)
%% ---------------------------------------------------------------------------

elf_header_be(Type, Machine, Entry, PhOff, ShOff, PhNum, ShNum, ShStrNdx) ->
    <<16#7F, "ELF", 2:8, 2:8, 1:8, 0:8, 0:64, Type:16/big, Machine:16/big, 1:32/big, Entry:64/big,
        PhOff:64/big, ShOff:64/big, 0:32/big, 64:16/big, 56:16/big, PhNum:16/big, 64:16/big,
        ShNum:16/big, ShStrNdx:16/big>>.

phdr_be(PType, PFlags, POffset, PVaddr, PPaddr, PFilesz, PMemsz, PAlign) ->
    <<PType:32/big, PFlags:32/big, POffset:64/big, PVaddr:64/big, PPaddr:64/big, PFilesz:64/big,
        PMemsz:64/big, PAlign:64/big>>.

shdr_be(
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
    <<ShName:32/big, ShType:32/big, ShFlags:64/big, ShAddr:64/big, ShOffset:64/big, ShSize:64/big,
        ShLink:32/big, ShInfo:32/big, ShAddralign:64/big, ShEntsize:64/big>>.

%% ===========================================================================
%% Tests
%% ===========================================================================

%% --- Valid header parsing ---

parse_valid_le_test() ->
    Bin = minimal_elf64_le(),
    {ok, Elf} = elf_parse:from_binary(Bin),
    Hdr = Elf#elf.header,
    ?assertEqual(64, Hdr#elf_header.class),
    ?assertEqual(little, Hdr#elf_header.endian),
    ?assertEqual(exec, Hdr#elf_header.type),
    ?assertEqual(x86_64, Hdr#elf_header.machine),
    ?assertEqual(?TEXT_VADDR, Hdr#elf_header.entry),
    ?assertEqual(1, Hdr#elf_header.ph_count),
    ?assertEqual(3, Hdr#elf_header.sh_count),
    ?assertEqual(2, Hdr#elf_header.sh_strndx).

%% --- Invalid magic ---

parse_invalid_magic_test() ->
    ?assertEqual({error, not_elf}, elf_parse:from_binary(<<0, 0, 0, 0, 0:480>>)).

parse_truncated_test() ->
    ?assertEqual({error, truncated}, elf_parse:from_binary(<<16#7F, "ELF">>)).

parse_not_elf64_test() ->
    %% ELF32 class = 1
    Bin = <<16#7F, "ELF", 1:8, 1:8, 1:8, 0:8, 0:64, 0:(48 * 8)>>,
    ?assertEqual({error, not_elf64}, elf_parse:from_binary(Bin)).

%% --- Section name resolution ---

section_name_resolution_test() ->
    {ok, Elf} = elf_parse:from_binary(minimal_elf64_le()),
    Shdrs = Elf#elf.shdrs,
    ?assertEqual(3, length(Shdrs)),
    [Null, Text, Shstrtab] = Shdrs,
    ?assertEqual(<<>>, Null#elf_shdr.name),
    ?assertEqual(<<".text">>, Text#elf_shdr.name),
    ?assertEqual(<<".shstrtab">>, Shstrtab#elf_shdr.name).

%% --- section/2 lookup ---

section_lookup_test() ->
    {ok, Elf} = elf_parse:from_binary(minimal_elf64_le()),
    {ok, Text} = elf_parse:section(<<".text">>, Elf),
    ?assertEqual(progbits, Text#elf_shdr.type),
    ?assertEqual({error, not_found}, elf_parse:section(<<".bss">>, Elf)).

%% --- section_data/2 ---

section_data_test() ->
    {ok, Elf} = elf_parse:from_binary(minimal_elf64_le()),
    {ok, Text} = elf_parse:section(<<".text">>, Elf),
    {ok, Data} = elf_parse:section_data(Text, Elf),
    ?assertEqual(<<16#90, 16#90, 16#90, 16#C3>>, Data).

%% --- Program header parsing ---

phdr_parsing_test() ->
    {ok, Elf} = elf_parse:from_binary(minimal_elf64_le()),
    [Phdr] = Elf#elf.phdrs,
    ?assertEqual(load, Phdr#elf_phdr.type),
    ?assert(lists:member(r, Phdr#elf_phdr.flags)),
    ?assert(lists:member(x, Phdr#elf_phdr.flags)),
    ?assertNot(lists:member(w, Phdr#elf_phdr.flags)),
    ?assertEqual(?TEXT_VADDR, Phdr#elf_phdr.vaddr),
    ?assertEqual(?TEXT_OFF, Phdr#elf_phdr.offset),
    ?assertEqual(?TEXT_SIZE, Phdr#elf_phdr.filesz).

%% --- vaddr_to_offset ---

vaddr_to_offset_test() ->
    {ok, Elf} = elf_parse:from_binary(minimal_elf64_le()),
    %% Start of .text segment
    ?assertEqual({ok, ?TEXT_OFF}, elf_parse:vaddr_to_offset(?TEXT_VADDR, Elf)),
    %% Offset within segment
    ?assertEqual({ok, ?TEXT_OFF + 2}, elf_parse:vaddr_to_offset(?TEXT_VADDR + 2, Elf)),
    %% Unmapped address
    ?assertEqual({error, not_mapped}, elf_parse:vaddr_to_offset(16#DEAD, Elf)).

%% --- is_static ---

is_static_test() ->
    {ok, Static} = elf_parse:from_binary(minimal_elf64_le()),
    ?assert(elf_parse:is_static(Static)),
    {ok, Dynamic} = elf_parse:from_binary(minimal_elf64_le_dynamic()),
    ?assertNot(elf_parse:is_static(Dynamic)).

%% --- is_pie ---

is_pie_test() ->
    %% ET_EXEC without PT_INTERP → not PIE
    {ok, Exec} = elf_parse:from_binary(minimal_elf64_le()),
    ?assertNot(elf_parse:is_pie(Exec)),
    %% ET_DYN without PT_INTERP → PIE
    {ok, Pie} = elf_parse:from_binary(minimal_elf64_le_dyn()),
    ?assert(elf_parse:is_pie(Pie)),
    %% ET_DYN with PT_INTERP → shared object, not static PIE
    DynBin = minimal_elf64_le_dynamic(),
    %% Patch to ET_DYN
    <<Pre:16/binary, _:16, Post/binary>> = DynBin,
    DynWithInterp = <<Pre/binary, ?ET_DYN:16/little, Post/binary>>,
    {ok, SharedObj} = elf_parse:from_binary(DynWithInterp),
    ?assertNot(elf_parse:is_pie(SharedObj)).

%% --- has_debug_info ---

has_debug_info_test() ->
    {ok, NoDebug} = elf_parse:from_binary(minimal_elf64_le()),
    ?assertNot(elf_parse:has_debug_info(NoDebug)),
    {ok, WithDebug} = elf_parse:from_binary(minimal_elf64_le_debug()),
    ?assert(elf_parse:has_debug_info(WithDebug)).

%% --- executable_sections ---

executable_sections_test() ->
    {ok, Elf} = elf_parse:from_binary(minimal_elf64_le()),
    ExecSections = elf_parse:executable_sections(Elf),
    ?assertEqual(1, length(ExecSections)),
    [Text] = ExecSections,
    ?assertEqual(<<".text">>, Text#elf_shdr.name).

%% --- Big-endian ---

parse_big_endian_test() ->
    Bin = minimal_elf64_be(),
    {ok, Elf} = elf_parse:from_binary(Bin),
    Hdr = Elf#elf.header,
    ?assertEqual(big, Hdr#elf_header.endian),
    ?assertEqual(exec, Hdr#elf_header.type),
    ?assertEqual(x86_64, Hdr#elf_header.machine),
    ?assertEqual(?TEXT_VADDR, Hdr#elf_header.entry),
    %% Section names should resolve correctly
    {ok, Text} = elf_parse:section(<<".text">>, Elf),
    ?assertEqual(progbits, Text#elf_shdr.type),
    %% vaddr should work
    ?assertEqual({ok, ?TEXT_OFF}, elf_parse:vaddr_to_offset(?TEXT_VADDR, Elf)).

%% --- from_file error ---

from_file_nonexistent_test() ->
    ?assertMatch(
        {error, {file, enoent}},
        elf_parse:from_file("/nonexistent/file")
    ).

%% --- Section type and flag decoding ---

shdr_types_test() ->
    {ok, Elf} = elf_parse:from_binary(minimal_elf64_le()),
    [Null, Text, Strtab] = Elf#elf.shdrs,
    ?assertEqual(null, Null#elf_shdr.type),
    ?assertEqual(progbits, Text#elf_shdr.type),
    ?assertEqual(strtab, Strtab#elf_shdr.type),
    %% .text should have alloc + execinstr
    ?assert(lists:member(alloc, Text#elf_shdr.flags)),
    ?assert(lists:member(execinstr, Text#elf_shdr.flags)),
    ?assertNot(lists:member(write, Text#elf_shdr.flags)).

%% --- nobits section_data ---

section_data_nobits_test() ->
    %% Construct a section header with type=nobits
    NobitsShdr = #elf_shdr{
        index = 0,
        name_idx = 0,
        name = <<".bss">>,
        type = nobits,
        flags = [alloc, write],
        addr = 0,
        offset = 0,
        size = 4096,
        link = 0,
        info = 0,
        addralign = 16,
        entsize = 0
    },
    {ok, Elf} = elf_parse:from_binary(minimal_elf64_le()),
    ?assertEqual({error, nobits}, elf_parse:section_data(NobitsShdr, Elf)).

%% --- Raw binary retained ---

raw_binary_retained_test() ->
    Bin = minimal_elf64_le(),
    {ok, Elf} = elf_parse:from_binary(Bin),
    ?assertEqual(Bin, Elf#elf.bin).
