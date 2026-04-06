-module(elf_syscall_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("elf_parse.hrl").

%% ---------------------------------------------------------------------------
%% Test ELF binary construction helpers
%% ---------------------------------------------------------------------------

%% Build a minimal valid ELF64 LE binary with custom .text content.
%%
%% Layout:
%%   0x000 - 0x03F  ELF header       (64 bytes)
%%   0x040 - 0x077  Program header    (56 bytes)
%%   0x078 - ...    .text content     (variable)
%%   ...            .shstrtab         (17 bytes)
%%   ...            Section headers   (3 * 64 = 192 bytes)

-define(TEXT_VADDR, 16#400000).

make_elf(Machine, TextContent) ->
    TextOff = 16#078,
    TextSize = byte_size(TextContent),
    StrTab = <<0, ".text", 0, ".shstrtab", 0>>,
    StrTabSize = byte_size(StrTab),

    %% Align strtab offset to after text
    StrtabOff = TextOff + TextSize,
    %% Align section headers to 8-byte boundary
    ShdrOff0 = StrtabOff + StrTabSize,
    ShdrOff = (ShdrOff0 + 7) band (bnot 7),
    PadSize = ShdrOff - ShdrOff0,

    Header = elf_header_le(
        ?ET_EXEC,
        Machine,
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

%% x86-64: MOV EAX, <imm32> ; SYSCALL
%% Encodes as: B8 <imm32 LE> 0F 05
x86_64_syscall_seq(Nr) ->
    <<16#B8, Nr:32/little, 16#0F, 16#05>>.

%% ---------------------------------------------------------------------------
%% Binary construction helpers (LE)
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

%% ===========================================================================
%% Tests
%% ===========================================================================

%% --- extract/1 finds syscalls ---

extract_x86_64_test() ->
    %% Two syscall sequences: write (1) and exit_group (231)
    Text = <<(x86_64_syscall_seq(1))/binary, (x86_64_syscall_seq(231))/binary>>,
    Bin = make_elf(?EM_X86_64, Text),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Result} = elf_syscall:extract(Elf),
    ?assertEqual(x86_64, maps:get(arch, Result)),
    Resolved = maps:get(resolved, Result),
    ?assertEqual(<<"write">>, maps:get(1, Resolved)),
    ?assertEqual(<<"exit_group">>, maps:get(231, Resolved)),
    ?assertEqual(0, maps:get(unresolved_count, Result)),
    %% Sites should have 2 entries
    Sites = maps:get(sites, Result),
    ?assertEqual(2, length(Sites)),
    %% Check site addresses
    [Site1, Site2] = Sites,
    ?assertEqual(1, maps:get(syscall_nr, Site1)),
    ?assertEqual(231, maps:get(syscall_nr, Site2)).

extract_multiple_syscalls_test() ->
    %% read(0), write(1), openat(257), exit_group(231)
    Text = <<
        (x86_64_syscall_seq(0))/binary,
        (x86_64_syscall_seq(1))/binary,
        (x86_64_syscall_seq(257))/binary,
        (x86_64_syscall_seq(231))/binary
    >>,
    Bin = make_elf(?EM_X86_64, Text),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Result} = elf_syscall:extract(Elf),
    Resolved = maps:get(resolved, Result),
    ?assertEqual(4, maps:size(Resolved)),
    ?assertEqual(<<"read">>, maps:get(0, Resolved)),
    ?assertEqual(<<"openat">>, maps:get(257, Resolved)).

%% --- numbers/1 ---

numbers_test() ->
    Text = <<
        (x86_64_syscall_seq(1))/binary,
        (x86_64_syscall_seq(60))/binary,
        (x86_64_syscall_seq(231))/binary
    >>,
    Bin = make_elf(?EM_X86_64, Text),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Nrs} = elf_syscall:numbers(Elf),
    ?assertEqual([1, 60, 231], Nrs).

%% --- names/1 ---

names_test() ->
    Text = <<(x86_64_syscall_seq(1))/binary, (x86_64_syscall_seq(60))/binary>>,
    Bin = make_elf(?EM_X86_64, Text),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Names} = elf_syscall:names(Elf),
    ?assertEqual([<<"exit">>, <<"write">>], Names).

%% --- categories/1 ---

categories_test() ->
    %% write=filesystem, socket=network, mmap=memory, exit=process

    % write
    Text = <<
        (x86_64_syscall_seq(1))/binary,
        % socket
        (x86_64_syscall_seq(41))/binary,
        % mmap
        (x86_64_syscall_seq(9))/binary,
        % exit
        (x86_64_syscall_seq(60))/binary
    >>,
    Bin = make_elf(?EM_X86_64, Text),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Cats} = elf_syscall:categories(Elf),
    ?assert(lists:member(<<"write">>, maps:get(filesystem, Cats))),
    ?assert(lists:member(<<"socket">>, maps:get(network, Cats))),
    ?assert(lists:member(<<"mmap">>, maps:get(memory, Cats))),
    ?assert(lists:member(<<"exit">>, maps:get(process, Cats))).

%% --- Unsupported architecture ---

unsupported_arch_test() ->
    %% Build an ELF with ARM (not aarch64) machine type
    Text = <<16#90, 16#90, 16#90, 16#C3>>,
    Bin = make_elf(?EM_ARM, Text),
    {ok, Elf} = elf_parse:from_binary(Bin),
    ?assertEqual({error, unsupported_arch}, elf_syscall:extract(Elf)),
    ?assertEqual({error, unsupported_arch}, elf_syscall:numbers(Elf)),
    ?assertEqual({error, unsupported_arch}, elf_syscall:names(Elf)),
    ?assertEqual({error, unsupported_arch}, elf_syscall:categories(Elf)).

%% --- Empty text section ---

empty_text_test() ->
    % just RET, no syscalls
    Text = <<16#C3>>,
    Bin = make_elf(?EM_X86_64, Text),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Result} = elf_syscall:extract(Elf),
    ?assertEqual(#{}, maps:get(resolved, Result)),
    ?assertEqual(0, maps:get(unresolved_count, Result)),
    ?assertEqual([], maps:get(sites, Result)),
    ?assertEqual(#{}, maps:get(categories, Result)).

%% --- Duplicate syscall numbers deduplicated ---

dedup_test() ->
    %% Two write(1) calls should result in one resolved entry
    Text = <<(x86_64_syscall_seq(1))/binary, (x86_64_syscall_seq(1))/binary>>,
    Bin = make_elf(?EM_X86_64, Text),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Result} = elf_syscall:extract(Elf),
    ?assertEqual(1, maps:size(maps:get(resolved, Result))),
    %% But sites should have 2 entries
    ?assertEqual(2, length(maps:get(sites, Result))).
