-module(elf_lang_rust_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("elf_parse.hrl").
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

%% Build a symtab entry (Elf64_Sym = 24 bytes)
sym_le(StName, StInfo, StShndx, StValue, StSize) ->
    <<StName:32/little, StInfo:8, 0:8, StShndx:16/little, StValue:64/little, StSize:64/little>>.

%% ---------------------------------------------------------------------------
%% ELF construction with Rust artifacts
%% ---------------------------------------------------------------------------

%% Build a complete ELF with .symtab, .strtab, .rodata, .comment sections.
%% SymNames: [binary()] — symbol name strings
%% RodataContent: binary() — raw .rodata bytes
%% CommentContent: binary() — raw .comment bytes
make_rust_elf(SymNames, RodataContent, CommentContent) ->
    %% String tables: .shstrtab for section names, .strtab for symbol names

    %% .shstrtab: section names
    ShStrTab =
        <<0, ".text", 0, ".symtab", 0, ".strtab", 0, ".rodata", 0, ".comment", 0, ".shstrtab", 0>>,
    %% Name indices in ShStrTab:
    %%  0: ""
    %%  1: ".text"
    %%  7: ".symtab"
    %% 15: ".strtab"
    %% 23: ".rodata"
    %% 31: ".comment"
    %% 40: ".shstrtab"

    %% .strtab: symbol names (NUL-separated)
    StrTab = build_strtab(SymNames),
    NameOffsets = strtab_offsets(SymNames),

    %% Build symtab entries: first entry is always null
    NullSym = sym_le(0, 0, 0, 0, 0),
    SymEntries = lists:zipwith(
        fun(NameOff, Idx) ->
            %% STT_FUNC=2, STB_GLOBAL=1 => st_info = (1 bsl 4) bor 2 = 18
            sym_le(NameOff, 18, 1, 16#1000 * (Idx + 1), 64)
        end,
        NameOffsets,
        lists:seq(0, length(NameOffsets) - 1)
    ),
    SymtabData = iolist_to_binary([NullSym | SymEntries]),

    TextContent = <<16#90, 16#90, 16#90, 16#C3>>,
    TextSize = byte_size(TextContent),
    SymtabSize = byte_size(SymtabData),
    StrTabSize = byte_size(StrTab),
    RodataSize = byte_size(RodataContent),
    CommentSize = byte_size(CommentContent),
    ShStrTabSize = byte_size(ShStrTab),

    %% Layout:
    %%   0x000 ELF header (64)
    %%   0x040 Phdr (56)
    %%   0x078 .text
    %%   ...   .symtab
    %%   ...   .strtab
    %%   ...   .rodata
    %%   ...   .comment
    %%   ...   .shstrtab
    %%   ...   pad to 8-byte align
    %%   ...   Section headers (8 sections * 64 = 512)
    TextOff = 16#078,
    SymtabOff = TextOff + TextSize,
    StrTabOff = SymtabOff + SymtabSize,
    RodataOff = StrTabOff + StrTabSize,
    CommentOff = RodataOff + RodataSize,
    ShStrTabOff = CommentOff + CommentSize,
    ShdrOffUnaligned = ShStrTabOff + ShStrTabSize,
    ShdrOff = (ShdrOffUnaligned + 7) band (bnot 7),
    PadSize = ShdrOff - ShdrOffUnaligned,

    %% 8 sections: null, .text, .symtab, .strtab, .rodata, .comment, .shstrtab
    NumSections = 7,
    ShStrNdx = 6,

    Header = elf_header_le(
        ?ET_EXEC,
        ?EM_X86_64,
        ?TEXT_VADDR,
        64,
        ShdrOff,
        1,
        NumSections,
        ShStrNdx
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
    S0 = shdr_le(0, ?SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0),
    %% Section 1: .text (name_idx=1)
    S1 = shdr_le(
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
    %% Section 2: .symtab (name_idx=7, link=3 → .strtab, entsize=24)
    S2 = shdr_le(7, ?SHT_SYMTAB, 0, 0, SymtabOff, SymtabSize, 3, 1, 8, 24),
    %% Section 3: .strtab (name_idx=15)
    S3 = shdr_le(15, ?SHT_STRTAB, 0, 0, StrTabOff, StrTabSize, 0, 0, 1, 0),
    %% Section 4: .rodata (name_idx=23)
    S4 = shdr_le(23, ?SHT_PROGBITS, ?SHF_ALLOC, 0, RodataOff, RodataSize, 0, 0, 1, 0),
    %% Section 5: .comment (name_idx=31)
    S5 = shdr_le(31, ?SHT_PROGBITS, 0, 0, CommentOff, CommentSize, 0, 0, 1, 0),
    %% Section 6: .shstrtab (name_idx=40)
    S6 = shdr_le(40, ?SHT_STRTAB, 0, 0, ShStrTabOff, ShStrTabSize, 0, 0, 1, 0),

    Pad = <<0:(PadSize * 8)>>,
    <<Header/binary, Phdr/binary, TextContent/binary, SymtabData/binary, StrTab/binary,
        RodataContent/binary, CommentContent/binary, ShStrTab/binary, Pad/binary, S0/binary,
        S1/binary, S2/binary, S3/binary, S4/binary, S5/binary, S6/binary>>.

%% Build a plain ELF with no Rust artifacts
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
%% String table helpers
%% ---------------------------------------------------------------------------

%% Build a NUL-terminated string table from a list of names.
%% First byte is always NUL (empty string at offset 0).
build_strtab(Names) ->
    build_strtab(Names, <<0>>).

build_strtab([], Acc) -> Acc;
build_strtab([Name | Rest], Acc) -> build_strtab(Rest, <<Acc/binary, Name/binary, 0>>).

%% Return the offset of each name in the strtab built by build_strtab/1.
strtab_offsets(Names) ->
    strtab_offsets(Names, 1, []).

strtab_offsets([], _Off, Acc) ->
    lists:reverse(Acc);
strtab_offsets([Name | Rest], Off, Acc) ->
    strtab_offsets(Rest, Off + byte_size(Name) + 1, [Off | Acc]).

%% ---------------------------------------------------------------------------
%% Test data
%% ---------------------------------------------------------------------------

legacy_symbols() ->
    [
        <<"_ZN4core3fmt5write17h0123456789abcdefE">>,
        <<"_ZN3std2io5stdio6_print17hfedcba9876543210E">>,
        <<"_ZN5alloc3vec8Vec$LT$T$GT$3new17h1111111111111111E">>,
        <<"_ZN5tokio7runtime6Runtime3new17h2222222222222222E">>
    ].

v0_symbols() ->
    [
        <<"_RNvCs1234abcd_4core3foo">>,
        <<"_RNvNtCs5678efgh_5serde2de11deserialize">>,
        <<"_RNvCsAAAABBBB_5hyper4main">>
    ].

cargo_rodata() ->
    <<"some prefix data",
        "/home/user/.cargo/registry/src/index.crates.io-6f17d22bba15001f/serde-1.0.197/src/de/mod.rs",
        0, "more data here",
        "/home/user/.cargo/registry/src/index.crates.io-6f17d22bba15001f/tokio-1.37.0/src/runtime/mod.rs",
        0,
        "/home/user/.cargo/registry/src/index.crates.io-6f17d22bba15001f/hyper-0.14.28/src/client/mod.rs",
        0, "trailing data">>.

rustc_comment() ->
    <<0, "GCC: (Debian 13.2.0-25) 13.2.0", 0, "rustc version 1.77.0 (aedd173a2 2024-03-17)", 0>>.

%% ===========================================================================
%% Tests
%% ===========================================================================

%% --- is_rust/1 ---

is_rust_detects_legacy_symbols_test() ->
    Bin = make_rust_elf(legacy_symbols(), <<>>, <<>>),
    {ok, Elf} = elf_parse:from_binary(Bin),
    ?assert(elf_lang_rust:is_rust(Elf)).

is_rust_detects_v0_symbols_test() ->
    Bin = make_rust_elf(v0_symbols(), <<>>, <<>>),
    {ok, Elf} = elf_parse:from_binary(Bin),
    ?assert(elf_lang_rust:is_rust(Elf)).

is_rust_detects_comment_only_test() ->
    %% ELF with no Rust symbols but a rustc .comment section
    %% We need a .symtab with non-Rust symbols to have a valid symtab
    Bin = make_rust_elf([<<"main">>], <<>>, rustc_comment()),
    {ok, Elf} = elf_parse:from_binary(Bin),
    ?assert(elf_lang_rust:is_rust(Elf)).

is_rust_false_for_plain_binary_test() ->
    Bin = make_plain_elf(),
    {ok, Elf} = elf_parse:from_binary(Bin),
    ?assertNot(elf_lang_rust:is_rust(Elf)).

%% --- not_rust error ---

not_rust_parse_error_test() ->
    Bin = make_plain_elf(),
    {ok, Elf} = elf_parse:from_binary(Bin),
    ?assertEqual({error, not_rust}, elf_lang_rust:parse(Elf)).

not_rust_crates_error_test() ->
    Bin = make_plain_elf(),
    {ok, Elf} = elf_parse:from_binary(Bin),
    ?assertEqual({error, not_rust}, elf_lang_rust:crates(Elf)).

%% --- Legacy demangling ---

legacy_demangle_extracts_crates_test() ->
    Bin = make_rust_elf(legacy_symbols(), <<>>, <<>>),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Info} = elf_lang_rust:parse(Elf),
    CrateNames = [C#rust_crate.name || C <- Info#rust_info.crates],
    ?assert(lists:member(<<"core">>, CrateNames)),
    ?assert(lists:member(<<"std">>, CrateNames)),
    ?assert(lists:member(<<"alloc">>, CrateNames)),
    ?assert(lists:member(<<"tokio">>, CrateNames)),
    %% All from symtab
    lists:foreach(
        fun(C) ->
            ?assertEqual(symtab, C#rust_crate.source),
            ?assertEqual(unknown, C#rust_crate.version)
        end,
        Info#rust_info.crates
    ).

%% --- V0 demangling ---

v0_demangle_extracts_crates_test() ->
    Bin = make_rust_elf(v0_symbols(), <<>>, <<>>),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Info} = elf_lang_rust:parse(Elf),
    CrateNames = [C#rust_crate.name || C <- Info#rust_info.crates],
    ?assert(lists:member(<<"core">>, CrateNames)),
    ?assert(lists:member(<<"serde">>, CrateNames)),
    ?assert(lists:member(<<"hyper">>, CrateNames)).

%% --- Panic string scanning ---

panic_strings_extract_crates_test() ->
    %% Use a non-Rust symbol + rustc comment to make is_rust true,
    %% plus cargo paths in .rodata
    Bin = make_rust_elf([<<"main">>], cargo_rodata(), rustc_comment()),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Info} = elf_lang_rust:parse(Elf),
    PanicCrates = [
        C
     || C <- Info#rust_info.crates,
        C#rust_crate.source =:= panic_strings
    ],
    PanicNames = [C#rust_crate.name || C <- PanicCrates],
    ?assert(lists:member(<<"serde">>, PanicNames)),
    ?assert(lists:member(<<"tokio">>, PanicNames)),
    ?assert(lists:member(<<"hyper">>, PanicNames)),
    %% Check versions
    Serde = hd([C || C <- PanicCrates, C#rust_crate.name =:= <<"serde">>]),
    ?assertEqual(<<"1.0.197">>, Serde#rust_crate.version),
    Tokio = hd([C || C <- PanicCrates, C#rust_crate.name =:= <<"tokio">>]),
    ?assertEqual(<<"1.37.0">>, Tokio#rust_crate.version),
    Hyper = hd([C || C <- PanicCrates, C#rust_crate.name =:= <<"hyper">>]),
    ?assertEqual(<<"0.14.28">>, Hyper#rust_crate.version).

%% --- .comment extraction ---

comment_extracts_compiler_version_test() ->
    Bin = make_rust_elf(legacy_symbols(), <<>>, rustc_comment()),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Info} = elf_lang_rust:parse(Elf),
    ?assertEqual(<<"1.77.0 (aedd173a2 2024-03-17)">>, Info#rust_info.compiler).

comment_unknown_without_rustc_test() ->
    GccComment = <<0, "GCC: (Debian 13.2.0-25) 13.2.0", 0>>,
    Bin = make_rust_elf(legacy_symbols(), <<>>, GccComment),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Info} = elf_lang_rust:parse(Elf),
    ?assertEqual(unknown, Info#rust_info.compiler).

%% --- Deduplication ---

dedup_prefers_versioned_crate_test() ->
    %% Both symtab and panic strings have "tokio" — panic_strings has version
    Syms = [<<"_ZN5tokio7runtime6Runtime3new17h2222222222222222E">>],
    Rodata = <<"/home/u/.cargo/registry/src/index.crates.io-abc/tokio-1.37.0/src/lib.rs", 0>>,
    Bin = make_rust_elf(Syms, Rodata, <<>>),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Crates} = elf_lang_rust:crates(Elf),
    TokioCrates = [C || C <- Crates, C#rust_crate.name =:= <<"tokio">>],
    ?assertEqual(1, length(TokioCrates)),
    [Tokio] = TokioCrates,
    ?assertEqual(<<"1.37.0">>, Tokio#rust_crate.version),
    ?assertEqual(panic_strings, Tokio#rust_crate.source).

%% --- Combined parse ---

parse_full_test() ->
    Bin = make_rust_elf(legacy_symbols(), cargo_rodata(), rustc_comment()),
    {ok, Elf} = elf_parse:from_binary(Bin),
    {ok, Info} = elf_lang_rust:parse(Elf),
    %% Compiler detected
    ?assertMatch(<<_/binary>>, Info#rust_info.compiler),
    %% Multiple crates found
    ?assert(length(Info#rust_info.crates) >= 4),
    %% tokio should be deduplicated: panic_strings version preferred
    TokioCrates = [
        C
     || C <- Info#rust_info.crates,
        C#rust_crate.name =:= <<"tokio">>
    ],
    ?assertEqual(1, length(TokioCrates)),
    [Tokio] = TokioCrates,
    ?assertEqual(<<"1.37.0">>, Tokio#rust_crate.version).
