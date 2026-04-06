-module(elf_parse_symtab_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("elf_parse.hrl").

%% ---------------------------------------------------------------------------
%% Test helpers — build a minimal ELF64 binary with .symtab + .strtab
%% ---------------------------------------------------------------------------

%% Section header entry size
-define(SHDR_SIZE, 64).
%% Symbol entry size
-define(SYM_SIZE, 24).

%% Build a minimal valid ELF64 LE binary containing:
%%   Section 0: SHT_NULL
%%   Section 1: .strtab   (section name string table = shstrtab)
%%   Section 2: .strtab   (symbol string table)
%%   Section 3: .symtab   (symbol table, sh_link = 2)
%%
%% We reuse the same .strtab section for shstrtab and the symbol strtab
%% to keep things simple — but we use separate sections so sh_link works.
build_test_elf() ->
    %% --- String tables ---
    %% Section name string table (shstrtab): used by section headers
    %% Index 0: \0 (null), 1: .strtab\0, 9: .symtab\0
    ShStrTab = <<0, ".strtab", 0, ".symtab", 0>>,
    %% Offsets: .strtab = 1, .symtab = 9

    %% Symbol string table: names for our test symbols
    %% Index 0: \0 (null name), 1: main\0, 6: my_global\0, 16: my_local\0, 25: my_object\0
    SymStrTab = <<0, "main", 0, "my_global", 0, "my_local", 0, "my_object", 0>>,
    %% Offsets: main=1, my_global=6, my_local=16, my_object=25

    %% --- Symbols (Elf64_Sym, 24 bytes each) ---
    %% Entry 0: STN_UNDEF (required null entry)
    Sym0 = sym_entry(0, 0, 0, 0, 0, 0),
    %% Entry 1: main — STB_GLOBAL, STT_FUNC, section 1, value=0x401000, size=0x100
    Sym1 = sym_entry(1, st_info(?STB_GLOBAL, ?STT_FUNC), 0, 1, 16#401000, 16#100),
    %% Entry 2: my_global — STB_GLOBAL, STT_FUNC, section 1, value=0x401100, size=0x80
    Sym2 = sym_entry(6, st_info(?STB_GLOBAL, ?STT_FUNC), 0, 1, 16#401100, 16#80),
    %% Entry 3: my_local — STB_LOCAL, STT_NOTYPE, section 1, value=0x402000, size=0x10
    Sym3 = sym_entry(16, st_info(?STB_LOCAL, ?STT_NOTYPE), 0, 1, 16#402000, 16#10),
    %% Entry 4: my_object — STB_GLOBAL, STT_OBJECT, SHN_ABS, value=0x42, size=8
    Sym4 = sym_entry(25, st_info(?STB_GLOBAL, ?STT_OBJECT), 0, 16#FFF1, 16#42, 8),
    SymTab = <<Sym0/binary, Sym1/binary, Sym2/binary, Sym3/binary, Sym4/binary>>,

    %% --- Layout ---
    %% ELF header: 64 bytes (offset 0)
    %% ShStrTab: starts at 64
    %% SymStrTab: starts at 64 + byte_size(ShStrTab)
    %% SymTab: starts after SymStrTab
    %% Section headers: starts after SymTab
    ElfHdrSize = 64,
    ShStrTabOff = ElfHdrSize,
    SymStrTabOff = ShStrTabOff + byte_size(ShStrTab),
    SymTabOff = SymStrTabOff + byte_size(SymStrTab),
    ShOff = SymTabOff + byte_size(SymTab),

    %% --- Section headers (4 sections) ---
    %% Section 0: SHT_NULL
    Sh0 = shdr_entry(0, ?SHT_NULL, 0, 0, 0, 0, 0, 0, 0),
    %% Section 1: .strtab (shstrtab) — name offset = 1 (".strtab")
    Sh1 = shdr_entry(1, ?SHT_STRTAB, 0, ShStrTabOff, byte_size(ShStrTab), 0, 0, 0, 0),
    %% Section 2: .strtab (symbol strtab) — name offset = 1 (".strtab")
    Sh2 = shdr_entry(1, ?SHT_STRTAB, 0, SymStrTabOff, byte_size(SymStrTab), 0, 0, 0, 0),
    %% Section 3: .symtab — name offset = 9, sh_link = 2 (symbol strtab index)
    Sh3 = shdr_entry(9, ?SHT_SYMTAB, 0, SymTabOff, byte_size(SymTab), 2, 0, 8, ?SYM_SIZE),
    Shdrs = <<Sh0/binary, Sh1/binary, Sh2/binary, Sh3/binary>>,

    ShCount = 4,
    %% Section 1 is our shstrtab
    ShStrNdx = 1,

    ElfHdr = elf_header(ShOff, ShCount, ShStrNdx),
    Bin = <<ElfHdr/binary, ShStrTab/binary, SymStrTab/binary, SymTab/binary, Shdrs/binary>>,
    {ok, Elf} = elf_parse:from_binary(Bin),
    Elf.

%% Build a minimal ELF64 with no .symtab (stripped).
build_stripped_elf() ->
    %% shstrtab with just a null byte
    ShStrTab = <<0, ".strtab", 0>>,
    ElfHdrSize = 64,
    ShStrTabOff = ElfHdrSize,
    ShOff = ShStrTabOff + byte_size(ShStrTab),

    Sh0 = shdr_entry(0, ?SHT_NULL, 0, 0, 0, 0, 0, 0, 0),
    Sh1 = shdr_entry(1, ?SHT_STRTAB, 0, ShStrTabOff, byte_size(ShStrTab), 0, 0, 0, 0),
    Shdrs = <<Sh0/binary, Sh1/binary>>,

    ShCount = 2,
    ShStrNdx = 1,
    ElfHdr = elf_header(ShOff, ShCount, ShStrNdx),
    Bin = <<ElfHdr/binary, ShStrTab/binary, Shdrs/binary>>,
    {ok, Elf} = elf_parse:from_binary(Bin),
    Elf.

%% --- Binary builders ---

elf_header(ShOff, ShCount, ShStrNdx) ->
    <<16#7F, "ELF",
        %% ELFCLASS64
        2,
        %% ELFDATA2LSB
        1,
        %% EV_CURRENT
        1,
        %% OS/ABI
        0,
        %% padding
        0:64,
        %% ET_EXEC
        2:16/little,
        %% EM_X86_64
        16#3E:16/little,
        %% EV_CURRENT
        1:32/little,
        %% e_entry
        16#401000:64/little,
        %% e_phoff (no phdrs)
        0:64/little,
        %% e_shoff
        ShOff:64/little,
        %% e_flags
        0:32/little,
        %% e_ehsize
        64:16/little,
        %% e_phentsize
        56:16/little,
        %% e_phnum
        0:16/little,
        %% e_shentsize
        64:16/little, ShCount:16/little, ShStrNdx:16/little>>.

shdr_entry(Name, Type, Flags, Offset, Size, Link, Info, Addralign, Entsize) ->
    <<Name:32/little, Type:32/little, Flags:64/little,
        %% sh_addr
        0:64/little, Offset:64/little, Size:64/little, Link:32/little, Info:32/little,
        Addralign:64/little, Entsize:64/little>>.

sym_entry(Name, Info, Other, Shndx, Value, Size) ->
    <<Name:32/little, Info:8, Other:8, Shndx:16/little, Value:64/little, Size:64/little>>.

st_info(Bind, Type) ->
    (Bind bsl 4) bor Type.

%% Constants from elf_parse.hrl (already included above).

%% ---------------------------------------------------------------------------
%% Tests
%% ---------------------------------------------------------------------------

symbols_test() ->
    Elf = build_test_elf(),
    {ok, Syms} = elf_parse_symtab:symbols(Elf),
    ?assertEqual(5, length(Syms)),
    %% First entry is the null symbol
    [Null | Named] = Syms,
    ?assertEqual(<<>>, Null#elf_sym.name),
    ?assertEqual(undefined, Null#elf_sym.shndx),
    %% Check main
    [Main | _] = Named,
    ?assertEqual(<<"main">>, Main#elf_sym.name),
    ?assertEqual(global, Main#elf_sym.bind),
    ?assertEqual(func, Main#elf_sym.type),
    ?assertEqual(16#401000, Main#elf_sym.value),
    ?assertEqual(16#100, Main#elf_sym.size).

functions_test() ->
    Elf = build_test_elf(),
    {ok, Fns} = elf_parse_symtab:functions(Elf),
    %% Should contain main and my_global (both STT_FUNC)
    ?assertEqual(2, length(Fns)),
    Names = [F#elf_sym.name || F <- Fns],
    ?assert(lists:member(<<"main">>, Names)),
    ?assert(lists:member(<<"my_global">>, Names)),
    %% Should NOT contain my_local (NOTYPE) or my_object (OBJECT)
    ?assertNot(lists:member(<<"my_local">>, Names)),
    ?assertNot(lists:member(<<"my_object">>, Names)).

lookup_test() ->
    Elf = build_test_elf(),
    {ok, Main} = elf_parse_symtab:lookup(Elf, <<"main">>),
    ?assertEqual(<<"main">>, Main#elf_sym.name),
    ?assertEqual(func, Main#elf_sym.type),
    %% Non-existent name
    ?assertEqual(error, elf_parse_symtab:lookup(Elf, <<"nonexistent">>)).

at_address_test() ->
    Elf = build_test_elf(),
    %% Exact start of main (0x401000, size 0x100)
    {ok, S1} = elf_parse_symtab:at_address(Elf, 16#401000),
    ?assertEqual(<<"main">>, S1#elf_sym.name),
    %% Inside main
    {ok, S2} = elf_parse_symtab:at_address(Elf, 16#4010FF),
    ?assertEqual(<<"main">>, S2#elf_sym.name),
    %% Just past main — should match my_global (0x401100, size 0x80)
    {ok, S3} = elf_parse_symtab:at_address(Elf, 16#401100),
    ?assertEqual(<<"my_global">>, S3#elf_sym.name),
    %% my_object at 0x42, size 8
    {ok, S4} = elf_parse_symtab:at_address(Elf, 16#45),
    ?assertEqual(<<"my_object">>, S4#elf_sym.name),
    %% Address not in any symbol
    ?assertEqual(error, elf_parse_symtab:at_address(Elf, 16#DEAD0000)).

at_address_absolute_test() ->
    Elf = build_test_elf(),
    %% my_object has SHN_ABS
    {ok, Obj} = elf_parse_symtab:lookup(Elf, <<"my_object">>),
    ?assertEqual(absolute, Obj#elf_sym.shndx).

stripped_test() ->
    Elf = build_stripped_elf(),
    ?assertEqual({error, no_symtab}, elf_parse_symtab:symbols(Elf)),
    ?assertEqual({error, no_symtab}, elf_parse_symtab:functions(Elf)),
    ?assertEqual(error, elf_parse_symtab:lookup(Elf, <<"main">>)),
    ?assertEqual(error, elf_parse_symtab:at_address(Elf, 16#401000)).
