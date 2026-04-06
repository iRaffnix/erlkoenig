-module(elf_patch_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("elf_parse.hrl").

%% ---------------------------------------------------------------------------
%% Test helpers — build a minimal ELF64 LE binary with symtab + PT_LOAD
%% ---------------------------------------------------------------------------

-define(SYM_SIZE, 24).

%% Build a minimal valid ELF64 LE binary (x86_64) with:
%%   - 1 PT_LOAD covering .text
%%   - Section 0: SHT_NULL
%%   - Section 1: .text (progbits, executable)
%%   - Section 2: .strtab (shstrtab / section names)
%%   - Section 3: .strtab (symbol string table)
%%   - Section 4: .symtab (symbol table, sh_link = 3)
%%
%% The .text section contains 32 bytes of 0x90 (NOP) at vaddr 0x400000.
%% Symbols: "test_func" at 0x400000 size 16, "small_func" at 0x400010 size 2.
build_test_elf_x86() ->
    build_test_elf_arch(x86_64).

build_test_elf_aarch64() ->
    build_test_elf_arch(aarch64).

build_test_elf_arch(Arch) ->
    Machine =
        case Arch of
            x86_64 -> ?EM_X86_64;
            aarch64 -> ?EM_AARCH64
        end,

    %% --- String tables ---
    ShStrTab =
        <<0,
            % idx 1
            ".text", 0,
            % idx 7
            ".strtab", 0,
            % idx 15
            ".symtab", 0>>,

    SymStrTab =
        <<0,
            % idx 1
            "test_func", 0,
            % idx 11
            "small_func", 0>>,

    %% --- .text content: 32 bytes of NOP ---
    TextSize = 32,
    TextContent = binary:copy(<<16#90>>, TextSize),

    %% --- Symbols ---
    Sym0 = sym_entry(0, 0, 0, 0, 0, 0),
    %% test_func: global func, section 1, vaddr 0x400000, size 16
    Sym1 = sym_entry(
        1,
        st_info(?STB_GLOBAL, ?STT_FUNC),
        0,
        1,
        16#400000,
        16
    ),
    %% small_func: global func, section 1, vaddr 0x400010, size 2
    Sym2 = sym_entry(
        11,
        st_info(?STB_GLOBAL, ?STT_FUNC),
        0,
        1,
        16#400010,
        2
    ),
    SymTab = <<Sym0/binary, Sym1/binary, Sym2/binary>>,

    %% --- Layout ---
    %% 0x000: ELF header (64)
    %% 0x040: PT_LOAD phdr (56)
    %% 0x078: .text content (32)
    %% 0x098: ShStrTab
    %% ShStrTab + size: SymStrTab
    %% SymStrTab + size: SymTab
    %% SymTab + size: align to 8, section headers (5 * 64 = 320)
    PhOff = 64,
    TextOff = PhOff + 56,
    TextVaddr = 16#400000,
    ShStrTabOff = TextOff + TextSize,
    SymStrTabOff = ShStrTabOff + byte_size(ShStrTab),
    SymTabOff = SymStrTabOff + byte_size(SymStrTab),
    ShOffUnaligned = SymTabOff + byte_size(SymTab),
    %% Align to 8 bytes
    ShOff = (ShOffUnaligned + 7) band (bnot 7),
    PadSize = ShOff - ShOffUnaligned,

    %% --- Section headers ---
    Sh0 = shdr_entry(0, ?SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0),
    Sh1 = shdr_entry(
        1,
        ?SHT_PROGBITS,
        ?SHF_ALLOC bor ?SHF_EXECINSTR,
        TextVaddr,
        TextOff,
        TextSize,
        0,
        0,
        16,
        0
    ),
    Sh2 = shdr_entry(
        7,
        ?SHT_STRTAB,
        0,
        0,
        ShStrTabOff,
        byte_size(ShStrTab),
        0,
        0,
        1,
        0
    ),
    Sh3 = shdr_entry(
        7,
        ?SHT_STRTAB,
        0,
        0,
        SymStrTabOff,
        byte_size(SymStrTab),
        0,
        0,
        1,
        0
    ),
    Sh4 = shdr_entry(
        15,
        ?SHT_SYMTAB,
        0,
        0,
        SymTabOff,
        byte_size(SymTab),
        3,
        0,
        8,
        ?SYM_SIZE
    ),

    %% --- ELF header ---
    Header = elf_header_le(
        ?ET_EXEC,
        Machine,
        TextVaddr,
        PhOff,
        ShOff,
        1,
        5,
        2
    ),

    %% --- PT_LOAD covering .text ---
    Phdr = phdr_le(
        ?PT_LOAD,
        ?PF_R bor ?PF_X,
        TextOff,
        TextVaddr,
        TextVaddr,
        TextSize,
        TextSize,
        16#1000
    ),

    Pad = <<0:(PadSize * 8)>>,
    <<Header/binary, Phdr/binary, TextContent/binary, ShStrTab/binary, SymStrTab/binary,
        SymTab/binary, Pad/binary, Sh0/binary, Sh1/binary, Sh2/binary, Sh3/binary, Sh4/binary>>.

%% ---------------------------------------------------------------------------
%% Binary construction helpers
%% ---------------------------------------------------------------------------

elf_header_le(Type, Machine, Entry, PhOff, ShOff, PhNum, ShNum, ShStrNdx) ->
    <<16#7F, "ELF", 2:8, 1:8, 1:8, 0:8, 0:64, Type:16/little, Machine:16/little, 1:32/little,
        Entry:64/little, PhOff:64/little, ShOff:64/little, 0:32/little, 64:16/little, 56:16/little,
        PhNum:16/little, 64:16/little, ShNum:16/little, ShStrNdx:16/little>>.

phdr_le(PType, PFlags, POffset, PVaddr, PPaddr, PFilesz, PMemsz, PAlign) ->
    <<PType:32/little, PFlags:32/little, POffset:64/little, PVaddr:64/little, PPaddr:64/little,
        PFilesz:64/little, PMemsz:64/little, PAlign:64/little>>.

shdr_entry(
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

%% ---------------------------------------------------------------------------
%% Temp file helpers
%% ---------------------------------------------------------------------------

tmp_path() ->
    Suffix =
        integer_to_list(erlang:unique_integer([positive, monotonic])) ++
            "_" ++ integer_to_list(rand:uniform(1000000)),
    "/tmp/erlkoenig_elf_test_" ++ Suffix.

write_tmp(Bin) ->
    Path = tmp_path(),
    ok = file:write_file(Path, Bin),
    Path.

cleanup(Paths) when is_list(Paths) ->
    lists:foreach(fun(P) -> file:delete(P) end, Paths);
cleanup(Path) ->
    cleanup([Path, Path ++ ".orig"]).

%% ---------------------------------------------------------------------------
%% Tests
%% ---------------------------------------------------------------------------

%% 1. patch_function/3 with a valid function name
patch_function_by_name_test() ->
    Bin = build_test_elf_x86(),
    Path = write_tmp(Bin),
    try
        Result = elf_patch:patch_function(Path, <<"test_func">>, ret),
        ?assertMatch({ok, _}, Result),
        {ok, Info} = Result,
        ?assertEqual(<<"test_func">>, maps:get(function, Info)),
        ?assertEqual(16#400000, maps:get(addr, Info)),
        ?assertEqual(16, maps:get(size, Info)),
        ?assertEqual(ret, maps:get(strategy, Info)),
        ?assertEqual(Path ++ ".orig", maps:get(backup, Info))
    after
        cleanup(Path)
    end.

%% 2. patch_function_at/4 with direct address
patch_function_at_test() ->
    Bin = build_test_elf_x86(),
    Path = write_tmp(Bin),
    try
        Result = elf_patch:patch_function_at(Path, 16#400000, 16, ret_zero),
        ?assertMatch({ok, _}, Result),
        {ok, Info} = Result,
        ?assertEqual(16#400000, maps:get(addr, Info)),
        ?assertEqual(16, maps:get(size, Info)),
        ?assertEqual(ret_zero, maps:get(strategy, Info))
    after
        cleanup(Path)
    end.

%% 3a. ret strategy — correct bytes (x86_64)
patch_ret_x86_test() ->
    Bin = build_test_elf_x86(),
    OrigSize = byte_size(Bin),
    Path = write_tmp(Bin),
    try
        {ok, _} = elf_patch:patch_function(Path, <<"test_func">>, ret),
        {ok, Patched} = file:read_file(Path),
        %% File offset of test_func: vaddr 0x400000, PT_LOAD vaddr 0x400000 offset 0x78
        %% So file offset = 0x78
        FileOff = 16#78,
        <<_:FileOff/binary, PatchArea:16/binary, _/binary>> = Patched,
        %% First byte: RET (0xC3), rest: INT3 (0xCC)
        Expected = <<16#C3, (binary:copy(<<16#CC>>, 15))/binary>>,
        ?assertEqual(Expected, PatchArea),
        ?assertEqual(OrigSize, byte_size(Patched))
    after
        cleanup(Path)
    end.

%% 3b. ret_zero strategy — correct bytes (x86_64)
patch_ret_zero_x86_test() ->
    Bin = build_test_elf_x86(),
    Path = write_tmp(Bin),
    try
        {ok, _} = elf_patch:patch_function(Path, <<"test_func">>, ret_zero),
        {ok, Patched} = file:read_file(Path),
        FileOff = 16#78,
        <<_:FileOff/binary, PatchArea:16/binary, _/binary>> = Patched,
        %% XOR EAX,EAX; RET + 13 bytes INT3
        Expected = <<16#31, 16#C0, 16#C3, (binary:copy(<<16#CC>>, 13))/binary>>,
        ?assertEqual(Expected, PatchArea)
    after
        cleanup(Path)
    end.

%% 3c. ret_error strategy — correct bytes (x86_64)
patch_ret_error_x86_test() ->
    Bin = build_test_elf_x86(),
    Path = write_tmp(Bin),
    try
        {ok, _} = elf_patch:patch_function(Path, <<"test_func">>, ret_error),
        {ok, Patched} = file:read_file(Path),
        FileOff = 16#78,
        <<_:FileOff/binary, PatchArea:16/binary, _/binary>> = Patched,
        %% MOV RAX,-1; RET + 8 bytes INT3
        Expected =
            <<16#48, 16#C7, 16#C0, 16#FF, 16#FF, 16#FF, 16#FF, 16#C3,
                (binary:copy(<<16#CC>>, 8))/binary>>,
        ?assertEqual(Expected, PatchArea)
    after
        cleanup(Path)
    end.

%% 3d. aarch64 ret strategy
patch_ret_aarch64_test() ->
    Bin = build_test_elf_aarch64(),
    Path = write_tmp(Bin),
    try
        {ok, _} = elf_patch:patch_function(Path, <<"test_func">>, ret),
        {ok, Patched} = file:read_file(Path),
        FileOff = 16#78,
        <<_:FileOff/binary, PatchArea:16/binary, _/binary>> = Patched,
        %% RET (4 bytes) + 3 * BRK #0 (12 bytes)
        Brk = <<16#00, 16#00, 16#20, 16#D4>>,
        Expected = <<16#C0, 16#03, 16#5F, 16#D6, Brk/binary, Brk/binary, Brk/binary>>,
        ?assertEqual(Expected, PatchArea)
    after
        cleanup(Path)
    end.

%% 3e. aarch64 ret_zero strategy
patch_ret_zero_aarch64_test() ->
    Bin = build_test_elf_aarch64(),
    Path = write_tmp(Bin),
    try
        {ok, _} = elf_patch:patch_function(Path, <<"test_func">>, ret_zero),
        {ok, Patched} = file:read_file(Path),
        FileOff = 16#78,
        <<_:FileOff/binary, PatchArea:16/binary, _/binary>> = Patched,
        %% MOV X0,XZR (4) + RET (4) + 2 * BRK #0 (8)
        Brk = <<16#00, 16#00, 16#20, 16#D4>>,
        Expected =
            <<16#E0, 16#03, 16#1F, 16#AA, 16#C0, 16#03, 16#5F, 16#D6, Brk/binary, Brk/binary>>,
        ?assertEqual(Expected, PatchArea)
    after
        cleanup(Path)
    end.

%% 4. INT3 padding fills remaining bytes (verified in tests 3a-3e above,
%%    but let's also verify explicitly with a larger func)
padding_fills_remaining_test() ->
    Bin = build_test_elf_x86(),
    Path = write_tmp(Bin),
    try
        {ok, _} = elf_patch:patch_function(Path, <<"test_func">>, ret),
        {ok, Patched} = file:read_file(Path),
        FileOff = 16#78,
        <<_:FileOff/binary, _Ret:1/binary, Padding:15/binary, _/binary>> = Patched,
        ?assertEqual(binary:copy(<<16#CC>>, 15), Padding)
    after
        cleanup(Path)
    end.

%% 5. Backup .orig file is created
backup_created_test() ->
    Bin = build_test_elf_x86(),
    Path = write_tmp(Bin),
    try
        {ok, Info} = elf_patch:patch_function(Path, <<"test_func">>, ret),
        BackupPath = maps:get(backup, Info),
        ?assert(filelib:is_regular(BackupPath)),
        {ok, BackupBin} = file:read_file(BackupPath),
        ?assertEqual(Bin, BackupBin)
    after
        cleanup(Path)
    end.

%% 6. verify_patch/1 on patched file succeeds
verify_patch_test() ->
    Bin = build_test_elf_x86(),
    Path = write_tmp(Bin),
    try
        {ok, _} = elf_patch:patch_function(Path, <<"test_func">>, ret),
        ?assertEqual(ok, elf_patch:verify_patch(Path))
    after
        cleanup(Path)
    end.

%% 7. list_patches/2 shows correct diff
list_patches_test() ->
    Bin = build_test_elf_x86(),
    Path = write_tmp(Bin),
    try
        {ok, Info} = elf_patch:patch_function(Path, <<"test_func">>, ret),
        BackupPath = maps:get(backup, Info),
        {ok, Diffs} = elf_patch:list_patches(BackupPath, Path),
        ?assert(length(Diffs) > 0),
        %% The first diff should be at the function's file offset
        [First | _] = Diffs,
        ?assertEqual(16#78, maps:get(offset, First)),
        %% Original bytes were NOPs, patched bytes start with RET
        OrigBytes = maps:get(original, First),
        PatchedBytes = maps:get(patched, First),
        ?assertEqual(byte_size(OrigBytes), byte_size(PatchedBytes)),
        <<16#C3, _/binary>> = PatchedBytes
    after
        cleanup(Path)
    end.

%% 8. Error: function not found
error_function_not_found_test() ->
    Bin = build_test_elf_x86(),
    Path = write_tmp(Bin),
    try
        Result = elf_patch:patch_function(Path, <<"nonexistent">>, ret),
        ?assertMatch({error, {symbol_not_found, <<"nonexistent">>}}, Result)
    after
        cleanup(Path)
    end.

%% 9. Error: function too small
error_function_too_small_test() ->
    Bin = build_test_elf_x86(),
    Path = write_tmp(Bin),
    try
        %% small_func has size 2, ret_error needs 8 bytes
        Result = elf_patch:patch_function(Path, <<"small_func">>, ret_error),
        ?assertMatch({error, {function_too_small, 2, 8}}, Result)
    after
        cleanup(Path)
    end.

%% 10. Error: invalid ELF file
error_invalid_elf_test() ->
    Path = write_tmp(<<"not an elf file at all">>),
    try
        ?assertMatch({error, _}, elf_patch:patch_function(Path, <<"main">>, ret)),
        ?assertMatch({error, _}, elf_patch:verify_patch(Path))
    after
        cleanup(Path)
    end.

%% 11. File size unchanged after patch
file_size_unchanged_test() ->
    Bin = build_test_elf_x86(),
    OrigSize = byte_size(Bin),
    Path = write_tmp(Bin),
    try
        {ok, _} = elf_patch:patch_function(Path, <<"test_func">>, ret),
        {ok, Patched} = file:read_file(Path),
        ?assertEqual(OrigSize, byte_size(Patched))
    after
        cleanup(Path)
    end.

%% Extra: backup already exists error
backup_exists_error_test() ->
    Bin = build_test_elf_x86(),
    Path = write_tmp(Bin),
    try
        %% Create the backup file first
        ok = file:write_file(Path ++ ".orig", <<"preexisting">>),
        Result = elf_patch:patch_function(Path, <<"test_func">>, ret),
        ?assertMatch({error, {backup_exists, _}}, Result)
    after
        cleanup(Path)
    end.

%% Extra: unsupported architecture
unsupported_arch_test() ->
    %% Build an ELF with RISC-V machine type
    Bin = build_test_elf_arch_raw(?EM_RISCV),
    Path = write_tmp(Bin),
    try
        Result = elf_patch:patch_function(Path, <<"test_func">>, ret),
        ?assertMatch({error, {unsupported_architecture, riscv}}, Result)
    after
        cleanup(Path)
    end.

%% Helper: build test ELF with arbitrary machine code for unsupported arch test
build_test_elf_arch_raw(Machine) ->
    ShStrTab = <<0, ".text", 0, ".strtab", 0, ".symtab", 0>>,
    SymStrTab = <<0, "test_func", 0, "small_func", 0>>,
    TextSize = 32,
    TextContent = binary:copy(<<16#90>>, TextSize),
    Sym0 = sym_entry(0, 0, 0, 0, 0, 0),
    Sym1 = sym_entry(1, st_info(?STB_GLOBAL, ?STT_FUNC), 0, 1, 16#400000, 16),
    Sym2 = sym_entry(11, st_info(?STB_GLOBAL, ?STT_FUNC), 0, 1, 16#400010, 2),
    SymTab = <<Sym0/binary, Sym1/binary, Sym2/binary>>,
    PhOff = 64,
    TextOff = PhOff + 56,
    TextVaddr = 16#400000,
    ShStrTabOff = TextOff + TextSize,
    SymStrTabOff = ShStrTabOff + byte_size(ShStrTab),
    SymTabOff = SymStrTabOff + byte_size(SymStrTab),
    ShOffUnaligned = SymTabOff + byte_size(SymTab),
    ShOff = (ShOffUnaligned + 7) band (bnot 7),
    PadSize = ShOff - ShOffUnaligned,
    Sh0 = shdr_entry(0, ?SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0),
    Sh1 = shdr_entry(
        1,
        ?SHT_PROGBITS,
        ?SHF_ALLOC bor ?SHF_EXECINSTR,
        TextVaddr,
        TextOff,
        TextSize,
        0,
        0,
        16,
        0
    ),
    Sh2 = shdr_entry(
        7,
        ?SHT_STRTAB,
        0,
        0,
        ShStrTabOff,
        byte_size(ShStrTab),
        0,
        0,
        1,
        0
    ),
    Sh3 = shdr_entry(
        7,
        ?SHT_STRTAB,
        0,
        0,
        SymStrTabOff,
        byte_size(SymStrTab),
        0,
        0,
        1,
        0
    ),
    Sh4 = shdr_entry(
        15,
        ?SHT_SYMTAB,
        0,
        0,
        SymTabOff,
        byte_size(SymTab),
        3,
        0,
        8,
        ?SYM_SIZE
    ),
    Header = elf_header_le(
        ?ET_EXEC,
        Machine,
        TextVaddr,
        PhOff,
        ShOff,
        1,
        5,
        2
    ),
    Phdr = phdr_le(
        ?PT_LOAD,
        ?PF_R bor ?PF_X,
        TextOff,
        TextVaddr,
        TextVaddr,
        TextSize,
        TextSize,
        16#1000
    ),
    Pad = <<0:(PadSize * 8)>>,
    <<Header/binary, Phdr/binary, TextContent/binary, ShStrTab/binary, SymStrTab/binary,
        SymTab/binary, Pad/binary, Sh0/binary, Sh1/binary, Sh2/binary, Sh3/binary, Sh4/binary>>.
