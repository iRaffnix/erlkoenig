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

-module(elf_parse).
-moduledoc """
ELF64 binary parser in pure Erlang.

Parses ELF64 headers, program headers, and section headers using
binary pattern matching. Supports both little-endian and big-endian
binaries, with the fast path optimized for little-endian (x86_64/aarch64).

All parsing is done from an in-memory binary -- either read from a file
path or supplied directly. The raw binary is retained in the #elf{}
record so that section_data/2 can extract content without re-reading.
""".

-include("elf_parse.hrl").

%% Primary API
-export([
    from_file/1,
    from_binary/1
]).

%% Query API
-export([
    section/2,
    section_data/2,
    vaddr_to_offset/2,
    is_static/1,
    is_pie/1,
    has_debug_info/1,
    executable_sections/1
]).

-export_type([
    elf/0,
    parse_error/0
]).

-type elf() :: #elf{}.
-type parse_error() ::
    {error, not_elf}
    | {error, not_elf64}
    | {error, unsupported_endian}
    | {error, truncated}
    | {error, {file, term()}}.

%% ---------------------------------------------------------------------------
%% Primary API
%% ---------------------------------------------------------------------------

-spec from_file(file:name_all()) -> {ok, elf()} | parse_error().
from_file(Path) ->
    case file:read_file(Path) of
        {ok, Bin} -> from_binary(Bin);
        {error, Reason} -> {error, {file, Reason}}
    end.

-spec from_binary(binary()) -> {ok, elf()} | parse_error().
from_binary(Bin) when byte_size(Bin) < ?ELF64_EHDR_SIZE ->
    {error, truncated};
from_binary(Bin) ->
    case Bin of
        <<16#7F, "ELF", ?ELFCLASS64, Endian:8, 1:8, _Rest/binary>> ->
            parse_elf(Bin, decode_endian(Endian));
        <<16#7F, "ELF", ?ELFCLASS64, _:8, _/binary>> ->
            %% Version != 1 — treat as unsupported but not invalid magic
            {error, unsupported_endian};
        <<16#7F, "ELF", Class:8, _/binary>> when Class =/= ?ELFCLASS64 ->
            {error, not_elf64};
        <<16#7F, "ELF", _/binary>> ->
            {error, not_elf64};
        _ ->
            {error, not_elf}
    end.

%% ---------------------------------------------------------------------------
%% Query API
%% ---------------------------------------------------------------------------

-doc "Find a section header by name (binary).".
-spec section(binary(), elf()) -> {ok, #elf_shdr{}} | {error, not_found}.
section(Name, #elf{shdrs = Shdrs}) when is_binary(Name) ->
    case [S || S <- Shdrs, S#elf_shdr.name =:= Name] of
        [H | _] -> {ok, H};
        [] -> {error, not_found}
    end.

-doc "Read the raw content bytes for a section.".
-spec section_data(#elf_shdr{}, elf()) -> {ok, binary()} | {error, nobits | truncated}.
section_data(#elf_shdr{type = nobits}, _Elf) ->
    {error, nobits};
section_data(#elf_shdr{offset = Off, size = Sz}, #elf{bin = Bin}) when
    Off + Sz =< byte_size(Bin)
->
    {ok, binary:part(Bin, Off, Sz)};
section_data(_, _) ->
    {error, truncated}.

-doc "Convert a virtual address to a file offset using PT_LOAD segments.".
-spec vaddr_to_offset(non_neg_integer(), elf()) ->
    {ok, non_neg_integer()} | {error, not_mapped}.
vaddr_to_offset(Vaddr, #elf{phdrs = Phdrs}) ->
    vaddr_to_offset_1(Vaddr, Phdrs).

-doc "True if the binary is statically linked (no PT_INTERP segment).".
-spec is_static(elf()) -> boolean().
is_static(#elf{phdrs = Phdrs}) ->
    not has_phdr_type(interp, Phdrs).

-doc """
True if the binary is a position-independent executable
(ET_DYN without PT_INTERP -- i.e. static PIE or Go-style PIE).
""".
-spec is_pie(elf()) -> boolean().
is_pie(#elf{header = #elf_header{type = dyn}, phdrs = Phdrs}) ->
    not has_phdr_type(interp, Phdrs);
is_pie(_) ->
    false.

-doc "True if any DWARF debug sections (.debug_*) are present.".
-spec has_debug_info(elf()) -> boolean().
has_debug_info(#elf{shdrs = Shdrs}) ->
    lists:any(
        fun(#elf_shdr{name = N}) ->
            case N of
                <<".debug_", _/binary>> -> true;
                _ -> false
            end
        end,
        Shdrs
    ).

-doc "Return all section headers with the SHF_EXECINSTR flag.".
-spec executable_sections(elf()) -> [#elf_shdr{}].
executable_sections(#elf{shdrs = Shdrs}) ->
    [S || S <- Shdrs, lists:member(execinstr, S#elf_shdr.flags)].

%% ---------------------------------------------------------------------------
%% Internal — ELF header parsing
%% ---------------------------------------------------------------------------

-spec decode_endian(byte()) -> little | big | invalid.
decode_endian(?ELFDATA2LSB) -> little;
decode_endian(?ELFDATA2MSB) -> big;
decode_endian(_) -> invalid.

-spec parse_elf(binary(), little | big | invalid) -> {ok, elf()} | parse_error().
parse_elf(_Bin, invalid) ->
    {error, unsupported_endian};
parse_elf(Bin, Endian) ->
    maybe
        {ok, Hdr} ?= parse_header(Bin, Endian),
        {ok, Phdrs} ?= parse_phdrs(Bin, Endian, Hdr),
        {ok, Shdrs0} ?= parse_shdrs(Bin, Endian, Hdr),
        Shdrs = resolve_section_names(Bin, Hdr, Shdrs0),
        {ok, #elf{
            bin = Bin,
            header = Hdr,
            phdrs = Phdrs,
            shdrs = Shdrs
        }}
    end.

%% Little-endian fast path (vast majority of real-world ELF binaries).
parse_header(Bin, little) ->
    case Bin of
        <<16#7F, "ELF", ?ELFCLASS64, ?ELFDATA2LSB, 1:8, OsAbi:8, _Pad:64, Type:16/little,
            Machine:16/little, _Version:32/little, Entry:64/little, PhOff:64/little,
            ShOff:64/little, Flags:32/little, _EhSize:16/little, _PhEntSize:16/little,
            PhNum:16/little, _ShEntSize:16/little, ShNum:16/little, ShStrNdx:16/little,
            _/binary>> ->
            {ok, #elf_header{
                class = 64,
                endian = little,
                os_abi = OsAbi,
                type = decode_type(Type),
                machine = decode_machine(Machine),
                entry = Entry,
                ph_offset = PhOff,
                sh_offset = ShOff,
                flags = Flags,
                ph_count = PhNum,
                sh_count = ShNum,
                sh_strndx = ShStrNdx
            }};
        _ ->
            {error, truncated}
    end;
parse_header(Bin, big) ->
    case Bin of
        <<16#7F, "ELF", ?ELFCLASS64, ?ELFDATA2MSB, 1:8, OsAbi:8, _Pad:64, Type:16/big,
            Machine:16/big, _Version:32/big, Entry:64/big, PhOff:64/big, ShOff:64/big, Flags:32/big,
            _EhSize:16/big, _PhEntSize:16/big, PhNum:16/big, _ShEntSize:16/big, ShNum:16/big,
            ShStrNdx:16/big, _/binary>> ->
            {ok, #elf_header{
                class = 64,
                endian = big,
                os_abi = OsAbi,
                type = decode_type(Type),
                machine = decode_machine(Machine),
                entry = Entry,
                ph_offset = PhOff,
                sh_offset = ShOff,
                flags = Flags,
                ph_count = PhNum,
                sh_count = ShNum,
                sh_strndx = ShStrNdx
            }};
        _ ->
            {error, truncated}
    end.

%% ---------------------------------------------------------------------------
%% Internal — Program header parsing
%% ---------------------------------------------------------------------------

-spec parse_phdrs(binary(), little | big, #elf_header{}) ->
    {ok, [#elf_phdr{}]} | parse_error().
parse_phdrs(_Bin, _Endian, #elf_header{ph_count = 0}) ->
    {ok, []};
parse_phdrs(Bin, Endian, #elf_header{ph_offset = Off, ph_count = N}) ->
    Required = Off + N * ?ELF64_PHDR_SIZE,
    case byte_size(Bin) >= Required of
        true -> {ok, parse_phdrs_1(Bin, Endian, Off, N, [])};
        false -> {error, truncated}
    end.

parse_phdrs_1(_Bin, _Endian, _Off, 0, Acc) ->
    lists:reverse(Acc);
parse_phdrs_1(Bin, little, Off, N, Acc) ->
    <<_:Off/binary, PType:32/little, PFlags:32/little, POffset:64/little, PVaddr:64/little,
        PPaddr:64/little, PFilesz:64/little, PMemsz:64/little, PAlign:64/little, _/binary>> = Bin,
    Phdr = #elf_phdr{
        type = decode_phdr_type(PType),
        flags = decode_phdr_flags(PFlags),
        offset = POffset,
        vaddr = PVaddr,
        paddr = PPaddr,
        filesz = PFilesz,
        memsz = PMemsz,
        align = PAlign
    },
    parse_phdrs_1(Bin, little, Off + ?ELF64_PHDR_SIZE, N - 1, [Phdr | Acc]);
parse_phdrs_1(Bin, big, Off, N, Acc) ->
    <<_:Off/binary, PType:32/big, PFlags:32/big, POffset:64/big, PVaddr:64/big, PPaddr:64/big,
        PFilesz:64/big, PMemsz:64/big, PAlign:64/big, _/binary>> = Bin,
    Phdr = #elf_phdr{
        type = decode_phdr_type(PType),
        flags = decode_phdr_flags(PFlags),
        offset = POffset,
        vaddr = PVaddr,
        paddr = PPaddr,
        filesz = PFilesz,
        memsz = PMemsz,
        align = PAlign
    },
    parse_phdrs_1(Bin, big, Off + ?ELF64_PHDR_SIZE, N - 1, [Phdr | Acc]).

%% ---------------------------------------------------------------------------
%% Internal — Section header parsing
%% ---------------------------------------------------------------------------

-spec parse_shdrs(binary(), little | big, #elf_header{}) ->
    {ok, [#elf_shdr{}]} | parse_error().
parse_shdrs(_Bin, _Endian, #elf_header{sh_count = 0}) ->
    {ok, []};
parse_shdrs(Bin, Endian, #elf_header{sh_offset = Off, sh_count = N}) ->
    Required = Off + N * ?ELF64_SHDR_SIZE,
    case byte_size(Bin) >= Required of
        true -> {ok, parse_shdrs_1(Bin, Endian, Off, N, 0, [])};
        false -> {error, truncated}
    end.

parse_shdrs_1(_Bin, _Endian, _Off, 0, _Idx, Acc) ->
    lists:reverse(Acc);
parse_shdrs_1(Bin, little, Off, N, Idx, Acc) ->
    <<_:Off/binary, ShName:32/little, ShType:32/little, ShFlags:64/little, ShAddr:64/little,
        ShOffset:64/little, ShSize:64/little, ShLink:32/little, ShInfo:32/little,
        ShAddralign:64/little, ShEntsize:64/little, _/binary>> = Bin,
    Shdr = #elf_shdr{
        index = Idx,
        name_idx = ShName,
        name = <<>>,
        type = decode_shdr_type(ShType),
        flags = decode_shdr_flags(ShFlags),
        addr = ShAddr,
        offset = ShOffset,
        size = ShSize,
        link = ShLink,
        info = ShInfo,
        addralign = ShAddralign,
        entsize = ShEntsize
    },
    parse_shdrs_1(Bin, little, Off + ?ELF64_SHDR_SIZE, N - 1, Idx + 1, [Shdr | Acc]);
parse_shdrs_1(Bin, big, Off, N, Idx, Acc) ->
    <<_:Off/binary, ShName:32/big, ShType:32/big, ShFlags:64/big, ShAddr:64/big, ShOffset:64/big,
        ShSize:64/big, ShLink:32/big, ShInfo:32/big, ShAddralign:64/big, ShEntsize:64/big,
        _/binary>> = Bin,
    Shdr = #elf_shdr{
        index = Idx,
        name_idx = ShName,
        name = <<>>,
        type = decode_shdr_type(ShType),
        flags = decode_shdr_flags(ShFlags),
        addr = ShAddr,
        offset = ShOffset,
        size = ShSize,
        link = ShLink,
        info = ShInfo,
        addralign = ShAddralign,
        entsize = ShEntsize
    },
    parse_shdrs_1(Bin, big, Off + ?ELF64_SHDR_SIZE, N - 1, Idx + 1, [Shdr | Acc]).

%% ---------------------------------------------------------------------------
%% Internal — Section name resolution from .shstrtab
%% ---------------------------------------------------------------------------

-spec resolve_section_names(binary(), #elf_header{}, [#elf_shdr{}]) -> [#elf_shdr{}].
resolve_section_names(_Bin, #elf_header{sh_strndx = 0}, Shdrs) ->
    Shdrs;
resolve_section_names(Bin, #elf_header{sh_strndx = Idx}, Shdrs) ->
    case find_shdr_by_index(Idx, Shdrs) of
        {ok, #elf_shdr{offset = Off, size = Sz}} when Off + Sz =< byte_size(Bin) ->
            StrTab = binary:part(Bin, Off, Sz),
            [S#elf_shdr{name = read_strtab(StrTab, S#elf_shdr.name_idx)} || S <- Shdrs];
        _ ->
            Shdrs
    end.

-spec find_shdr_by_index(non_neg_integer(), [#elf_shdr{}]) ->
    {ok, #elf_shdr{}} | error.
find_shdr_by_index(_Idx, []) ->
    error;
find_shdr_by_index(Idx, [S | _]) when S#elf_shdr.index =:= Idx ->
    {ok, S};
find_shdr_by_index(Idx, [_ | T]) ->
    find_shdr_by_index(Idx, T).

%% Read a NUL-terminated string from a string table binary at the given offset.
-spec read_strtab(binary(), non_neg_integer()) -> binary().
read_strtab(Tab, Offset) when Offset < byte_size(Tab) ->
    <<_:Offset/binary, Rest/binary>> = Tab,
    case binary:match(Rest, <<0>>) of
        {Pos, 1} -> binary:part(Rest, 0, Pos);
        nomatch -> Rest
    end;
read_strtab(_, _) ->
    <<>>.

%% ---------------------------------------------------------------------------
%% Internal — vaddr → file offset via PT_LOAD segments
%% ---------------------------------------------------------------------------

-spec vaddr_to_offset_1(non_neg_integer(), [#elf_phdr{}]) ->
    {ok, non_neg_integer()} | {error, not_mapped}.
vaddr_to_offset_1(_Vaddr, []) ->
    {error, not_mapped};
vaddr_to_offset_1(Vaddr, [
    #elf_phdr{
        type = load,
        vaddr = Base,
        offset = Off,
        memsz = Memsz
    }
    | _
]) when
    Vaddr >= Base, Vaddr < Base + Memsz
->
    {ok, Off + (Vaddr - Base)};
vaddr_to_offset_1(Vaddr, [_ | T]) ->
    vaddr_to_offset_1(Vaddr, T).

%% ---------------------------------------------------------------------------
%% Internal — Decoders
%% ---------------------------------------------------------------------------

decode_type(?ET_EXEC) -> exec;
decode_type(?ET_DYN) -> dyn;
decode_type(?ET_REL) -> rel;
decode_type(?ET_CORE) -> core;
decode_type(V) -> {unknown, V}.

decode_machine(?EM_X86_64) -> x86_64;
decode_machine(?EM_AARCH64) -> aarch64;
decode_machine(?EM_RISCV) -> riscv;
decode_machine(?EM_ARM) -> arm;
decode_machine(?EM_386) -> i386;
decode_machine(V) -> {unknown, V}.

-spec decode_phdr_type(non_neg_integer()) ->
    load
    | dynamic
    | interp
    | note
    | tls
    | phdr
    | gnu_eh_frame
    | gnu_stack
    | gnu_relro
    | {unknown, non_neg_integer()}.
decode_phdr_type(?PT_NULL) -> null;
decode_phdr_type(?PT_LOAD) -> load;
decode_phdr_type(?PT_DYNAMIC) -> dynamic;
decode_phdr_type(?PT_INTERP) -> interp;
decode_phdr_type(?PT_NOTE) -> note;
decode_phdr_type(?PT_PHDR) -> phdr;
decode_phdr_type(?PT_TLS) -> tls;
decode_phdr_type(?PT_GNU_EH_FRAME) -> gnu_eh_frame;
decode_phdr_type(?PT_GNU_STACK) -> gnu_stack;
decode_phdr_type(?PT_GNU_RELRO) -> gnu_relro;
decode_phdr_type(V) -> {unknown, V}.

-spec decode_phdr_flags(non_neg_integer()) -> [r | w | x].
decode_phdr_flags(Flags) ->
    lists:append([
        case Flags band ?PF_R of
            0 -> [];
            _ -> [r]
        end,
        case Flags band ?PF_W of
            0 -> [];
            _ -> [w]
        end,
        case Flags band ?PF_X of
            0 -> [];
            _ -> [x]
        end
    ]).

decode_shdr_type(?SHT_NULL) -> null;
decode_shdr_type(?SHT_PROGBITS) -> progbits;
decode_shdr_type(?SHT_SYMTAB) -> symtab;
decode_shdr_type(?SHT_STRTAB) -> strtab;
decode_shdr_type(?SHT_RELA) -> rela;
decode_shdr_type(?SHT_HASH) -> hash;
decode_shdr_type(?SHT_DYNAMIC) -> dynamic;
decode_shdr_type(?SHT_NOTE) -> note;
decode_shdr_type(?SHT_NOBITS) -> nobits;
decode_shdr_type(?SHT_REL) -> rel;
decode_shdr_type(?SHT_DYNSYM) -> dynsym;
decode_shdr_type(?SHT_INIT_ARRAY) -> init_array;
decode_shdr_type(?SHT_FINI_ARRAY) -> fini_array;
decode_shdr_type(V) -> {unknown, V}.

-spec decode_shdr_flags(non_neg_integer()) ->
    [write | alloc | execinstr | merge | strings | tls].
decode_shdr_flags(Flags) ->
    lists:append([
        case Flags band ?SHF_WRITE of
            0 -> [];
            _ -> [write]
        end,
        case Flags band ?SHF_ALLOC of
            0 -> [];
            _ -> [alloc]
        end,
        case Flags band ?SHF_EXECINSTR of
            0 -> [];
            _ -> [execinstr]
        end,
        case Flags band ?SHF_MERGE of
            0 -> [];
            _ -> [merge]
        end,
        case Flags band ?SHF_STRINGS of
            0 -> [];
            _ -> [strings]
        end,
        case Flags band ?SHF_TLS of
            0 -> [];
            _ -> [tls]
        end
    ]).

-spec has_phdr_type(atom(), [#elf_phdr{}]) -> boolean().
has_phdr_type(Type, Phdrs) ->
    lists:any(fun(#elf_phdr{type = T}) -> T =:= Type end, Phdrs).
