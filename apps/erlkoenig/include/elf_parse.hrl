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

%% ELF64 Parser Records
%% Reference: elf(5), ELF-64 Object File Format

-ifndef(ELF_PARSE_HRL).
-define(ELF_PARSE_HRL, true).

%% ELF Magic
-define(ELF_MAGIC, <<16#7F, "ELF">>).

%% ELF Class
-define(ELFCLASS64, 2).

%% ELF Data (Endianness)
-define(ELFDATA2LSB, 1).
-define(ELFDATA2MSB, 2).

%% ELF Type (e_type)
-define(ET_NONE, 0).
-define(ET_REL, 1).
-define(ET_EXEC, 2).
-define(ET_DYN, 3).
-define(ET_CORE, 4).

%% ELF Machine (e_machine)
-define(EM_386, 16#03).
-define(EM_ARM, 16#28).
-define(EM_X86_64, 16#3E).
-define(EM_AARCH64, 16#B7).
-define(EM_RISCV, 16#F3).

%% Program Header Types (p_type)
-define(PT_NULL, 16#00000000).
-define(PT_LOAD, 16#00000001).
-define(PT_DYNAMIC, 16#00000002).
-define(PT_INTERP, 16#00000003).
-define(PT_NOTE, 16#00000004).
-define(PT_SHLIB, 16#00000005).
-define(PT_PHDR, 16#00000006).
-define(PT_TLS, 16#00000007).
-define(PT_GNU_EH_FRAME, 16#6474E550).
-define(PT_GNU_STACK, 16#6474E551).
-define(PT_GNU_RELRO, 16#6474E552).

%% Program Header Flags (p_flags)
-define(PF_X, 16#1).
-define(PF_W, 16#2).
-define(PF_R, 16#4).

%% Section Header Types (sh_type)
-define(SHT_NULL, 0).
-define(SHT_PROGBITS, 1).
-define(SHT_SYMTAB, 2).
-define(SHT_STRTAB, 3).
-define(SHT_RELA, 4).
-define(SHT_HASH, 5).
-define(SHT_DYNAMIC, 6).
-define(SHT_NOTE, 7).
-define(SHT_NOBITS, 8).
-define(SHT_REL, 9).
-define(SHT_DYNSYM, 11).
-define(SHT_INIT_ARRAY, 14).
-define(SHT_FINI_ARRAY, 15).

%% Section Header Flags (sh_flags)
-define(SHF_WRITE, 16#1).
-define(SHF_ALLOC, 16#2).
-define(SHF_EXECINSTR, 16#4).
-define(SHF_MERGE, 16#10).
-define(SHF_STRINGS, 16#20).
-define(SHF_TLS, 16#400).

%% Symbol Binding (upper nibble of st_info)
-define(STB_LOCAL, 0).
-define(STB_GLOBAL, 1).
-define(STB_WEAK, 2).

%% Symbol Type (lower nibble of st_info)
-define(STT_NOTYPE, 0).
-define(STT_OBJECT, 1).
-define(STT_FUNC, 2).
-define(STT_SECTION, 3).
-define(STT_FILE, 4).
-define(STT_COMMON, 5).
-define(STT_TLS, 6).
-define(STT_GNU_IFUNC, 10).

%% Special Section Indices
-define(SHN_UNDEF, 16#0000).
-define(SHN_ABS, 16#FFF1).
-define(SHN_COMMON, 16#FFF2).

%% NOTE types
-define(NT_GNU_BUILD_ID, 3).

%% ELF64 structure sizes (bytes)
-define(ELF64_EHDR_SIZE, 64).
-define(ELF64_PHDR_SIZE, 56).
-define(ELF64_SHDR_SIZE, 64).
-define(ELF64_SYM_SIZE, 24).

%% --- Records ---

-record(elf_header, {
    class :: 64,
    endian :: little | big,
    os_abi :: byte(),
    type :: exec | dyn | rel | core | {unknown, non_neg_integer()},
    machine :: x86_64 | aarch64 | riscv | arm | i386 | {unknown, non_neg_integer()},
    entry :: non_neg_integer(),
    ph_offset :: non_neg_integer(),
    sh_offset :: non_neg_integer(),
    flags :: non_neg_integer(),
    ph_count :: non_neg_integer(),
    sh_count :: non_neg_integer(),
    sh_strndx :: non_neg_integer()
}).

-record(elf_phdr, {
    type ::
        load
        | dynamic
        | interp
        | note
        | tls
        | phdr
        | gnu_eh_frame
        | gnu_stack
        | gnu_relro
        | {unknown, non_neg_integer()},
    flags :: [r | w | x],
    offset :: non_neg_integer(),
    vaddr :: non_neg_integer(),
    paddr :: non_neg_integer(),
    filesz :: non_neg_integer(),
    memsz :: non_neg_integer(),
    align :: non_neg_integer()
}).

-record(elf_shdr, {
    index :: non_neg_integer(),
    name_idx :: non_neg_integer(),
    name :: binary(),
    type ::
        null
        | progbits
        | symtab
        | strtab
        | rela
        | hash
        | dynamic
        | note
        | nobits
        | rel
        | dynsym
        | init_array
        | fini_array
        | {unknown, non_neg_integer()},
    flags :: [write | alloc | execinstr | merge | strings | tls],
    addr :: non_neg_integer(),
    offset :: non_neg_integer(),
    size :: non_neg_integer(),
    link :: non_neg_integer(),
    info :: non_neg_integer(),
    addralign :: non_neg_integer(),
    entsize :: non_neg_integer()
}).

-record(elf_sym, {
    name :: binary(),
    bind :: local | global | weak | {unknown, non_neg_integer()},
    type ::
        notype
        | object
        | func
        | section
        | file
        | common
        | tls
        | ifunc
        | {unknown, non_neg_integer()},
    shndx :: non_neg_integer() | undefined | absolute | common,
    value :: non_neg_integer(),
    size :: non_neg_integer()
}).

-record(elf_note, {
    name :: binary(),
    type :: non_neg_integer(),
    desc :: binary()
}).

%% Top-level parsed ELF
-record(elf, {
    %% raw file data
    bin :: binary(),
    header :: #elf_header{},
    phdrs :: [#elf_phdr{}],
    shdrs :: [#elf_shdr{}]
}).

-endif.
