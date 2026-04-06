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

%% DWARF Debug Info Records
%% Reference: DWARF Debugging Information Format Version 4/5

-ifndef(ELF_LANG_DWARF_HRL).
-define(ELF_LANG_DWARF_HRL, true).

-record(dwarf_cu, {
    producer :: binary() | undefined,
    language ::
        c
        | c89
        | c99
        | c11
        | c17
        | cpp
        | cpp11
        | cpp14
        | go
        | rust
        | {unknown, non_neg_integer()}
        | undefined,
    comp_dir :: binary() | undefined,
    name :: binary() | undefined,
    %% DWARF version
    version :: non_neg_integer()
}).

%% DW_TAG
-define(DW_TAG_compile_unit, 16#11).

%% DW_AT
-define(DW_AT_name, 16#03).
-define(DW_AT_language, 16#13).
-define(DW_AT_producer, 16#25).
-define(DW_AT_comp_dir, 16#1B).

%% DW_FORM
-define(DW_FORM_addr, 16#01).
-define(DW_FORM_data2, 16#05).
-define(DW_FORM_data4, 16#06).
-define(DW_FORM_data8, 16#07).
-define(DW_FORM_string, 16#08).
-define(DW_FORM_data1, 16#0B).
-define(DW_FORM_strp, 16#0E).
-define(DW_FORM_sec_offset, 16#17).
-define(DW_FORM_exprloc, 16#18).
-define(DW_FORM_flag_present, 16#19).
-define(DW_FORM_line_strp, 16#1F).
-define(DW_FORM_implicit_const, 16#21).

%% DW_LANG
-define(DW_LANG_C89, 16#0001).
-define(DW_LANG_C, 16#0002).
-define(DW_LANG_C_plus_plus, 16#0004).
-define(DW_LANG_C99, 16#000C).
-define(DW_LANG_Go, 16#0016).
-define(DW_LANG_C_plus_plus_11, 16#001A).
-define(DW_LANG_Rust, 16#001C).
-define(DW_LANG_C11, 16#001D).
-define(DW_LANG_C_plus_plus_14, 16#0021).
-define(DW_LANG_C17, 16#002C).

-endif.
