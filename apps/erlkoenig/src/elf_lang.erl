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

-module(elf_lang).
-moduledoc """
Language detection and dispatch for ELF binaries.

Detects the source language of an ELF binary by inspecting sections,
symbols, and DWARF metadata. Dispatches to language-specific parsers
for detailed analysis.

Detection priority:
  1. Go     -- .gopclntab or .go.buildinfo section
  2. Rust   -- _ZN/_R mangled symbols or .cargo/ panic strings
  3. Zig    -- std.start/std.builtin symbols or /zig/ in DWARF comp_dir
  4. C/C++  -- DWARF DW_AT_language attribute
  5. unknown
""".

-include("elf_parse.hrl").
-include("elf_lang_dwarf.hrl").

-export([
    detect/1,
    analyze/1
]).

-export_type([language/0]).

-type language() :: go | rust | zig | c | cpp | unknown.

%% ---------------------------------------------------------------------------
%% Public API
%% ---------------------------------------------------------------------------

-doc "Detect the source language of an ELF binary.".
-spec detect(#elf{}) -> language().
detect(Elf) ->
    case is_go(Elf) of
        true ->
            go;
        false ->
            case is_rust(Elf) of
                true ->
                    rust;
                false ->
                    case is_zig(Elf) of
                        true -> zig;
                        false -> detect_from_dwarf(Elf)
                    end
            end
    end.

-doc "Detect language and dispatch to the appropriate parser.".
-spec analyze(#elf{}) -> {ok, #{language => language(), info => term()}} | {error, term()}.
analyze(Elf) ->
    Lang = detect(Elf),
    case Lang of
        go ->
            case elf_lang_go:parse(Elf) of
                {ok, Info} ->
                    {ok, #{language => go, info => Info}};
                {error, Reason} ->
                    {error, Reason}
            end;
        rust ->
            analyze_rust(Elf);
        zig ->
            analyze_dwarf(zig, Elf);
        c ->
            analyze_dwarf(c, Elf);
        cpp ->
            analyze_dwarf(cpp, Elf);
        unknown ->
            {ok, #{language => unknown, info => undefined}}
    end.

%% ---------------------------------------------------------------------------
%% Go detection
%% ---------------------------------------------------------------------------

-spec is_go(#elf{}) -> boolean().
is_go(Elf) ->
    has_section(<<".gopclntab">>, Elf) orelse
        has_section(<<".go.buildinfo">>, Elf).

%% ---------------------------------------------------------------------------
%% Rust detection
%% ---------------------------------------------------------------------------

-spec is_rust(#elf{}) -> boolean().
is_rust(Elf) ->
    %% Try the dedicated module first if available.
    case try_call(elf_lang_rust, is_rust, [Elf]) of
        {ok, true} -> true;
        {ok, false} -> false;
        {error, _} -> is_rust_fallback(Elf)
    end.

-spec is_rust_fallback(#elf{}) -> boolean().
is_rust_fallback(Elf) ->
    case elf_parse_symtab:symbols(Elf) of
        {ok, Syms} ->
            lists:any(
                fun(#elf_sym{name = Name}) ->
                    is_rust_symbol(Name)
                end,
                Syms
            );
        {error, _} ->
            false
    end.

-spec is_rust_symbol(binary()) -> boolean().
is_rust_symbol(<<"_ZN", _/binary>>) -> true;
is_rust_symbol(<<"_R", _/binary>>) -> true;
is_rust_symbol(_) -> false.

%% ---------------------------------------------------------------------------
%% Zig detection
%% ---------------------------------------------------------------------------

-spec is_zig(#elf{}) -> boolean().
is_zig(Elf) ->
    is_zig_symbols(Elf) orelse is_zig_dwarf(Elf).

-spec is_zig_symbols(#elf{}) -> boolean().
is_zig_symbols(Elf) ->
    case elf_parse_symtab:symbols(Elf) of
        {ok, Syms} ->
            lists:any(
                fun(#elf_sym{name = Name}) ->
                    is_zig_symbol(Name)
                end,
                Syms
            );
        {error, _} ->
            false
    end.

-spec is_zig_symbol(binary()) -> boolean().
is_zig_symbol(Name) ->
    binary:match(Name, <<"std.start">>) =/= nomatch orelse
        binary:match(Name, <<"std.builtin">>) =/= nomatch orelse
        binary:match(Name, <<"std.os.linux">>) =/= nomatch.

-spec is_zig_dwarf(#elf{}) -> boolean().
is_zig_dwarf(Elf) ->
    case elf_lang_dwarf:has_debug_info(Elf) of
        false ->
            false;
        true ->
            case elf_lang_dwarf:compilation_units(Elf) of
                {ok, CUs} ->
                    lists:any(
                        fun(#dwarf_cu{comp_dir = Dir}) ->
                            is_binary(Dir) andalso
                                binary:match(Dir, <<"/zig/">>) =/= nomatch
                        end,
                        CUs
                    );
                {error, _} ->
                    false
            end
    end.

%% ---------------------------------------------------------------------------
%% DWARF-based language detection (C / C++)
%% ---------------------------------------------------------------------------

-spec detect_from_dwarf(#elf{}) -> c | cpp | unknown.
detect_from_dwarf(Elf) ->
    case elf_lang_dwarf:has_debug_info(Elf) of
        false ->
            unknown;
        true ->
            case elf_lang_dwarf:compilation_units(Elf) of
                {ok, CUs} -> classify_dwarf_lang(CUs);
                {error, _} -> unknown
            end
    end.

-spec classify_dwarf_lang([#dwarf_cu{}]) -> c | cpp | unknown.
classify_dwarf_lang([]) ->
    unknown;
classify_dwarf_lang(CUs) ->
    Langs = [L || #dwarf_cu{language = L} <- CUs, L =/= undefined],
    case has_cpp_lang(Langs) of
        true ->
            cpp;
        false ->
            case has_c_lang(Langs) of
                true -> c;
                false -> unknown
            end
    end.

-spec has_cpp_lang([
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
    | undefined
    | {unknown, non_neg_integer()}
]) -> boolean().
has_cpp_lang(Langs) ->
    lists:any(fun is_cpp_lang/1, Langs).

-spec has_c_lang([
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
    | undefined
    | {unknown, non_neg_integer()}
]) -> boolean().
has_c_lang(Langs) ->
    lists:any(fun is_c_lang/1, Langs).

-spec is_cpp_lang(term()) -> boolean().
is_cpp_lang(cpp) -> true;
is_cpp_lang(cpp11) -> true;
is_cpp_lang(cpp14) -> true;
is_cpp_lang(_) -> false.

-spec is_c_lang(term()) -> boolean().
is_c_lang(c) -> true;
is_c_lang(c89) -> true;
is_c_lang(c99) -> true;
is_c_lang(c11) -> true;
is_c_lang(c17) -> true;
is_c_lang(_) -> false.

%% ---------------------------------------------------------------------------
%% Analyze helpers
%% ---------------------------------------------------------------------------

-spec analyze_rust(#elf{}) -> {ok, #{language => rust, info => term()}} | {error, term()}.
analyze_rust(Elf) ->
    case try_call(elf_lang_rust, parse, [Elf]) of
        {ok, {ok, Info}} ->
            {ok, #{language => rust, info => Info}};
        {ok, {error, Reason}} ->
            {error, Reason};
        {error, _} ->
            %% Module not available yet — return basic result.
            {ok, #{language => rust, info => undefined}}
    end.

-spec analyze_dwarf(language(), #elf{}) -> {ok, #{language => language(), info => term()}}.
analyze_dwarf(Lang, Elf) ->
    case elf_lang_dwarf:compilation_units(Elf) of
        {ok, CUs} ->
            {ok, #{language => Lang, info => CUs}};
        {error, _} ->
            {ok, #{language => Lang, info => []}}
    end.

%% ---------------------------------------------------------------------------
%% Internal helpers
%% ---------------------------------------------------------------------------

-spec has_section(binary(), #elf{}) -> boolean().
has_section(Name, Elf) ->
    case elf_parse:section(Name, Elf) of
        {ok, _} -> true;
        _ -> false
    end.

%% Try calling M:F(Args). Returns {ok, Result} or {error, not_loaded}.
try_call(M, F, A) ->
    try
        Result = erlang:apply(M, F, A),
        {ok, Result}
    catch
        error:undef -> {error, not_loaded}
    end.
