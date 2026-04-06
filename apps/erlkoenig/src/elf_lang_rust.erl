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

-module(elf_lang_rust).
-moduledoc """
Rust binary analysis module.

Detects Rust binaries and extracts crate information from:
- .symtab: legacy (_ZN) and v0 (_R) mangled symbols
- .rodata: panic strings containing .cargo/registry paths
- .comment: rustc compiler version strings

Rust doesn't have dedicated sections like Go, so detection relies
on symbol mangling patterns and embedded string artifacts.
""".

-include("elf_parse.hrl").
-include("elf_lang_rust.hrl").

-export([
    is_rust/1,
    parse/1,
    crates/1
]).

-export_type([
    rust_info/0,
    rust_crate/0
]).

-type rust_info() :: #rust_info{}.
-type rust_crate() :: #rust_crate{}.

%% ---------------------------------------------------------------------------
%% Public API
%% ---------------------------------------------------------------------------

-spec is_rust(#elf{}) -> boolean().
is_rust(Elf) ->
    has_rust_symbols(Elf) orelse has_rust_comment(Elf).

-spec parse(#elf{}) -> {ok, #rust_info{}} | {error, term()}.
parse(Elf) ->
    case is_rust(Elf) of
        false ->
            {error, not_rust};
        true ->
            SymCrates = crates_from_symtab(Elf),
            PanicCrates = crates_from_panic_strings(Elf),
            Compiler = compiler_from_comment(Elf),
            AllCrates = dedup_crates(SymCrates ++ PanicCrates),
            {ok, #rust_info{crates = AllCrates, compiler = Compiler}}
    end.

-spec crates(#elf{}) -> {ok, [#rust_crate{}]} | {error, term()}.
crates(Elf) ->
    case parse(Elf) of
        {ok, #rust_info{crates = Crates}} -> {ok, Crates};
        Error -> Error
    end.

%% ---------------------------------------------------------------------------
%% Symbol-based detection and crate extraction
%% ---------------------------------------------------------------------------

-spec has_rust_symbols(#elf{}) -> boolean().
has_rust_symbols(Elf) ->
    case elf_parse_symtab:symbols(Elf) of
        {ok, Syms} ->
            lists:any(fun is_rust_symbol/1, Syms);
        _ ->
            false
    end.

-spec is_rust_symbol(#elf_sym{}) -> boolean().
is_rust_symbol(#elf_sym{name = <<"_ZN", _/binary>>}) -> true;
is_rust_symbol(#elf_sym{name = <<"_R", _/binary>>}) -> true;
is_rust_symbol(_) -> false.

-spec crates_from_symtab(#elf{}) -> [#rust_crate{}].
crates_from_symtab(Elf) ->
    case elf_parse_symtab:symbols(Elf) of
        {ok, Syms} ->
            RustSyms = [S || S <- Syms, is_rust_symbol(S)],
            Names = lists:filtermap(fun extract_crate_from_symbol/1, RustSyms),
            Unique = lists:usort(Names),
            [
                #rust_crate{name = N, version = unknown, source = symtab}
             || N <- Unique
            ];
        _ ->
            []
    end.

-spec extract_crate_from_symbol(#elf_sym{}) -> {true, binary()} | false.
extract_crate_from_symbol(#elf_sym{name = <<"_ZN", Rest/binary>>}) ->
    case demangle_legacy_first_segment(Rest) of
        {ok, Seg} -> {true, Seg};
        error -> false
    end;
extract_crate_from_symbol(#elf_sym{name = <<"_R", Rest/binary>>}) ->
    case demangle_v0_crate(Rest) of
        {ok, Crate} -> {true, Crate};
        error -> false
    end;
extract_crate_from_symbol(_) ->
    false.

%% Legacy Itanium C++ mangling used by older Rust.
%% Format: _ZN <len><chars> <len><chars> ... E
%% We extract the first segment (crate name).
demangle_legacy_first_segment(Bin) ->
    parse_length_prefixed_segment(Bin).

%% Parse a single length-prefixed segment: digits followed by that many chars.
parse_length_prefixed_segment(Bin) ->
    case parse_decimal(Bin, 0, false) of
        {ok, Len, Rest} when Len > 0, byte_size(Rest) >= Len ->
            <<Seg:Len/binary, _/binary>> = Rest,
            {ok, Seg};
        _ ->
            error
    end.

-spec parse_decimal(binary(), non_neg_integer(), boolean()) ->
    {ok, non_neg_integer(), binary()} | error.
parse_decimal(<<C, Rest/binary>>, Acc, _HasDigit) when C >= $0, C =< $9 ->
    parse_decimal(Rest, Acc * 10 + (C - $0), true);
parse_decimal(Rest, Acc, true) ->
    {ok, Acc, Rest};
parse_decimal(_, _, false) ->
    error.

%% Rust v0 mangling: _R followed by encoding.
%% Simplified: look for N<namespace>C<crate-disambiguator><ident> patterns.
%% The crate name is typically the first identifier after the prefix.
%% Common patterns: _RNvCs<hash>_<len><crate>... or _RNvNtCs<hash>_<len><crate>...
%% We scan for 'C' (crate root) followed by disambiguator and identifier.
demangle_v0_crate(Bin) ->
    find_crate_root(Bin).

%% Scan through the v0 mangled name looking for 'C' (crate root marker),
%% which is followed by a disambiguator (s<base62>_ or s_) and then
%% a length-prefixed identifier.
find_crate_root(<<>>) ->
    error;
find_crate_root(<<"C", Rest/binary>>) ->
    case skip_v0_disambiguator(Rest) of
        {ok, AfterDisambig} ->
            case parse_decimal(AfterDisambig, 0, false) of
                {ok, Len, IdentRest} when Len > 0, byte_size(IdentRest) >= Len ->
                    <<Crate:Len/binary, _/binary>> = IdentRest,
                    %% Validate: crate names are ASCII alphanumeric + underscore
                    case is_valid_crate_name(Crate) of
                        true -> {ok, Crate};
                        false -> find_crate_root(Rest)
                    end;
                _ ->
                    find_crate_root(Rest)
            end;
        error ->
            find_crate_root(Rest)
    end;
find_crate_root(<<_, Rest/binary>>) ->
    find_crate_root(Rest).

%% Skip v0 disambiguator: 's' followed by base62 digits and '_'.
%% A lone 's_' means disambiguator 0. Otherwise 's<base62chars>_'.
-spec skip_v0_disambiguator(binary()) -> {ok, binary()} | error.
skip_v0_disambiguator(<<"s", Rest/binary>>) ->
    skip_until_underscore(Rest);
skip_v0_disambiguator(_) ->
    error.

-spec skip_until_underscore(binary()) -> {ok, binary()} | error.
skip_until_underscore(<<>>) ->
    error;
skip_until_underscore(<<"_", Rest/binary>>) ->
    {ok, Rest};
skip_until_underscore(<<C, Rest/binary>>) when
    (C >= $0 andalso C =< $9);
    (C >= $a andalso C =< $z);
    (C >= $A andalso C =< $Z)
->
    skip_until_underscore(Rest);
skip_until_underscore(_) ->
    error.

is_valid_crate_name(<<>>) -> false;
is_valid_crate_name(Bin) -> is_valid_crate_name_1(Bin).

is_valid_crate_name_1(<<>>) ->
    true;
is_valid_crate_name_1(<<C, Rest/binary>>) when
    (C >= $a andalso C =< $z);
    (C >= $A andalso C =< $Z);
    (C >= $0 andalso C =< $9);
    C =:= $_
->
    is_valid_crate_name_1(Rest);
is_valid_crate_name_1(_) ->
    false.

%% ---------------------------------------------------------------------------
%% .rodata panic string scanning
%% ---------------------------------------------------------------------------

-spec crates_from_panic_strings(#elf{}) -> [#rust_crate{}].
crates_from_panic_strings(Elf) ->
    case elf_parse:section(<<".rodata">>, Elf) of
        {ok, Shdr} ->
            case elf_parse:section_data(Shdr, Elf) of
                {ok, Data} -> scan_cargo_paths(Data);
                _ -> []
            end;
        _ ->
            []
    end.

%% Scan binary data for .cargo/registry/src/ paths and extract crate-version.
%% Pattern: .cargo/registry/src/<registry>/<crate>-<version>/
-define(CARGO_MARKER, <<".cargo/registry/src/">>).
-define(CARGO_MARKER_LEN, 20).

-spec scan_cargo_paths(binary()) -> [#rust_crate{}].
scan_cargo_paths(Data) ->
    Matches = binary:matches(Data, ?CARGO_MARKER),
    Crates = lists:filtermap(
        fun({Pos, Len}) ->
            AfterMarker = Pos + Len,
            Rest = binary:part(
                Data,
                AfterMarker,
                byte_size(Data) - AfterMarker
            ),
            extract_crate_from_cargo_path(Rest)
        end,
        Matches
    ),
    dedup_crates(Crates).

%% After ".cargo/registry/src/" we expect:
%%   <registry-name>/<crate-name>-<version>/
%% e.g. "index.crates.io-6f17d22bba15001f/serde-1.0.197/src/de/mod.rs"
-spec extract_crate_from_cargo_path(binary()) -> {true, #rust_crate{}} | false.
extract_crate_from_cargo_path(Rest) ->
    %% Skip past the registry directory (up to first '/')
    case binary:match(Rest, <<"/">>) of
        {SlashPos, 1} ->
            AfterRegistry = binary:part(
                Rest,
                SlashPos + 1,
                byte_size(Rest) - SlashPos - 1
            ),
            %% Now extract crate-version up to the next '/'
            case binary:match(AfterRegistry, <<"/">>) of
                {SlashPos2, 1} ->
                    CrateVer = binary:part(AfterRegistry, 0, SlashPos2),
                    parse_crate_version(CrateVer);
                nomatch ->
                    false
            end;
        nomatch ->
            false
    end.

%% Split "crate-name-1.2.3" into {crate-name, 1.2.3}.
%% The version starts at the last '-' followed by a digit.
-spec parse_crate_version(binary()) -> {true, #rust_crate{}} | false.
parse_crate_version(CrateVer) ->
    case find_version_split(CrateVer) of
        {ok, Name, Version} ->
            {true, #rust_crate{
                name = Name,
                version = Version,
                source = panic_strings
            }};
        error ->
            false
    end.

%% Find the last '-' that is followed by a digit — that splits name from version.
-spec find_version_split(binary()) -> {ok, binary(), binary()} | error.
find_version_split(Bin) ->
    Dashes = binary:matches(Bin, <<"-">>),
    find_version_split_1(Bin, lists:reverse(Dashes)).

find_version_split_1(_Bin, []) ->
    error;
find_version_split_1(Bin, [{Pos, 1} | Rest]) ->
    case Pos + 1 < byte_size(Bin) of
        true ->
            <<_:Pos/binary, "-", Next:8, _/binary>> = Bin,
            case Next >= $0 andalso Next =< $9 of
                true ->
                    Name = binary:part(Bin, 0, Pos),
                    Version = binary:part(
                        Bin,
                        Pos + 1,
                        byte_size(Bin) - Pos - 1
                    ),
                    {ok, Name, Version};
                false ->
                    find_version_split_1(Bin, Rest)
            end;
        false ->
            find_version_split_1(Bin, Rest)
    end.

%% ---------------------------------------------------------------------------
%% .comment section — rustc version
%% ---------------------------------------------------------------------------

-spec has_rust_comment(#elf{}) -> boolean().
has_rust_comment(Elf) ->
    case compiler_from_comment(Elf) of
        unknown -> false;
        _ -> true
    end.

-spec compiler_from_comment(#elf{}) -> binary() | unknown.
compiler_from_comment(Elf) ->
    case elf_parse:section(<<".comment">>, Elf) of
        {ok, Shdr} ->
            case elf_parse:section_data(Shdr, Elf) of
                {ok, Data} -> find_rustc_version(Data);
                _ -> unknown
            end;
        _ ->
            unknown
    end.

%% Scan .comment for "rustc version X.Y.Z" or just "rustc X.Y.Z".
-spec find_rustc_version(binary()) -> binary() | unknown.
find_rustc_version(Data) ->
    case binary:match(Data, <<"rustc">>) of
        {Pos, Len} ->
            Start = Pos + Len,
            Rest = binary:part(Data, Start, byte_size(Data) - Start),
            extract_rustc_line(Rest);
        nomatch ->
            unknown
    end.

%% Extract the rustc version line: skip whitespace/"version ", read until NUL/newline.
-spec extract_rustc_line(binary()) -> binary() | unknown.
extract_rustc_line(<<" version ", Rest/binary>>) ->
    take_until_terminator(Rest);
extract_rustc_line(<<" ", Rest/binary>>) ->
    take_until_terminator(Rest);
extract_rustc_line(_) ->
    unknown.

-spec take_until_terminator(binary()) -> binary() | unknown.
take_until_terminator(Bin) ->
    take_until_terminator(Bin, 0).

take_until_terminator(Bin, Pos) when Pos >= byte_size(Bin) ->
    case Pos > 0 of
        true -> binary:part(Bin, 0, Pos);
        false -> unknown
    end;
take_until_terminator(Bin, Pos) ->
    <<_:Pos/binary, C:8, _/binary>> = Bin,
    case C of
        0 -> version_or_unknown(Bin, Pos);
        %% newline
        10 -> version_or_unknown(Bin, Pos);
        _ -> take_until_terminator(Bin, Pos + 1)
    end.

version_or_unknown(_Bin, 0) -> unknown;
version_or_unknown(Bin, Pos) -> binary:part(Bin, 0, Pos).

%% ---------------------------------------------------------------------------
%% Deduplication
%% ---------------------------------------------------------------------------

%% Deduplicate crates by name, preferring entries with a known version
%% and preferring panic_strings source (has version) over symtab.
-spec dedup_crates([#rust_crate{}]) -> [#rust_crate{}].
dedup_crates(Crates) ->
    Map = lists:foldl(
        fun(C = #rust_crate{name = N}, Acc) ->
            case maps:find(N, Acc) of
                {ok, Existing} ->
                    maps:put(N, pick_better(Existing, C), Acc);
                error ->
                    maps:put(N, C, Acc)
            end
        end,
        #{},
        Crates
    ),
    lists:sort(
        fun(#rust_crate{name = A}, #rust_crate{name = B}) ->
            A =< B
        end,
        maps:values(Map)
    ).

-spec pick_better(#rust_crate{}, #rust_crate{}) -> #rust_crate{}.
pick_better(#rust_crate{version = unknown} = _Old, New) -> New;
pick_better(Old, _New) -> Old.
