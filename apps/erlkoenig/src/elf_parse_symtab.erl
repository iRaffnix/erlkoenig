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

-module(elf_parse_symtab).
-moduledoc """
ELF64 Symbol Table parser.

Parses .symtab sections from a parsed #elf{} record, resolving
symbol names from the associated string table (sh_link).
""".

-include("elf_parse.hrl").

-export([
    symbols/1,
    functions/1,
    lookup/2,
    at_address/2
]).

-export_type([
    sym_error/0
]).

-type sym_error() :: {error, no_symtab | not_found | truncated}.

-doc "Parse all symbols from the .symtab section.".
-spec symbols(#elf{}) -> {ok, [#elf_sym{}]} | {error, term()}.
symbols(Elf = #elf{}) ->
    case elf_parse:section(<<".symtab">>, Elf) of
        {error, not_found} ->
            {error, no_symtab};
        {ok, Shdr = #elf_shdr{link = StrtabIdx}} ->
            case elf_parse:section_data(Shdr, Elf) of
                {error, Reason} ->
                    {error, Reason};
                {ok, SymData} ->
                    case find_shdr_by_index(StrtabIdx, Elf#elf.shdrs) of
                        error ->
                            {error, no_strtab};
                        {ok, StrtabShdr} ->
                            case elf_parse:section_data(StrtabShdr, Elf) of
                                {error, Reason} ->
                                    {error, Reason};
                                {ok, StrData} ->
                                    Endian = Elf#elf.header#elf_header.endian,
                                    Syms = parse_syms(SymData, StrData, Endian),
                                    {ok, Syms}
                            end
                    end
            end
    end.

-doc "Return only STT_FUNC symbols.".
-spec functions(#elf{}) -> {ok, [#elf_sym{}]} | {error, term()}.
functions(Elf) ->
    case symbols(Elf) of
        {ok, Syms} ->
            {ok, [S || S = #elf_sym{type = func} <- Syms]};
        Error ->
            Error
    end.

-doc "Find a symbol by name.".
-spec lookup(#elf{}, binary()) -> {ok, #elf_sym{}} | error.
lookup(Elf, Name) when is_binary(Name) ->
    case symbols(Elf) of
        {ok, Syms} ->
            case [S || S = #elf_sym{name = N} <- Syms, N =:= Name] of
                [H | _] -> {ok, H};
                [] -> error
            end;
        _ ->
            error
    end.

-doc "Find a symbol that contains the given address (value <= addr < value+size).".
-spec at_address(#elf{}, non_neg_integer()) -> {ok, #elf_sym{}} | error.
at_address(Elf, Addr) when is_integer(Addr), Addr >= 0 ->
    case symbols(Elf) of
        {ok, Syms} ->
            find_at_addr(Addr, Syms);
        _ ->
            error
    end.

%% ---------------------------------------------------------------------------
%% Internal
%% ---------------------------------------------------------------------------

-spec find_shdr_by_index(non_neg_integer(), [#elf_shdr{}]) ->
    {ok, #elf_shdr{}} | error.
find_shdr_by_index(_Idx, []) ->
    error;
find_shdr_by_index(Idx, [S | _]) when S#elf_shdr.index =:= Idx ->
    {ok, S};
find_shdr_by_index(Idx, [_ | T]) ->
    find_shdr_by_index(Idx, T).

-spec find_at_addr(non_neg_integer(), [#elf_sym{}]) -> {ok, #elf_sym{}} | error.
find_at_addr(_Addr, []) ->
    error;
find_at_addr(Addr, [S = #elf_sym{value = V, size = Sz} | _]) when
    Sz > 0, Addr >= V, Addr < V + Sz
->
    {ok, S};
find_at_addr(Addr, [_ | T]) ->
    find_at_addr(Addr, T).

%% Parse all ELF64_SYM_SIZE-byte Elf64_Sym entries from raw symtab data.
-spec parse_syms(binary(), binary(), little | big) -> [#elf_sym{}].
parse_syms(SymData, StrData, Endian) ->
    parse_syms_1(SymData, StrData, Endian, []).

parse_syms_1(<<>>, _StrData, _Endian, Acc) ->
    lists:reverse(Acc);
parse_syms_1(
    <<StName:32/little, StInfo:8, _StOther:8, StShndx:16/little, StValue:64/little,
        StSize:64/little, Rest/binary>>,
    StrData,
    little,
    Acc
) ->
    Sym = make_sym(StName, StInfo, StShndx, StValue, StSize, StrData),
    parse_syms_1(Rest, StrData, little, [Sym | Acc]);
parse_syms_1(
    <<StName:32/big, StInfo:8, _StOther:8, StShndx:16/big, StValue:64/big, StSize:64/big,
        Rest/binary>>,
    StrData,
    big,
    Acc
) ->
    Sym = make_sym(StName, StInfo, StShndx, StValue, StSize, StrData),
    parse_syms_1(Rest, StrData, big, [Sym | Acc]);
parse_syms_1(_Short, _StrData, _Endian, Acc) ->
    %% Trailing bytes shorter than 24 — ignore.
    lists:reverse(Acc).

make_sym(StName, StInfo, StShndx, StValue, StSize, StrData) ->
    Bind = StInfo bsr 4,
    Type = StInfo band 16#0F,
    #elf_sym{
        name = read_strtab(StrData, StName),
        bind = decode_bind(Bind),
        type = decode_type(Type),
        shndx = decode_shndx(StShndx),
        value = StValue,
        size = StSize
    }.

-spec read_strtab(binary(), non_neg_integer()) -> binary().
read_strtab(Tab, Offset) when Offset < byte_size(Tab) ->
    <<_:Offset/binary, Rest/binary>> = Tab,
    case binary:match(Rest, <<0>>) of
        {Pos, 1} -> binary:part(Rest, 0, Pos);
        nomatch -> Rest
    end;
read_strtab(_, _) ->
    <<>>.

decode_bind(?STB_LOCAL) -> local;
decode_bind(?STB_GLOBAL) -> global;
decode_bind(?STB_WEAK) -> weak;
decode_bind(V) -> {unknown, V}.

decode_type(?STT_NOTYPE) -> notype;
decode_type(?STT_OBJECT) -> object;
decode_type(?STT_FUNC) -> func;
decode_type(?STT_SECTION) -> section;
decode_type(?STT_FILE) -> file;
decode_type(?STT_COMMON) -> common;
decode_type(?STT_TLS) -> tls;
decode_type(?STT_GNU_IFUNC) -> ifunc;
decode_type(V) -> {unknown, V}.

decode_shndx(?SHN_UNDEF) -> undefined;
decode_shndx(?SHN_ABS) -> absolute;
decode_shndx(?SHN_COMMON) -> common;
decode_shndx(V) -> V.
