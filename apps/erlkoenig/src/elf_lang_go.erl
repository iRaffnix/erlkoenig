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

-module(elf_lang_go).
-moduledoc """
Go binary analysis module.

Parses Go-specific data structures from ELF binaries:
- .go.buildinfo section (version, module path, dependencies, build settings)
- .gopclntab section (function names, entry addresses, packages)

Both sections survive stripping and are present in all Go binaries
compiled with Go 1.13+.
""".

-include("elf_parse.hrl").
-include("elf_lang_go.hrl").

-export([
    parse/1,
    functions/1,
    deps/1,
    is_go/1,
    function_package_map/1
]).

-export_type([
    go_info/0,
    go_func/0,
    go_dep/0
]).

-type go_info() :: #go_info{}.
-type go_func() :: #go_func{}.
-type go_dep() :: #go_dep{}.

%% .go.buildinfo magic
-define(BUILDINFO_MAGIC, <<16#FF, " Go buildinf:">>).

%% gopclntab magic values (stored as little-endian uint32 in binary)

%% Go 1.20+
-define(GOPCLNTAB_MAGIC_120, <<16#F1, 16#FF, 16#FF, 16#FF>>).
%% Go 1.18-1.19
-define(GOPCLNTAB_MAGIC_118, <<16#F0, 16#FF, 16#FF, 16#FF>>).
%% Go 1.16-1.17
-define(GOPCLNTAB_MAGIC_116, <<16#FA, 16#FF, 16#FF, 16#FF>>).

%% ---------------------------------------------------------------------------
%% Public API
%% ---------------------------------------------------------------------------

-spec is_go(#elf{}) -> boolean().
is_go(Elf) ->
    has_buildinfo(Elf) orelse has_gopclntab(Elf).

-spec parse(#elf{}) -> {ok, #go_info{}} | {error, term()}.
parse(Elf) ->
    case is_go(Elf) of
        false ->
            {error, not_go};
        true ->
            BuildInfo =
                case parse_buildinfo(Elf) of
                    {ok, BI} ->
                        BI;
                    {error, _} ->
                        #{
                            version => <<>>,
                            main_module => undefined,
                            mod_version => undefined,
                            deps => [],
                            build_settings => []
                        }
                end,
            Funcs =
                case parse_gopclntab(Elf) of
                    {ok, Fs} -> Fs;
                    {error, _} -> []
                end,
            Version = maps:get(version, BuildInfo),
            {ok, #go_info{
                version = Version,
                main_module = maps:get(main_module, BuildInfo),
                mod_version = maps:get(mod_version, BuildInfo),
                deps = maps:get(deps, BuildInfo),
                functions = Funcs,
                build_settings = maps:get(build_settings, BuildInfo),
                go_version_raw = Version
            }}
    end.

-spec functions(#elf{}) -> {ok, [#go_func{}]} | {error, term()}.
functions(Elf) ->
    case parse_gopclntab(Elf) of
        {ok, Funcs} -> {ok, Funcs};
        Error -> Error
    end.

-spec deps(#elf{}) -> {ok, [#go_dep{}]} | {error, term()}.
deps(Elf) ->
    case parse_buildinfo(Elf) of
        {ok, #{deps := Deps}} -> {ok, Deps};
        {error, _} = Error -> Error
    end.

-spec function_package_map(#elf{}) -> {ok, #{binary() => [#go_func{}]}} | {error, term()}.
function_package_map(Elf) ->
    case functions(Elf) of
        {ok, Funcs} ->
            Map = lists:foldl(
                fun(#go_func{package = Pkg} = F, Acc) ->
                    maps:update_with(Pkg, fun(Existing) -> Existing ++ [F] end, [F], Acc)
                end,
                #{},
                Funcs
            ),
            {ok, Map};
        Error ->
            Error
    end.

%% ---------------------------------------------------------------------------
%% .go.buildinfo parsing
%% ---------------------------------------------------------------------------

-spec has_buildinfo(#elf{}) -> boolean().
has_buildinfo(Elf) ->
    case elf_parse:section(<<".go.buildinfo">>, Elf) of
        {ok, _} -> true;
        _ -> false
    end.

-spec parse_buildinfo(#elf{}) -> {ok, map()} | {error, term()}.
parse_buildinfo(Elf) ->
    case elf_parse:section(<<".go.buildinfo">>, Elf) of
        {ok, Shdr} ->
            case elf_parse:section_data(Shdr, Elf) of
                {ok, Data} -> decode_buildinfo(Data, Elf);
                Error -> Error
            end;
        Error ->
            Error
    end.

-spec decode_buildinfo(binary(), #elf{}) -> {ok, map()} | {error, term()}.
decode_buildinfo(<<Magic:14/binary, PtrSize:8, Flags:8, Rest/binary>>, Elf) when
    Magic =:= ?BUILDINFO_MAGIC, (PtrSize =:= 4 orelse PtrSize =:= 8)
->
    InlineStrings = (Flags band 2) =/= 0,
    case InlineStrings of
        true ->
            %% Newer Go (>=1.18): varint-prefixed strings after 32-byte header
            %% Skip remaining header bytes to get past 32-byte mark

            %% Already consumed 16 bytes (14 magic + 1 ptr + 1 flags)
            SkipBytes = 32 - 16,
            case Rest of
                <<_Skip:SkipBytes/binary, StringData/binary>> ->
                    decode_buildinfo_inline(StringData);
                _ ->
                    {error, truncated_buildinfo}
            end;
        false ->
            %% Older Go: pointers to version and module strings
            _Endian =
                case Flags band 1 of
                    0 -> little;
                    1 -> big
                end,
            decode_buildinfo_ptrs(Rest, PtrSize, _Endian, Elf)
    end;
decode_buildinfo(_, _) ->
    {error, bad_buildinfo_magic}.

decode_buildinfo_inline(Data) ->
    case decode_varint_string(Data) of
        {ok, Version, Rest1} ->
            case decode_varint_string(Rest1) of
                {ok, ModInfo, _Rest2} ->
                    {Mod, ModVer, Deps, BuildSettings} = parse_mod_info(ModInfo),
                    {ok, #{
                        version => Version,
                        main_module => Mod,
                        mod_version => ModVer,
                        deps => Deps,
                        build_settings => BuildSettings
                    }};
                {error, _} ->
                    %% No module info, just version
                    {ok, #{
                        version => Version,
                        main_module => undefined,
                        mod_version => undefined,
                        deps => [],
                        build_settings => []
                    }}
            end;
        {error, _} = Error ->
            Error
    end.

-spec decode_buildinfo_ptrs(binary(), 4 | 8, little | big, #elf{}) ->
    {ok, map()} | {error, term()}.
decode_buildinfo_ptrs(Data, PtrSize, Endian, Elf) ->
    PtrBits = PtrSize * 8,
    case Data of
        <<VerPtr:PtrBits/little, ModPtr:PtrBits/little, _/binary>> when Endian =:= little ->
            decode_buildinfo_from_ptrs(VerPtr, ModPtr, PtrSize, Endian, Elf);
        <<VerPtr:PtrBits/big, ModPtr:PtrBits/big, _/binary>> when Endian =:= big ->
            decode_buildinfo_from_ptrs(VerPtr, ModPtr, PtrSize, Endian, Elf);
        _ ->
            {error, truncated_buildinfo}
    end.

-spec decode_buildinfo_from_ptrs(
    non_neg_integer(),
    non_neg_integer(),
    4 | 8,
    little | big,
    #elf{}
) ->
    {ok, map()} | {error, term()}.
decode_buildinfo_from_ptrs(VerPtr, ModPtr, PtrSize, Endian, Elf) ->
    case read_go_string(VerPtr, PtrSize, Endian, Elf) of
        {ok, Version} ->
            case read_go_string(ModPtr, PtrSize, Endian, Elf) of
                {ok, ModInfo} ->
                    {Mod, ModVer, Deps, BuildSettings} = parse_mod_info(ModInfo),
                    {ok, #{
                        version => Version,
                        main_module => Mod,
                        mod_version => ModVer,
                        deps => Deps,
                        build_settings => BuildSettings
                    }};
                {error, _} ->
                    {ok, #{
                        version => Version,
                        main_module => undefined,
                        mod_version => undefined,
                        deps => [],
                        build_settings => []
                    }}
            end;
        {error, _} = Error ->
            Error
    end.

%% Read a Go string (pointer, length) from a virtual address
-spec read_go_string(non_neg_integer(), 4 | 8, little | big, #elf{}) ->
    {ok, binary()} | {error, term()}.
read_go_string(Vaddr, PtrSize, Endian, Elf) ->
    PtrBits = PtrSize * 8,
    case elf_parse:vaddr_to_offset(Vaddr, Elf) of
        {ok, Off} ->
            Bin = Elf#elf.bin,
            RequiredBytes = Off + PtrSize * 2,
            case byte_size(Bin) >= RequiredBytes of
                true ->
                    case Endian of
                        little ->
                            <<_:Off/binary, DataPtr:PtrBits/little, Len:PtrBits/little, _/binary>> =
                                Bin,
                            read_bytes_at_vaddr(DataPtr, Len, Elf);
                        big ->
                            <<_:Off/binary, DataPtr:PtrBits/big, Len:PtrBits/big, _/binary>> = Bin,
                            read_bytes_at_vaddr(DataPtr, Len, Elf)
                    end;
                false ->
                    {error, truncated_buildinfo}
            end;
        Error ->
            Error
    end.

-spec read_bytes_at_vaddr(non_neg_integer(), non_neg_integer(), #elf{}) ->
    {ok, binary()} | {error, term()}.
read_bytes_at_vaddr(Vaddr, Len, Elf) ->
    case elf_parse:vaddr_to_offset(Vaddr, Elf) of
        {ok, Off} ->
            Bin = Elf#elf.bin,
            case byte_size(Bin) >= Off + Len of
                true -> {ok, binary:part(Bin, Off, Len)};
                false -> {error, truncated}
            end;
        Error ->
            Error
    end.

%% ---------------------------------------------------------------------------
%% Module info parsing
%% ---------------------------------------------------------------------------

-spec parse_mod_info(binary()) ->
    {binary() | undefined, binary() | undefined, [#go_dep{}], [{binary(), binary()}]}.
parse_mod_info(<<>>) ->
    {undefined, undefined, [], []};
parse_mod_info(Info) ->
    Lines = binary:split(Info, <<"\n">>, [global, trim_all]),
    parse_mod_lines(Lines, undefined, undefined, [], []).

-spec parse_mod_lines(
    [binary()],
    binary() | undefined,
    binary() | undefined,
    [#go_dep{}],
    [{binary(), binary()}]
) ->
    {binary() | undefined, binary() | undefined, [#go_dep{}], [{binary(), binary()}]}.
parse_mod_lines([], Mod, ModVer, Deps, Build) ->
    {Mod, ModVer, lists:reverse(Deps), lists:reverse(Build)};
parse_mod_lines([Line | Rest], Mod, ModVer, Deps, Build) ->
    case binary:split(Line, <<"\t">>, [global]) of
        [<<"path">>, Path | _] ->
            parse_mod_lines(Rest, Path, ModVer, Deps, Build);
        [<<"mod">>, ModPath, Ver | _] ->
            parse_mod_lines(Rest, ModPath, Ver, Deps, Build);
        [<<"dep">>, Path, Ver, Hash | _] ->
            Dep = #go_dep{path = Path, version = Ver, hash = Hash},
            parse_mod_lines(Rest, Mod, ModVer, [Dep | Deps], Build);
        [<<"dep">>, Path, Ver] ->
            Dep = #go_dep{path = Path, version = Ver, hash = <<>>},
            parse_mod_lines(Rest, Mod, ModVer, [Dep | Deps], Build);
        [<<"build">>, Setting | _] ->
            case binary:split(Setting, <<"=">>) of
                [Key, Val] ->
                    parse_mod_lines(Rest, Mod, ModVer, Deps, [{Key, Val} | Build]);
                _ ->
                    parse_mod_lines(Rest, Mod, ModVer, Deps, Build)
            end;
        _ ->
            parse_mod_lines(Rest, Mod, ModVer, Deps, Build)
    end.

%% ---------------------------------------------------------------------------
%% Varint encoding/decoding
%% ---------------------------------------------------------------------------

decode_varint(Bin) ->
    decode_varint(Bin, 0, 0).

decode_varint(<<>>, _Shift, _Acc) ->
    {error, truncated_varint};
decode_varint(<<Byte:8, Rest/binary>>, Shift, Acc) ->
    Value = Acc bor ((Byte band 16#7F) bsl Shift),
    case Byte band 16#80 of
        0 -> {ok, Value, Rest};
        _ -> decode_varint(Rest, Shift + 7, Value)
    end.

decode_varint_string(Data) ->
    case decode_varint(Data) of
        {ok, Len, Rest} when byte_size(Rest) >= Len ->
            <<Str:Len/binary, Remaining/binary>> = Rest,
            {ok, Str, Remaining};
        {ok, _Len, _Rest} ->
            {error, truncated_string};
        Error ->
            Error
    end.

%% ---------------------------------------------------------------------------
%% .gopclntab parsing
%% ---------------------------------------------------------------------------

-spec has_gopclntab(#elf{}) -> boolean().
has_gopclntab(Elf) ->
    case elf_parse:section(<<".gopclntab">>, Elf) of
        {ok, _} -> true;
        _ -> false
    end.

-spec parse_gopclntab(#elf{}) -> {ok, [#go_func{}]} | {error, term()}.
parse_gopclntab(Elf) ->
    case elf_parse:section(<<".gopclntab">>, Elf) of
        {ok, Shdr} ->
            case elf_parse:section_data(Shdr, Elf) of
                {ok, Data} -> decode_gopclntab(Data);
                Error -> Error
            end;
        Error ->
            Error
    end.

decode_gopclntab(<<Magic:4/binary, _Pad:2/binary, _MinLC:8, PtrSize:8, Rest/binary>> = Tab) when
    (Magic =:= ?GOPCLNTAB_MAGIC_120 orelse
        Magic =:= ?GOPCLNTAB_MAGIC_118 orelse
        Magic =:= ?GOPCLNTAB_MAGIC_116),
    (PtrSize =:= 4 orelse PtrSize =:= 8)
->
    GoVer =
        case Magic of
            ?GOPCLNTAB_MAGIC_120 -> '1.20';
            ?GOPCLNTAB_MAGIC_118 -> '1.18';
            ?GOPCLNTAB_MAGIC_116 -> '1.16'
        end,
    PtrBits = PtrSize * 8,
    case GoVer of
        V when V =:= '1.20'; V =:= '1.18' ->
            %% Header fields after magic+pad+minLC+ptrSize (8 bytes consumed)
            case Rest of
                <<Nfunc:PtrBits/little, Nfiles:PtrBits/little, TextStart:PtrBits/little,
                    FuncnameOff:PtrBits/little, _CutabOff:PtrBits/little,
                    _FiletabOff:PtrBits/little, _PctabOff:PtrBits/little, PcDataOff:PtrBits/little,
                    FuncTabData/binary>> ->
                    _ = Nfiles,
                    parse_functab(
                        Tab,
                        FuncTabData,
                        Nfunc,
                        TextStart,
                        FuncnameOff,
                        PcDataOff
                    );
                _ ->
                    {error, truncated_gopclntab}
            end;
        '1.16' ->
            %% Go 1.16-1.17: slightly different header layout
            %% Same structure but no textStart field
            case Rest of
                <<Nfunc:PtrBits/little, Nfiles:PtrBits/little, FuncnameOff:PtrBits/little,
                    _CutabOff:PtrBits/little, _FiletabOff:PtrBits/little, _PctabOff:PtrBits/little,
                    PcDataOff:PtrBits/little, FuncTabData/binary>> ->
                    _ = Nfiles,
                    parse_functab(
                        Tab,
                        FuncTabData,
                        Nfunc,
                        0,
                        FuncnameOff,
                        PcDataOff
                    );
                _ ->
                    {error, truncated_gopclntab}
            end
    end;
decode_gopclntab(_) ->
    {error, bad_gopclntab_magic}.

parse_functab(Tab, FuncTabData, Nfunc, TextStart, FuncnameOff, PcDataOff) ->
    Funcs = parse_functab_entries(
        Tab,
        FuncTabData,
        Nfunc,
        TextStart,
        FuncnameOff,
        PcDataOff,
        []
    ),
    {ok, Funcs}.

parse_functab_entries(_Tab, _Data, 0, _TextStart, _FuncnameOff, _PcDataOff, Acc) ->
    lists:reverse(Acc);
parse_functab_entries(
    Tab,
    <<FuncOff:32/little, FuncDataOff:32/little, Rest/binary>>,
    N,
    TextStart,
    FuncnameOff,
    PcDataOff,
    Acc
) ->
    case resolve_func(Tab, FuncOff, FuncDataOff, TextStart, FuncnameOff, PcDataOff) of
        {ok, Func} ->
            parse_functab_entries(
                Tab,
                Rest,
                N - 1,
                TextStart,
                FuncnameOff,
                PcDataOff,
                [Func | Acc]
            );
        {error, _} ->
            parse_functab_entries(
                Tab,
                Rest,
                N - 1,
                TextStart,
                FuncnameOff,
                PcDataOff,
                Acc
            )
    end;
parse_functab_entries(_Tab, _Data, _N, _TextStart, _FuncnameOff, _PcDataOff, Acc) ->
    lists:reverse(Acc).

resolve_func(Tab, FuncOff, FuncDataOff, TextStart, FuncnameOff, PcDataOff) ->
    %% Function metadata is at PcDataOff + FuncDataOff within Tab
    MetaOff = PcDataOff + FuncDataOff,
    case byte_size(Tab) >= MetaOff + 8 of
        true ->
            <<_:MetaOff/binary, _EntryOff:32/little, NameOff:32/little, _/binary>> = Tab,
            %% Function name is at FuncnameOff + NameOff within Tab
            NameStart = FuncnameOff + NameOff,
            case NameStart < byte_size(Tab) of
                true ->
                    <<_:NameStart/binary, NameRest/binary>> = Tab,
                    Name = read_cstring(NameRest),
                    Entry = TextStart + FuncOff,
                    Pkg = extract_package(Name),
                    {ok, #go_func{name = Name, entry = Entry, package = Pkg}};
                false ->
                    {error, name_out_of_bounds}
            end;
        false ->
            {error, funcdata_out_of_bounds}
    end.

-spec read_cstring(binary()) -> binary().
read_cstring(Bin) ->
    case binary:match(Bin, <<0>>) of
        {Pos, 1} -> binary:part(Bin, 0, Pos);
        nomatch -> Bin
    end.

%% Extract Go package from a fully qualified function name.
%% e.g. "github.com/user/pkg.Function" → "github.com/user/pkg"
%%      "main.init" → "main"
%%      "runtime.goexit" → "runtime"
-spec extract_package(binary()) -> binary().
extract_package(Name) ->
    %% Find the last '/' then the first '.' after it
    case binary:matches(Name, <<"/">>) of
        [] ->
            %% No slash: package is everything before the first dot
            case binary:match(Name, <<".">>) of
                {Pos, 1} -> binary:part(Name, 0, Pos);
                nomatch -> Name
            end;
        Matches ->
            %% Has slashes: find the last slash, then the first dot after it
            {LastSlash, _} = lists:last(Matches),
            After = binary:part(Name, LastSlash + 1, byte_size(Name) - LastSlash - 1),
            case binary:match(After, <<".">>) of
                {Pos, 1} ->
                    binary:part(Name, 0, LastSlash + 1 + Pos);
                nomatch ->
                    Name
            end
    end.
