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

-module(erlkoenig_elf).
-moduledoc """
Public facade for erlkoenig_elf -- the only module users need.

Delegates to internal modules: elf_parse, elf_syscall, elf_seccomp,
elf_lang, elf_lang_go, elf_lang_rust, elf_patch.
""".

-include("elf_parse.hrl").
-include("elf_seccomp.hrl").
-include("elf_lang_go.hrl").
-include("elf_lang_rust.hrl").

%% === Parsing ===
-export([parse/1]).

%% === High-Level Analysis ===
-export([analyze/1]).

%% === Syscalls ===
-export([syscalls/1, syscall_names/1]).

%% === Seccomp ===
-export([seccomp_profile/1, seccomp_json/1, seccomp_bpf/1]).

%% === Dependencies ===
-export([deps/1, dep_capabilities/1, dep_anomalies/1, dep_anomalies/2]).

%% === Patching ===
-export([patch/3, patch_at/4]).

%% === Language ===
-export([language/1, go_info/1, rust_info/1]).

%% ---------------------------------------------------------------------------
%% Parsing
%% ---------------------------------------------------------------------------

-spec parse(file:name_all() | binary()) -> {ok, #elf{}} | {error, term()}.
parse(Path) when is_list(Path) ->
    elf_parse:from_file(Path);
parse(Path) when is_binary(Path), byte_size(Path) > 64 ->
    case Path of
        <<16#7F, "ELF", _/binary>> -> elf_parse:from_binary(Path);
        _ -> elf_parse:from_file(binary_to_list(Path))
    end;
parse(Path) when is_binary(Path) ->
    elf_parse:from_file(binary_to_list(Path)).

%% ---------------------------------------------------------------------------
%% High-Level Analysis
%% ---------------------------------------------------------------------------

-spec analyze(#elf{}) -> {ok, map()}.
analyze(#elf{} = Elf) ->
    Header = Elf#elf.header,
    TextSize = text_size(Elf),
    SyscallInfo = safe_syscalls(Elf),
    LangInfo = safe_lang_analyze(Elf),
    {ok, #{
        arch => Header#elf_header.machine,
        type => Header#elf_header.type,
        is_static => elf_parse:is_static(Elf),
        is_pie => elf_parse:is_pie(Elf),
        has_debug => elf_parse:has_debug_info(Elf),
        language => elf_lang:detect(Elf),
        entry_point => Header#elf_header.entry,
        sections => [S#elf_shdr.name || S <- Elf#elf.shdrs],
        text_size => TextSize,
        total_size => byte_size(Elf#elf.bin),
        syscalls => SyscallInfo,
        language_info => LangInfo
    }}.

%% ---------------------------------------------------------------------------
%% Syscalls
%% ---------------------------------------------------------------------------

-spec syscalls(#elf{}) -> {ok, map()} | {error, term()}.
syscalls(Elf) ->
    elf_syscall:extract(Elf).

-spec syscall_names(#elf{}) -> {ok, [binary()]} | {error, term()}.
syscall_names(Elf) ->
    case elf_syscall:names(Elf) of
        {ok, Names} -> {ok, ordsets:to_list(Names)};
        {error, _} = Err -> Err
    end.

%% ---------------------------------------------------------------------------
%% Seccomp
%% ---------------------------------------------------------------------------

-spec seccomp_profile(#elf{}) -> {ok, #seccomp_profile{}} | {error, term()}.
seccomp_profile(Elf) ->
    elf_seccomp:from_binary(Elf).

-spec seccomp_json(#elf{}) -> {ok, iodata()} | {error, term()}.
seccomp_json(Elf) ->
    case elf_seccomp:from_binary(Elf) of
        {ok, Profile} -> {ok, elf_seccomp:to_json(Profile)};
        {error, _} = Err -> Err
    end.

-spec seccomp_bpf(#elf{}) -> {ok, binary()} | {error, term()}.
seccomp_bpf(Elf) ->
    case elf_seccomp:from_binary(Elf) of
        {ok, Profile} -> {ok, elf_seccomp:to_bpf(Profile)};
        {error, _} = Err -> Err
    end.

%% ---------------------------------------------------------------------------
%% Dependencies
%% ---------------------------------------------------------------------------

-spec deps(#elf{}) -> {ok, [term()]} | {error, term()}.
deps(Elf) ->
    case elf_lang:detect(Elf) of
        go ->
            case elf_lang_go:deps(Elf) of
                {ok, Deps} -> {ok, Deps};
                {error, _} = Err -> Err
            end;
        rust ->
            case try_call(elf_lang_rust, crates, [Elf]) of
                {ok, {ok, Crates}} -> {ok, Crates};
                {ok, {error, Reason}} -> {error, Reason};
                {error, _} -> {ok, []}
            end;
        _ ->
            {ok, []}
    end.

-spec dep_capabilities(#elf{}) -> {ok, map()} | {error, term()}.
dep_capabilities(Elf) ->
    case deps(Elf) of
        {ok, DepList} ->
            Cats =
                case syscalls(Elf) of
                    {ok, #{categories := C}} -> C;
                    {error, _} -> #{}
                end,
            %% Build a map of dep -> categories it touches
            %% This is a heuristic based on available data
            CapMap = build_dep_capabilities(DepList, Cats),
            {ok, CapMap};
        {error, _} = Err ->
            Err
    end.

-spec dep_anomalies(#elf{}) -> [map()].
dep_anomalies(Elf) ->
    dep_anomalies(Elf, #{}).

-spec dep_anomalies(#elf{}, map()) -> [map()].
dep_anomalies(Elf, Expected) ->
    case dep_capabilities(Elf) of
        {ok, CapMap} ->
            find_anomalies(CapMap, Expected);
        {error, _} ->
            []
    end.

%% ---------------------------------------------------------------------------
%% Patching
%% ---------------------------------------------------------------------------

patch(Path, FuncName, Strategy) ->
    elf_patch:patch_function(Path, FuncName, Strategy).

patch_at(Path, Addr, Size, Strategy) ->
    elf_patch:patch_function_at(Path, Addr, Size, Strategy).

%% ---------------------------------------------------------------------------
%% Language
%% ---------------------------------------------------------------------------

-spec language(#elf{}) -> elf_lang:language().
language(Elf) ->
    elf_lang:detect(Elf).

-spec go_info(#elf{}) -> {ok, #go_info{}} | {error, not_go | term()}.
go_info(Elf) ->
    elf_lang_go:parse(Elf).

-spec rust_info(#elf{}) -> {ok, #rust_info{}} | {error, not_rust | term()}.
rust_info(Elf) ->
    elf_lang_rust:parse(Elf).

%% ---------------------------------------------------------------------------
%% Internal helpers
%% ---------------------------------------------------------------------------

-spec text_size(#elf{}) -> non_neg_integer().
text_size(Elf) ->
    case elf_parse:section(<<".text">>, Elf) of
        {ok, #elf_shdr{size = Sz}} -> Sz;
        _ -> 0
    end.

-spec safe_syscalls(#elf{}) -> map() | {error, term()}.
safe_syscalls(Elf) ->
    try
        case elf_syscall:extract(Elf) of
            {ok, Info} -> Info;
            {error, Reason} -> {error, Reason}
        end
    catch
        _:Reason2 -> {error, Reason2}
    end.

-spec safe_lang_analyze(#elf{}) -> map() | {error, term()}.
safe_lang_analyze(Elf) ->
    try
        case elf_lang:analyze(Elf) of
            {ok, Info} -> Info;
            {error, Reason} -> {error, Reason}
        end
    catch
        _:Reason2 -> {error, Reason2}
    end.

-spec build_dep_capabilities([term()], #{atom() => [term()]}) -> map().
build_dep_capabilities(DepList, Cats) ->
    AllCats = maps:keys(Cats),
    lists:foldl(
        fun(Dep, Acc) ->
            Name = dep_name(Dep),
            Acc#{Name => AllCats}
        end,
        #{},
        DepList
    ).

-spec dep_name(term()) -> binary().
dep_name(Dep) when is_map(Dep) ->
    maps:get(name, Dep, maps:get(path, Dep, <<"unknown">>));
dep_name(Dep) when is_tuple(Dep) ->
    %% Handle #go_dep{} and #rust_crate{} records
    element(2, Dep);
dep_name(Dep) when is_binary(Dep) ->
    Dep;
dep_name(_) ->
    <<"unknown">>.

-spec find_anomalies(map(), map()) -> [map()].
find_anomalies(CapMap, Expected) ->
    maps:fold(
        fun(Dep, ActualCats, Acc) ->
            case maps:find(Dep, Expected) of
                {ok, ExpectedCats} ->
                    Unexpected = [
                        C
                     || C <- ActualCats,
                        not lists:member(C, ExpectedCats)
                    ],
                    case Unexpected of
                        [] ->
                            Acc;
                        _ ->
                            [
                                #{
                                    dep => Dep,
                                    unexpected_capabilities => Unexpected
                                }
                                | Acc
                            ]
                    end;
                error ->
                    %% No expectations defined: flag if it has network capabilities
                    case lists:member(network, ActualCats) of
                        true ->
                            [
                                #{
                                    dep => Dep,
                                    level => warn,
                                    reason => unexpected_network
                                }
                                | Acc
                            ];
                        false ->
                            Acc
                    end
            end
        end,
        [],
        CapMap
    ).

%% Try calling M:F(Args). Returns {ok, Result} or {error, not_loaded}.
try_call(M, F, A) ->
    try
        Result = erlang:apply(M, F, A),
        {ok, Result}
    catch
        error:undef -> {error, not_loaded}
    end.
