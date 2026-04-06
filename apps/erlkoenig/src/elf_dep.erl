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

-module(elf_dep).
-moduledoc """
Dependency analysis and anomaly detection for ELF binaries.

Combines language-specific dependency info with syscall analysis
to determine per-dependency capabilities and detect anomalies.

For Go binaries (primary target):
  - gopclntab gives function -> package mapping
  - Syscall extraction gives address -> syscall number mapping
  - Combining both: per-package syscall capabilities

For Rust: similar concept using crate info from symbols.
""".

-include("elf_parse.hrl").
-include("elf_lang_go.hrl").
-include("elf_lang_rust.hrl").

-export([
    deps/1,
    capabilities/1,
    anomalies/1,
    anomalies/2
]).

-export_type([capability/0]).

-type capability() :: network | filesystem | process | memory | ipc | signal | time | io | other.

%% ---------------------------------------------------------------------------
%% Public API
%% ---------------------------------------------------------------------------

-doc "Get all dependencies with their versions.".
-spec deps(#elf{}) ->
    {ok, [#{name => binary(), version => binary() | unknown, source => atom()}]}
    | {error, term()}.
deps(Elf) ->
    case elf_lang:detect(Elf) of
        go ->
            deps_go(Elf);
        rust ->
            deps_rust(Elf);
        _ ->
            {ok, []}
    end.

-doc "Get capabilities (syscall categories) per dependency/package.".
-spec capabilities(#elf{}) ->
    {ok, #{binary() => #{syscalls => [binary()], categories => [capability()]}}}
    | {error, term()}.
capabilities(Elf) ->
    case elf_lang:detect(Elf) of
        go ->
            capabilities_go(Elf);
        _ ->
            {error, unsupported_language}
    end.

-doc """
Detect anomalies using default expectations.
Returns a plain list (not {ok, _} | {error, _}) by design: an empty list
means no anomalies, so there is no error case to represent.
""".
-spec anomalies(#elf{}) ->
    [#{package => binary(), unexpected => [capability()], syscalls => [binary()]}].
anomalies(Elf) ->
    anomalies(Elf, default_expectations()).

-doc """
Detect anomalies: packages with unexpected capabilities.
Returns a plain list by design -- empty list = no anomalies found.
""".
-spec anomalies(#elf{}, #{binary() => [capability()]}) ->
    [#{package => binary(), unexpected => [capability()], syscalls => [binary()]}].
anomalies(Elf, Expected) ->
    case capabilities(Elf) of
        {ok, Caps} ->
            compute_anomalies(Caps, Expected);
        {error, _} ->
            []
    end.

%% ---------------------------------------------------------------------------
%% Go dependency extraction
%% ---------------------------------------------------------------------------

-spec deps_go(#elf{}) ->
    {ok, [#{name => binary(), version => binary() | unknown, source => atom()}]}
    | {error, term()}.
deps_go(Elf) ->
    case elf_lang_go:parse(Elf) of
        {ok, #go_info{deps = GoDeps}} ->
            Normalized = [
                #{
                    name => D#go_dep.path,
                    version => D#go_dep.version,
                    source => go_buildinfo
                }
             || D <- GoDeps
            ],
            {ok, Normalized};
        {error, Reason} ->
            {error, Reason}
    end.

%% ---------------------------------------------------------------------------
%% Rust dependency extraction
%% ---------------------------------------------------------------------------

-spec deps_rust(#elf{}) ->
    {ok, [#{name => binary(), version => binary() | unknown, source => atom()}]}
    | {error, term()}.
deps_rust(Elf) ->
    case elf_lang_rust:parse(Elf) of
        {ok, #rust_info{crates = Crates}} ->
            Normalized = [
                #{
                    name => C#rust_crate.name,
                    version => C#rust_crate.version,
                    source => C#rust_crate.source
                }
             || C <- Crates
            ],
            {ok, Normalized};
        {error, Reason} ->
            {error, Reason}
    end.

%% ---------------------------------------------------------------------------
%% Go capability analysis
%% ---------------------------------------------------------------------------

-spec capabilities_go(#elf{}) ->
    {ok, #{binary() => #{syscalls => [binary()], categories => [capability()]}}}
    | {error, term()}.
capabilities_go(Elf) ->
    maybe
        {ok, PkgMap} ?= elf_lang_go:function_package_map(Elf),
        {ok, #{sites := Sites, resolved := Resolved, arch := Arch}} ?= elf_syscall:extract(Elf),
        %% Build sorted function list for address range lookup
        AllFuncs = lists:sort(
            fun(#go_func{entry = A}, #go_func{entry = B}) -> A =< B end,
            lists:append(maps:values(PkgMap))
        ),
        %% Build function ranges: [{Entry, EndAddr, Package}]
        Ranges = build_func_ranges(AllFuncs),
        %% Map each syscall site to its package
        PkgSyscalls = assign_sites_to_packages(Sites, Ranges, Resolved, Arch),
        %% Build the result map
        Result = maps:map(
            fun(_Pkg, SyscallNames) ->
                UniqNames = lists:usort(SyscallNames),
                Cats = lists:usort([elf_syscall_db:category(N) || N <- UniqNames]),
                #{syscalls => UniqNames, categories => Cats}
            end,
            PkgSyscalls
        ),
        {ok, Result}
    end.

%% Build function address ranges.
%% Functions are sorted by entry. Each function's range is [entry_N, entry_{N+1}).
%% Last function gets a generous size estimate.
-spec build_func_ranges([#go_func{}]) ->
    [{non_neg_integer(), non_neg_integer(), binary()}].
build_func_ranges([]) ->
    [];
build_func_ranges(Funcs) ->
    build_func_ranges_1(Funcs).

-spec build_func_ranges_1([#go_func{}, ...]) ->
    [{non_neg_integer(), non_neg_integer(), binary()}, ...].
build_func_ranges_1([#go_func{entry = Entry, package = Pkg}]) ->
    %% Last function: estimate 4KB range
    [{Entry, Entry + 4096, Pkg}];
build_func_ranges_1([
    #go_func{entry = Entry, package = Pkg},
    #go_func{entry = NextEntry} = Next
    | Rest
]) ->
    [{Entry, NextEntry, Pkg} | build_func_ranges_1([Next | Rest])].

%% Assign each syscall site to its containing package.
-spec assign_sites_to_packages(
    [#{addr => non_neg_integer(), syscall_nr => non_neg_integer() | unresolved}],
    [{non_neg_integer(), non_neg_integer(), binary()}],
    #{non_neg_integer() => binary()},
    x86_64 | aarch64
) -> #{binary() => [binary()]}.
assign_sites_to_packages(Sites, Ranges, Resolved, _Arch) ->
    lists:foldl(
        fun
            (#{addr := Addr, syscall_nr := Nr}, Acc) when is_integer(Nr) ->
                SyscallName = maps:get(Nr, Resolved, <<"unknown">>),
                case find_package(Addr, Ranges) of
                    {ok, Pkg} ->
                        Existing = maps:get(Pkg, Acc, []),
                        Acc#{Pkg => [SyscallName | Existing]};
                    error ->
                        Acc
                end;
            (_, Acc) ->
                Acc
        end,
        #{},
        Sites
    ).

%% Binary search for the package containing an address.
-spec find_package(
    non_neg_integer(),
    [{non_neg_integer(), non_neg_integer(), binary()}]
) ->
    {ok, binary()} | error.
find_package(_Addr, []) ->
    error;
find_package(Addr, Ranges) ->
    find_package_bs(Addr, Ranges, 0, length(Ranges) - 1).

-spec find_package_bs(
    non_neg_integer(),
    [{non_neg_integer(), non_neg_integer(), binary()}],
    non_neg_integer(),
    integer()
) ->
    {ok, binary()} | error.
find_package_bs(_Addr, _Ranges, Lo, Hi) when Lo > Hi ->
    error;
find_package_bs(Addr, Ranges, Lo, Hi) ->
    Mid = (Lo + Hi) div 2,
    Nth = Mid + 1,
    case Nth >= 1 andalso Nth =< length(Ranges) of
        false ->
            error;
        true ->
            {Entry, EndAddr, Pkg} = lists:nth(Nth, Ranges),
            if
                Addr >= Entry, Addr < EndAddr ->
                    {ok, Pkg};
                Addr < Entry ->
                    find_package_bs(Addr, Ranges, Lo, Mid - 1);
                true ->
                    find_package_bs(Addr, Ranges, Mid + 1, Hi)
            end
    end.

%% ---------------------------------------------------------------------------
%% Anomaly detection
%% ---------------------------------------------------------------------------

-spec compute_anomalies(
    #{binary() => #{syscalls => [binary()], categories => [capability()]}},
    #{binary() => [capability()]}
) -> [#{package => binary(), unexpected => [capability()], syscalls => [binary()]}].
compute_anomalies(Caps, Expected) ->
    maps:fold(
        fun(Pkg, #{categories := ActualCats, syscalls := Syscalls}, Acc) ->
            ExpectedCats = resolve_expected(Pkg, Expected),
            Unexpected = [
                C
             || C <- ActualCats,
                not lists:member(C, ExpectedCats)
            ],
            case Unexpected of
                [] ->
                    Acc;
                _ ->
                    %% Find syscalls that belong to unexpected categories
                    UnexpectedSyscalls = [
                        S
                     || S <- Syscalls,
                        lists:member(
                            elf_syscall_db:category(S),
                            Unexpected
                        )
                    ],
                    [
                        #{
                            package => Pkg,
                            unexpected => lists:sort(Unexpected),
                            syscalls => lists:usort(UnexpectedSyscalls)
                        }
                        | Acc
                    ]
            end
        end,
        [],
        Caps
    ).

%% Resolve expected capabilities for a package.
%% First check exact match, then prefix match for default expectations.
-spec resolve_expected(binary(), #{binary() => [capability()]}) -> [capability()].
resolve_expected(Pkg, Expected) ->
    case maps:find(Pkg, Expected) of
        {ok, Cats} ->
            Cats;
        error ->
            %% Try prefix matching for Go stdlib
            resolve_expected_prefix(Pkg, Expected)
    end.

-spec resolve_expected_prefix(binary(), #{binary() => [capability()]}) -> [capability()].
resolve_expected_prefix(Pkg, Expected) ->
    %% Find the longest matching prefix key that ends with '/'
    Matches = maps:fold(
        fun(Key, Cats, Acc) ->
            KeySlash = <<Key/binary, "/">>,
            case binary:match(Pkg, KeySlash) of
                {0, _} -> [{byte_size(Key), Cats} | Acc];
                _ -> Acc
            end
        end,
        [],
        Expected
    ),
    case Matches of
        [] ->
            [];
        _ ->
            %% Pick the longest prefix match
            Sorted = lists:sort(fun({A, _}, {B, _}) -> A >= B end, Matches),
            {_, Cats} = hd(Sorted),
            Cats
    end.

%% ---------------------------------------------------------------------------
%% Default expectations for Go standard library
%% ---------------------------------------------------------------------------

-spec default_expectations() -> #{<<_:16, _:_*8>> => [capability(), ...]}.
default_expectations() ->
    #{
        %% Pure computation / formatting packages
        <<"encoding">> => [memory],
        <<"fmt">> => [memory],
        <<"strings">> => [memory],
        <<"bytes">> => [memory],
        <<"sort">> => [memory],
        <<"unicode">> => [memory],
        <<"strconv">> => [memory],
        <<"math">> => [memory],
        <<"hash">> => [memory],
        <<"regexp">> => [memory],
        <<"text">> => [memory],

        %% Network packages
        <<"net">> => [network, filesystem, memory, time, io, process, ipc, signal],
        <<"crypto/tls">> => [network, filesystem, memory, time, io, process],
        <<"crypto">> => [memory, process],

        %% I/O packages
        <<"os">> => [filesystem, memory, process, signal],
        <<"io">> => [filesystem, memory],
        <<"bufio">> => [filesystem, memory],
        <<"log">> => [filesystem, memory, time],

        %% Runtime / concurrency packages
        <<"runtime">> => [memory, process, signal, time, ipc],
        <<"sync">> => [memory, process, ipc],
        <<"reflect">> => [memory, process],
        <<"internal">> => [memory, process, signal, time, ipc, filesystem],
        <<"syscall">> => [network, filesystem, process, memory, ipc, signal, time, io, other],

        %% Main package gets all capabilities
        <<"main">> => [network, filesystem, process, memory, ipc, signal, time, io, other]
    }.
