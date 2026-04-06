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

-module(elf_syscall).
-moduledoc """
High-level syscall extraction from parsed ELF binaries.

Combines the ELF parser, architecture-specific decoders, and the
syscall database to produce a complete syscall profile for a binary.
""".

-include("elf_parse.hrl").

-export([extract/1, numbers/1, names/1, categories/1]).

%% ---------------------------------------------------------------------------
%% API
%% ---------------------------------------------------------------------------

-spec extract(#elf{}) ->
    {ok, #{
        arch => x86_64 | aarch64,
        resolved => #{non_neg_integer() => binary()},
        unresolved_count => non_neg_integer(),
        sites => [#{addr => non_neg_integer(), syscall_nr => non_neg_integer() | unresolved}],
        categories => #{atom() => [binary()]}
    }}
    | {error, term()}.
extract(#elf{header = #elf_header{machine = Arch}} = Elf) when
    Arch =:= x86_64; Arch =:= aarch64
->
    case decoder_module(Arch) of
        {error, _} = Err ->
            Err;
        {ok, Mod} ->
            ExecShdrs = elf_parse:executable_sections(Elf),
            {AllNrs, TotalUnresolved, AllSites} =
                lists:foldl(
                    fun(Shdr, {NrsAcc, UnresAcc, SitesAcc}) ->
                        case elf_parse:section_data(Shdr, Elf) of
                            {ok, Data} ->
                                {Nrs, Unres} = Mod:extract_syscalls(Data),
                                Sites = build_sites(Mod, Data, Shdr),
                                {
                                    ordsets:union(NrsAcc, ordsets:from_list(Nrs)),
                                    UnresAcc + Unres,
                                    SitesAcc ++ Sites
                                };
                            _ ->
                                {NrsAcc, UnresAcc, SitesAcc}
                        end
                    end,
                    {ordsets:new(), 0, []},
                    ExecShdrs
                ),
            %% Callsite resolution: find syscall numbers passed to
            %% stub functions like Go's syscall.RawSyscall
            CallsiteNrs = resolve_callsite_syscalls(Elf, Arch, ExecShdrs),
            AllNrs2 = ordsets:union(AllNrs, ordsets:from_list(CallsiteNrs)),
            Resolved = lists:foldl(
                fun(Nr, Acc) ->
                    case elf_syscall_db:name(Arch, Nr) of
                        {ok, Name} -> Acc#{Nr => Name};
                        error -> Acc#{Nr => <<"unknown">>}
                    end
                end,
                #{},
                AllNrs2
            ),
            Cats = build_categories(maps:values(Resolved)),
            {ok, #{
                arch => Arch,
                resolved => Resolved,
                unresolved_count => TotalUnresolved,
                sites => AllSites,
                categories => Cats
            }}
    end;
extract(#elf{header = #elf_header{machine = _}}) ->
    {error, unsupported_arch}.

-spec numbers(#elf{}) -> {ok, ordsets:ordset(non_neg_integer())} | {error, term()}.
numbers(Elf) ->
    case extract(Elf) of
        {ok, #{resolved := Resolved}} ->
            {ok, ordsets:from_list(maps:keys(Resolved))};
        {error, _} = Err ->
            Err
    end.

-spec names(#elf{}) -> {ok, ordsets:ordset(binary())} | {error, term()}.
names(Elf) ->
    case extract(Elf) of
        {ok, #{resolved := Resolved}} ->
            {ok, ordsets:from_list(maps:values(Resolved))};
        {error, _} = Err ->
            Err
    end.

-spec categories(#elf{}) -> {ok, #{atom() => [binary()]}} | {error, term()}.
categories(Elf) ->
    case extract(Elf) of
        {ok, #{categories := Cats}} -> {ok, Cats};
        {error, _} = Err -> Err
    end.

%% ---------------------------------------------------------------------------
%% Internal
%% ---------------------------------------------------------------------------

-spec decoder_module(x86_64 | aarch64) ->
    {ok, elf_decode_x86_64 | elf_decode_aarch64} | {error, unsupported_arch}.
decoder_module(x86_64) ->
    check_module(elf_decode_x86_64);
decoder_module(aarch64) ->
    check_module(elf_decode_aarch64).

-spec check_module(elf_decode_x86_64 | elf_decode_aarch64) ->
    {ok, elf_decode_x86_64 | elf_decode_aarch64} | {error, unsupported_arch}.
check_module(Mod) ->
    case code:ensure_loaded(Mod) of
        {module, Mod} -> {ok, Mod};
        {error, _} -> {error, unsupported_arch}
    end.

-spec build_sites(module(), binary(), #elf_shdr{}) ->
    [#{addr => non_neg_integer(), syscall_nr => non_neg_integer() | unresolved}].
build_sites(Mod, Data, #elf_shdr{addr = BaseAddr}) ->
    Insns = Mod:decode_all(Data),
    SyscallType =
        case Mod of
            elf_decode_x86_64 -> syscall;
            elf_decode_aarch64 -> svc
        end,
    SyscallOffsets = [I || I <- Insns, element(4, I) =:= SyscallType],
    lists:map(
        fun(Insn) ->
            Off = element(2, Insn),
            Nr = Mod:resolve_syscall(Data, Off, Insns),
            #{addr => BaseAddr + Off, syscall_nr => Nr}
        end,
        SyscallOffsets
    ).

%% ---------------------------------------------------------------------------
%% Callsite-based syscall resolution
%% ---------------------------------------------------------------------------

%% For binaries that dispatch syscalls through shared stubs (e.g., Go's
%% syscall.RawSyscall), find the syscall number at each call site by
%% scanning backward from the CALL instruction for MOV RAX, imm32.
-spec resolve_callsite_syscalls(#elf{}, x86_64 | aarch64, [#elf_shdr{}]) ->
    [non_neg_integer()].
resolve_callsite_syscalls(Elf, x86_64, ExecShdrs) ->
    case find_syscall_stubs(Elf) of
        [] ->
            [];
        StubAddrs ->
            lists:usort(
                lists:flatmap(
                    fun(Shdr) ->
                        case elf_parse:section_data(Shdr, Elf) of
                            {ok, Data} ->
                                BaseAddr = Shdr#elf_shdr.addr,
                                resolve_calls_in_section(Data, BaseAddr, StubAddrs);
                            _ ->
                                []
                        end
                    end,
                    ExecShdrs
                )
            )
    end;
resolve_callsite_syscalls(_, _, _) ->
    [].

-spec find_syscall_stubs(#elf{}) -> [non_neg_integer()].
find_syscall_stubs(Elf) ->
    case elf_parse_symtab:functions(Elf) of
        {ok, Syms} ->
            [
                Sym#elf_sym.value
             || Sym <- Syms,
                Sym#elf_sym.size > 0,
                is_syscall_stub(Sym#elf_sym.name)
            ];
        _ ->
            []
    end.

-spec is_syscall_stub(binary()) -> boolean().
is_syscall_stub(Name) ->
    %% Match Go syscall dispatch functions:
    %%   syscall.RawSyscall, syscall.RawSyscall6,
    %%   syscall.Syscall, syscall.Syscall6,
    %%   internal/runtime/syscall.Syscall6
    binary:match(Name, <<"syscall.RawSyscall">>) =/= nomatch orelse
        binary:match(Name, <<"syscall.Syscall">>) =/= nomatch.

-spec resolve_calls_in_section(
    binary(),
    non_neg_integer(),
    [non_neg_integer()]
) ->
    [non_neg_integer()].
resolve_calls_in_section(Data, BaseAddr, StubAddrs) ->
    Insns = elf_decode_x86_64:decode_all(Data),
    Calls = elf_decode_x86_64:call_targets(Data, BaseAddr, Insns),
    StubCallOffsets = [
        Off
     || {Off, Target} <- Calls,
        lists:member(Target, StubAddrs)
    ],
    lists:filtermap(
        fun(CallOff) ->
            case elf_decode_x86_64:resolve_syscall(Data, CallOff, Insns) of
                unresolved -> false;
                Nr -> {true, Nr}
            end
        end,
        StubCallOffsets
    ).

-spec build_categories([binary()]) -> #{atom() => [binary()]}.
build_categories(Names) ->
    Unique = ordsets:from_list(Names),
    lists:foldl(
        fun(Name, Acc) ->
            Cat = elf_syscall_db:category(Name),
            Existing = maps:get(Cat, Acc, []),
            Acc#{Cat => ordsets:add_element(Name, Existing)}
        end,
        #{},
        Unique
    ).
