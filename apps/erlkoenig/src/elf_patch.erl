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

-module(elf_patch).
-moduledoc """
Binary patching module -- conservative, in-place function neutralization.

Patches ELF binaries to neutralize functions by making them return
immediately. No code insertion, no size changes, no metadata modification.
The file size stays exactly the same after patching.

Supported architectures: x86_64 and aarch64.
Supported strategies: ret (return immediately), ret_zero (return 0),
ret_error (return -1).
""".

-include("elf_parse.hrl").

-export([
    patch_function/3,
    patch_function_at/4,
    verify_patch/1,
    list_patches/2
]).

-export_type([
    patch_strategy/0
]).

-type patch_strategy() :: ret | ret_zero | ret_error.

%% ---------------------------------------------------------------------------
%% Public API
%% ---------------------------------------------------------------------------

-doc "Patch a function by name (looks up in symtab).".
-spec patch_function(file:filename(), binary(), patch_strategy()) ->
    {ok, #{
        function => binary(),
        addr => non_neg_integer(),
        size => non_neg_integer(),
        strategy => patch_strategy(),
        backup => file:filename()
    }}
    | {error, term()}.
patch_function(Path, FuncName, Strategy) ->
    maybe
        {ok, Elf} ?= elf_parse:from_file(Path),
        {ok, Sym} ?=
            case elf_parse_symtab:lookup(Elf, FuncName) of
                error -> {error, {symbol_not_found, FuncName}};
                {ok, #elf_sym{type = func} = S} -> {ok, S};
                {ok, #elf_sym{type = Type}} -> {error, {not_a_function, Type}}
            end,
        #elf_sym{value = Addr, size = Size} = Sym,
        {ok, Backup} ?= do_patch(Path, Elf, Addr, Size, Strategy),
        {ok, #{
            function => FuncName,
            addr => Addr,
            size => Size,
            strategy => Strategy,
            backup => Backup
        }}
    end.

-doc "Patch at a specific address + size (for stripped binaries).".
-spec patch_function_at(
    file:filename(),
    non_neg_integer(),
    non_neg_integer(),
    patch_strategy()
) ->
    {ok, map()} | {error, term()}.
patch_function_at(Path, Addr, Size, Strategy) ->
    maybe
        {ok, Elf} ?= elf_parse:from_file(Path),
        {ok, Backup} ?= do_patch(Path, Elf, Addr, Size, Strategy),
        {ok, #{
            addr => Addr,
            size => Size,
            strategy => Strategy,
            backup => Backup
        }}
    end.

-doc "Verify a patched binary is still valid ELF.".
-spec verify_patch(file:filename()) -> ok | {error, term()}.
verify_patch(Path) ->
    case elf_parse:from_file(Path) of
        {ok, #elf{}} ->
            ok;
        {error, Reason} ->
            {error, Reason}
    end.

-doc "Compare original and patched, list what changed.".
-spec list_patches(file:filename(), file:filename()) ->
    {ok, [
        #{
            offset => non_neg_integer(),
            original => binary(),
            patched => binary()
        }
    ]}
    | {error, term()}.
list_patches(OrigPath, PatchedPath) ->
    case {file:read_file(OrigPath), file:read_file(PatchedPath)} of
        {{ok, Orig}, {ok, Patched}} ->
            case byte_size(Orig) =:= byte_size(Patched) of
                false ->
                    {error, size_mismatch};
                true ->
                    {ok, find_diffs(Orig, Patched, 0, [])}
            end;
        {{error, Reason}, _} ->
            {error, {file, Reason}};
        {_, {error, Reason}} ->
            {error, {file, Reason}}
    end.

%% ---------------------------------------------------------------------------
%% Internal — patching logic
%% ---------------------------------------------------------------------------

-spec do_patch(
    file:filename(),
    #elf{},
    non_neg_integer(),
    non_neg_integer(),
    patch_strategy()
) ->
    {ok, file:filename()} | {error, term()}.
do_patch(Path, Elf, Addr, Size, Strategy) ->
    Arch = Elf#elf.header#elf_header.machine,
    maybe
        {ok, PatchBin} ?= patch_bytes(Arch, Strategy),
        PatchSize = byte_size(PatchBin),
        ok ?=
            case Size < PatchSize of
                true -> {error, {function_too_small, Size, PatchSize}};
                false -> ok
            end,
        {ok, FileOffset} ?=
            case elf_parse:vaddr_to_offset(Addr, Elf) of
                {error, not_mapped} -> {error, {address_not_mapped, Addr}};
                {ok, _} = Ok -> Ok
            end,
        PadBin = padding(Arch, Size - PatchSize),
        FullPatch = <<PatchBin/binary, PadBin/binary>>,
        apply_patch(Path, FileOffset, FullPatch)
    end.

-spec patch_bytes(atom(), patch_strategy()) ->
    {ok, binary()} | {error, {unsupported_architecture, atom()}}.
%% x86_64
patch_bytes(x86_64, ret) ->
    {ok, <<16#C3>>};
patch_bytes(x86_64, ret_zero) ->
    {ok, <<16#31, 16#C0, 16#C3>>};
patch_bytes(x86_64, ret_error) ->
    {ok, <<16#48, 16#C7, 16#C0, 16#FF, 16#FF, 16#FF, 16#FF, 16#C3>>};
%% aarch64
patch_bytes(aarch64, ret) ->
    {ok, <<16#C0, 16#03, 16#5F, 16#D6>>};
patch_bytes(aarch64, ret_zero) ->
    {ok, <<16#E0, 16#03, 16#1F, 16#AA, 16#C0, 16#03, 16#5F, 16#D6>>};
patch_bytes(aarch64, ret_error) ->
    {ok, <<16#00, 16#00, 16#80, 16#92, 16#C0, 16#03, 16#5F, 16#D6>>};
%% unsupported
patch_bytes(Arch, _) ->
    {error, {unsupported_architecture, Arch}}.

-spec padding(atom(), non_neg_integer()) -> binary().
padding(x86_64, N) ->
    binary:copy(<<16#CC>>, N);
padding(aarch64, N) ->
    %% aarch64 instructions are 4-byte aligned; pad with BRK #0
    Brk = <<16#00, 16#00, 16#20, 16#D4>>,
    FullInsns = N div 4,
    Remainder = N rem 4,
    Insns = binary:copy(Brk, FullInsns),
    Trail = binary:copy(<<16#00>>, Remainder),
    <<Insns/binary, Trail/binary>>;
padding(_, N) ->
    binary:copy(<<16#00>>, N).

-spec apply_patch(file:filename(), non_neg_integer(), binary()) ->
    {ok, file:filename()} | {error, term()}.
apply_patch(Path, Offset, PatchBin) ->
    BackupPath = Path ++ ".orig",
    maybe
        ok ?=
            case filelib:is_regular(BackupPath) of
                true -> {error, {backup_exists, BackupPath}};
                false -> ok
            end,
        {ok, Bin} ?=
            case file:read_file(Path) of
                {ok, _} = Ok -> Ok;
                {error, Reason1} -> {error, {file, Reason1}}
            end,
        PatchLen = byte_size(PatchBin),
        ok ?=
            case Offset + PatchLen =< byte_size(Bin) of
                false -> {error, {patch_out_of_bounds, Offset, PatchLen, byte_size(Bin)}};
                true -> ok
            end,
        <<Before:Offset/binary, _:PatchLen/binary, After/binary>> = Bin,
        Patched = <<Before/binary, PatchBin/binary, After/binary>>,
        ok ?=
            case file:write_file(BackupPath, Bin) of
                ok -> ok;
                {error, Reason2} -> {error, {file, Reason2}}
            end,
        case file:write_file(Path, Patched) of
            ok -> {ok, BackupPath};
            {error, Reason3} -> {error, {file, Reason3}}
        end
    end.

%% ---------------------------------------------------------------------------
%% Internal — diff comparison
%% ---------------------------------------------------------------------------

%% No spec — internal function.
find_diffs(<<>>, <<>>, _Pos, Acc) ->
    lists:reverse(Acc);
find_diffs(<<B:8, RestA/binary>>, <<B:8, RestB/binary>>, Pos, Acc) ->
    %% Same byte — skip
    find_diffs(RestA, RestB, Pos + 1, Acc);
find_diffs(BinA, BinB, Pos, Acc) ->
    %% Found a difference — collect contiguous differing bytes
    {Len, _} = collect_diff(BinA, BinB, 0),
    OrigBytes = binary:part(BinA, 0, Len),
    PatchBytes = binary:part(BinB, 0, Len),
    RestA = binary:part(BinA, Len, byte_size(BinA) - Len),
    RestB = binary:part(BinB, Len, byte_size(BinB) - Len),
    Entry = #{offset => Pos, original => OrigBytes, patched => PatchBytes},
    find_diffs(RestA, RestB, Pos + Len, [Entry | Acc]).

-spec collect_diff(binary(), binary(), non_neg_integer()) ->
    {non_neg_integer(), ok}.
collect_diff(<<>>, <<>>, N) ->
    {N, ok};
collect_diff(<<B:8, _/binary>>, <<B:8, _/binary>>, N) ->
    {N, ok};
collect_diff(<<_:8, RestA/binary>>, <<_:8, RestB/binary>>, N) ->
    collect_diff(RestA, RestB, N + 1);
collect_diff(_, _, N) ->
    {N, ok}.
