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

-module(elf_seccomp).
-moduledoc """
Seccomp-BPF profile generator from ELF syscall analysis.

Generates seccomp filters in three formats:
- Erlang term (for erlkoenig integration)
- JSON (Docker/OCI compatible)
- Classic BPF bytecode (for seccomp(SECCOMP_SET_MODE_FILTER))

For large syscall sets (>20), uses binary search tree BPF
instead of linear comparison chain for O(log n) performance.
""".

-include("elf_parse.hrl").
-include("elf_seccomp.hrl").

-export([
    from_binary/1,
    from_syscalls/2,
    to_json/1,
    to_bpf/1,
    to_erlang/1,
    analyze_to_json/1
]).

%% BPF constants
-define(BPF_LD, 16#00).
-define(BPF_W, 16#00).
-define(BPF_ABS, 16#20).
-define(BPF_JMP, 16#05).
-define(BPF_JEQ, 16#10).
-define(BPF_JGE, 16#30).
-define(BPF_K, 16#00).
-define(BPF_RET, 16#06).

-define(SECCOMP_RET_KILL_PROCESS, 16#80000000).
-define(SECCOMP_RET_ALLOW, 16#7FFF0000).

%% Threshold for switching from linear to binary search tree
-define(BST_THRESHOLD, 20).

%% ---------------------------------------------------------------------------
%% API
%% ---------------------------------------------------------------------------

-spec from_binary(#elf{}) -> {ok, #seccomp_profile{}} | {error, term()}.
from_binary(#elf{} = Elf) ->
    case elf_syscall:extract(Elf) of
        {ok, #{arch := Arch, resolved := Resolved, unresolved_count := Unresolved}} ->
            Nrs = ordsets:from_list(maps:keys(Resolved)),
            Names = ordsets:from_list([
                N
             || N <- maps:values(Resolved),
                N =/= <<"unknown">>
            ]),
            {ok, #seccomp_profile{
                arch = Arch,
                default_action = kill_process,
                syscalls = Nrs,
                names = Names,
                unresolved = Unresolved
            }};
        {error, _} = Err ->
            Err
    end.

-spec from_syscalls(x86_64 | aarch64, ordsets:ordset(non_neg_integer())) ->
    #seccomp_profile{}.
from_syscalls(Arch, Nrs) when Arch =:= x86_64; Arch =:= aarch64 ->
    Sorted = ordsets:from_list(Nrs),
    Names = ordsets:from_list(
        lists:filtermap(
            fun(Nr) ->
                case elf_syscall_db:name(Arch, Nr) of
                    {ok, Name} -> {true, Name};
                    error -> false
                end
            end,
            Sorted
        )
    ),
    Unresolved = length(Sorted) - length(Names),
    #seccomp_profile{
        arch = Arch,
        default_action = kill_process,
        syscalls = Sorted,
        names = Names,
        unresolved = Unresolved
    }.

-spec to_json(#seccomp_profile{}) -> <<_:32, _:_*8>> | [[any()] | byte()].
to_json(#seccomp_profile{arch = Arch, default_action = Action, names = Names}) ->
    ArchStr = arch_to_scmp(Arch),
    ActionStr = action_to_scmp(Action),
    %% Sort names for deterministic output
    SortedNames = lists:sort(Names),
    json_encode([
        {<<"defaultAction">>, ActionStr},
        {<<"architectures">>, [ArchStr]},
        {<<"syscalls">>, [
            [
                {<<"names">>, SortedNames},
                {<<"action">>, <<"SCMP_ACT_ALLOW">>}
            ]
        ]}
    ]).

-spec to_bpf(#seccomp_profile{}) -> binary().
to_bpf(#seccomp_profile{syscalls = Syscalls}) ->
    Sorted = lists:sort(ordsets:to_list(Syscalls)),
    N = length(Sorted),
    case N of
        0 ->
            %% Just load + deny + allow (allow is unreachable but keeps structure)
            iolist_to_binary([
                bpf_stmt(?BPF_LD bor ?BPF_W bor ?BPF_ABS, 0),
                bpf_stmt(?BPF_RET bor ?BPF_K, ?SECCOMP_RET_KILL_PROCESS),
                bpf_stmt(?BPF_RET bor ?BPF_K, ?SECCOMP_RET_ALLOW)
            ]);
        _ when N =< ?BST_THRESHOLD ->
            bpf_linear(Sorted);
        _ ->
            bpf_bst(Sorted)
    end.

-spec to_erlang(#seccomp_profile{}) ->
    #{
        arch := x86_64 | aarch64,
        default_action := kill_process | errno,
        syscalls := [non_neg_integer()],
        names := [binary()],
        unresolved := non_neg_integer()
    }.
to_erlang(#seccomp_profile{
    arch = Arch,
    default_action = Action,
    syscalls = Syscalls,
    names = Names,
    unresolved = Unresolved
}) ->
    #{
        arch => Arch,
        default_action => Action,
        syscalls => Syscalls,
        names => Names,
        unresolved => Unresolved
    }.

-spec analyze_to_json(#elf{}) -> {ok, iodata()} | {error, term()}.
analyze_to_json(#elf{} = Elf) ->
    case from_binary(Elf) of
        {ok, Profile} -> {ok, to_json(Profile)};
        {error, _} = Err -> Err
    end.

%% ---------------------------------------------------------------------------
%% BPF generation — linear chain (N <= 20)
%% ---------------------------------------------------------------------------

bpf_linear(Sorted) ->
    N = length(Sorted),
    %% Layout: 1 LD + N JEQ + 1 DENY + 1 ALLOW
    %% The ALLOW is at offset N+1 from the first JEQ (index 1).
    %% For JEQ at position i (0-based among JEQs), jump-to-allow = N - i.
    %% Jump-false = 0 (fall through to next JEQ or DENY).
    Load = bpf_stmt(?BPF_LD bor ?BPF_W bor ?BPF_ABS, 0),
    Jumps = lists:map(
        fun({Idx, Nr}) ->
            JtAllow = N - Idx,
            bpf_jump(?BPF_JMP bor ?BPF_JEQ bor ?BPF_K, Nr, JtAllow, 0)
        end,
        lists:zip(lists:seq(0, N - 1), Sorted)
    ),
    Deny = bpf_stmt(?BPF_RET bor ?BPF_K, ?SECCOMP_RET_KILL_PROCESS),
    Allow = bpf_stmt(?BPF_RET bor ?BPF_K, ?SECCOMP_RET_ALLOW),
    iolist_to_binary([Load | Jumps] ++ [Deny, Allow]).

%% ---------------------------------------------------------------------------
%% BPF generation — binary search tree (N > 20)
%% ---------------------------------------------------------------------------

%% Strategy: Build a list of BPF instructions using a binary search tree.
%% Each node uses BPF_JGE to split: if nr >= median, jump right; else fall left.
%% Leaves are JEQ checks that jump to ALLOW or fall through to DENY.
%%
%% We first build the instruction list, then patch jumps.
%% Instructions are accumulated in reverse, then reversed at the end.
%%
%% For simplicity: generate instructions with symbolic labels, then resolve.

bpf_bst(Sorted) ->
    Load = bpf_stmt(?BPF_LD bor ?BPF_W bor ?BPF_ABS, 0),
    %% Build tree instructions
    TreeInsns = bst_build(Sorted),
    Deny = bpf_stmt(?BPF_RET bor ?BPF_K, ?SECCOMP_RET_KILL_PROCESS),
    Allow = bpf_stmt(?BPF_RET bor ?BPF_K, ?SECCOMP_RET_ALLOW),
    AllInsns = [Load | TreeInsns] ++ [Deny, Allow],
    TotalLen = length(AllInsns),
    % 0-based index of ALLOW instruction
    AllowIdx = TotalLen - 1,
    %% Patch symbolic jumps
    Patched = patch_insns(AllInsns, AllowIdx),
    iolist_to_binary(Patched).

%% Build BST instructions. Returns a flat list of instruction tuples.
%% Each instruction is either:
%%   {stmt, Code, K}                  — no jumps
%%   {jump, Code, K, Jt, Jf}         — with symbolic targets
%%   {jeq_allow, Nr}                  — JEQ that jumps to ALLOW on match
%%
%% We use a recursive approach: for a range of syscalls,
%% pick median, emit JGE to split, recurse on each half.
%% Leaf nodes (1-2 elements) emit JEQ instructions.

bst_build(Sorted) ->
    %% We build instructions as a flat list.
    %% Each JGE needs to know how many instructions the left subtree has
    %% so it can jump over them.
    bst_build_range(Sorted).

bst_build_range([]) ->
    [];
bst_build_range([Nr]) ->
    %% Leaf: single JEQ, jump to allow on match, fall through to next on miss
    [{jeq_allow, Nr}];
bst_build_range([Nr1, Nr2]) ->
    %% Two elements: two JEQ checks
    [{jeq_allow, Nr1}, {jeq_allow, Nr2}];
bst_build_range(Sorted) ->
    N = length(Sorted),
    %% 1-based median position
    Mid = (N + 1) div 2,
    {Left, Right} = lists:split(Mid, Sorted),
    %% The pivot is the first element of Right (or last of Left for >=)
    Pivot = hd(Right),
    LeftInsns = bst_build_range(Left),
    RightInsns = bst_build_range(Right),
    LeftLen = length(LeftInsns),
    %% JGE Pivot: if nr >= Pivot, jump over left subtree to right subtree
    %% jt = LeftLen (skip left), jf = 0 (fall through to left)
    [{jge, Pivot, LeftLen, 0}] ++ LeftInsns ++ RightInsns.

%% Patch symbolic instructions into raw BPF bytes.
%% AllowIdx is the 0-based index of the ALLOW instruction.
patch_insns(Insns, AllowIdx) ->
    patch_insns(Insns, 0, AllowIdx).

patch_insns([], _Pos, _AllowIdx) ->
    [];
patch_insns([{jeq_allow, Nr} | Rest], Pos, AllowIdx) ->
    %% Jump to ALLOW = AllowIdx - Pos - 1 (relative from next insn)
    JtAllow = AllowIdx - Pos - 1,
    [
        bpf_jump(?BPF_JMP bor ?BPF_JEQ bor ?BPF_K, Nr, JtAllow, 0)
        | patch_insns(Rest, Pos + 1, AllowIdx)
    ];
patch_insns([{jge, Pivot, Jt, Jf} | Rest], Pos, AllowIdx) ->
    [
        bpf_jump(?BPF_JMP bor ?BPF_JGE bor ?BPF_K, Pivot, Jt, Jf)
        | patch_insns(Rest, Pos + 1, AllowIdx)
    ];
patch_insns([Bin | Rest], Pos, AllowIdx) when is_binary(Bin) ->
    [Bin | patch_insns(Rest, Pos + 1, AllowIdx)].

%% ---------------------------------------------------------------------------
%% BPF instruction encoding
%% ---------------------------------------------------------------------------

%% No spec — internal function.
bpf_stmt(Code, K) ->
    <<Code:16/little, 0:8, 0:8, K:32/little>>.

-spec bpf_jump(
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer()
) -> binary().
bpf_jump(Code, K, Jt, Jf) ->
    <<Code:16/little, Jt:8, Jf:8, K:32/little>>.

%% ---------------------------------------------------------------------------
%% Architecture / action mapping
%% ---------------------------------------------------------------------------

arch_to_scmp(x86_64) -> <<"SCMP_ARCH_X86_64">>;
arch_to_scmp(aarch64) -> <<"SCMP_ARCH_AARCH64">>.

action_to_scmp(kill_process) -> <<"SCMP_ACT_KILL_PROCESS">>;
action_to_scmp(errno) -> <<"SCMP_ACT_ERRNO">>.

%% ---------------------------------------------------------------------------
%% Minimal JSON encoder (no external deps)
%% ---------------------------------------------------------------------------

-spec json_encode(term()) -> iodata().
json_encode(B) when is_binary(B) ->
    [$", json_escape(B), $"];
json_encode(N) when is_integer(N) ->
    integer_to_list(N);
json_encode(true) ->
    <<"true">>;
json_encode(false) ->
    <<"false">>;
json_encode(null) ->
    <<"null">>;
json_encode(L) when is_list(L) ->
    case is_proplist(L) of
        true -> json_encode_object(L);
        false -> json_encode_array(L)
    end;
json_encode(M) when is_map(M) ->
    json_encode_object(maps:to_list(M)).

is_proplist([{K, _} | Rest]) when is_binary(K); is_atom(K) ->
    is_proplist(Rest);
is_proplist([]) ->
    true;
is_proplist(_) ->
    false.

json_encode_object(Props) ->
    Pairs = lists:map(
        fun({K, V}) ->
            Key =
                if
                    is_atom(K) -> atom_to_binary(K, utf8);
                    is_binary(K) -> K
                end,
            [json_encode(Key), $:, json_encode(V)]
        end,
        Props
    ),
    [${, lists:join($,, Pairs), $}].

json_encode_array(Items) ->
    Encoded = lists:map(fun json_encode/1, Items),
    [$[, lists:join($,, Encoded), $]].

json_escape(Bin) ->
    json_escape(Bin, []).

json_escape(<<>>, Acc) ->
    lists:reverse(Acc);
json_escape(<<$\\, Rest/binary>>, Acc) ->
    json_escape(Rest, [<<"\\\\"/utf8>> | Acc]);
json_escape(<<$", Rest/binary>>, Acc) ->
    json_escape(Rest, [<<"\\\""/utf8>> | Acc]);
json_escape(<<$\n, Rest/binary>>, Acc) ->
    json_escape(Rest, [<<"\\n">> | Acc]);
json_escape(<<$\r, Rest/binary>>, Acc) ->
    json_escape(Rest, [<<"\\r">> | Acc]);
json_escape(<<$\t, Rest/binary>>, Acc) ->
    json_escape(Rest, [<<"\\t">> | Acc]);
json_escape(<<C, Rest/binary>>, Acc) ->
    json_escape(Rest, [C | Acc]).
