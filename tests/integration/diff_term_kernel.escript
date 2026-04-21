#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% Tier 2.1 differential verifier.
%%
%% Takes a single DSL .exs stack file, compiles it, loads it, then
%% diffs the declared nft primitives against the actual kernel
%% state.  Reports every missing or empty primitive.
%%
%% Usage:
%%   sudo ./diff_term_kernel.escript <path/to/stack.exs> [parent]
%%
%% The optional second argument is the dummy-parent name to patch
%% the stack's `ipvlan` references to; defaults to `ek_diff`.
%%
%% Exit code 0 = kernel matches term, 1 = diffs found.
-mode(compile).

main(Args) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    case string:trim(os:cmd("id -u")) of
        "0" -> ok;
        _   -> io:format("ERROR: must run as root~n"), halt(1)
    end,

    {ExampleIn, Parent} = case Args of
        [E] -> {E, "ek_diff"};
        [E, P] -> {E, P};
        _ -> io:format("usage: diff_term_kernel.escript <stack.exs> [parent]~n"),
             halt(2)
    end,

    test_helper:boot(),
    logger:set_primary_config(level, error),

    Root = test_helper:project_root(),
    %% Accept absolute paths as-is; relative paths resolve against
    %% the project root (so the caller can say `examples/tutorial/03.exs`).
    Example = case filename:pathtype(ExampleIn) of
        absolute -> ExampleIn;
        _        -> filename:join(Root, ExampleIn)
    end,
    TermFile = "/tmp/diff_term_kernel.term",
    DemoBin = test_helper:demo("echo_server"),

    tutorial_helper:cleanup_all(),
    tutorial_helper:cleanup_dummy(list_to_binary(Parent)),
    tutorial_helper:ensure_dummy(list_to_binary(Parent),
                                  "10.99.0.1/24"),

    io:format("~n=== differential verifier: ~s ===~n", [Example]),

    ok = tutorial_helper:compile_dsl(Root, Example, TermFile),
    ok = patch_and_load(TermFile, iolist_to_binary(DemoBin),
                         list_to_binary(Parent)),

    timer:sleep(1500),
    {ok, Config} = erlkoenig_config:parse(TermFile),
    Tables = maps:get(nft_tables, Config, []),

    KernelDump = os:cmd("nft -a list ruleset 2>&1"),
    Diffs = lists:flatmap(fun(T) -> diff_table(T, KernelDump) end, Tables),

    tutorial_helper:cleanup_all(),
    tutorial_helper:cleanup_dummy(list_to_binary(Parent)),
    file:delete(TermFile),

    case Diffs of
        [] ->
            io:format("~n[~s] all declared primitives found in kernel ✓~n", [Example]),
            halt(0);
        _ ->
            io:format("~n[~s] SILENT DROPS FOUND:~n", [Example]),
            [io:format("  ✗ ~s~n", [D]) || D <- Diffs],
            halt(1)
    end.

%% ─── diff one table ──────────────────────────────────────────────

diff_table(#{name := TName} = T, KernelDump) ->
    NameStr = binary_to_list(iolist_to_binary(TName)),

    Counters = maps:get(counters, T, []),
    Sets     = maps:get(sets, T, []),
    Maps_    = maps:get(maps, T, []),
    VMaps    = maps:get(vmaps, T, []),
    FTs      = maps:get(flowtables, T, []),
    Chains   = maps:get(chains, T, []),

    %% Kernel table block
    TableBlock = extract_table_block(KernelDump, NameStr),

    check_counters(TName, Counters, TableBlock) ++
    check_sets(TName, Sets, TableBlock) ++
    check_maps(TName, Maps_, TableBlock) ++
    check_vmaps(TName, VMaps, TableBlock) ++
    check_flowtables(TName, FTs, TableBlock) ++
    check_chains(TName, Chains, TableBlock).

extract_table_block(Dump, NameStr) ->
    %% Match `table inet NAME { ... }` — naive brace-count.
    Prefix = "table inet " ++ NameStr ++ " {",
    case string:find(Dump, Prefix) of
        nomatch -> "";
        Rest ->
            After = lists:sublist(Rest, length(Prefix) + 1, length(Rest)),
            extract_until_matching(After, 1, [])
    end.

extract_until_matching([], _Depth, Acc) ->
    lists:reverse(Acc);
extract_until_matching([$} | _Rest], 1, Acc) ->
    lists:reverse(Acc);
extract_until_matching([$} | Rest], D, Acc) ->
    extract_until_matching(Rest, D - 1, [$} | Acc]);
extract_until_matching([${ | Rest], D, Acc) ->
    extract_until_matching(Rest, D + 1, [${ | Acc]);
extract_until_matching([C | Rest], D, Acc) ->
    extract_until_matching(Rest, D, [C | Acc]).

%% ─── per-primitive checks ─────────────────────────────────────────

check_counters(T, Counters, Block) ->
    lists:filtermap(fun(C) ->
        case string:find(Block, "counter " ++ binary_to_list(iolist_to_binary(C))) of
            nomatch -> {true, io_lib:format("~s: counter ~s missing from kernel",
                                             [T, C])};
            _ -> false
        end
    end, Counters).

check_sets(T, Sets, Block) ->
    lists:flatmap(fun(S) -> check_one_set(T, S, Block) end, Sets).

check_one_set(T, {Name, _Type}, Block) ->
    NameL = binary_to_list(iolist_to_binary(Name)),
    case string:find(Block, "set " ++ NameL) of
        nomatch -> [io_lib:format("~s: set ~s missing", [T, Name])];
        _ -> []
    end;
check_one_set(T, {Name, _Type, Opts}, Block) ->
    NameL = binary_to_list(iolist_to_binary(Name)),
    Declared = maps:get(elements, Opts, []),
    case string:find(Block, "set " ++ NameL) of
        nomatch -> [io_lib:format("~s: set ~s missing", [T, Name])];
        SetBlock ->
            %% Check element count parity
            ElementsInKernel = count_elements_line(SetBlock),
            case {Declared, ElementsInKernel} of
                {[], _} -> [];
                {Decl, 0} ->
                    [io_lib:format("~s: set ~s declared ~p elements but kernel shows NONE",
                                   [T, Name, length(Decl)])];
                _ -> []
            end
    end.

check_maps(T, Maps_, Block) ->
    lists:flatmap(fun(#{name := N, entries := E}) ->
        NameL = binary_to_list(iolist_to_binary(N)),
        case string:find(Block, "map " ++ NameL) of
            nomatch -> [io_lib:format("~s: map ~s missing", [T, N])];
            MapBlock ->
                ExpectN = case E of
                    {replica_ips, _, _} -> 0;  %% dynamic, skip
                    L when is_list(L) -> length(L);
                    _ -> 0
                end,
                ActN = count_elements_line(MapBlock),
                case {ExpectN, ActN} of
                    {0, _} -> [];
                    {X, 0} when X > 0 ->
                        [io_lib:format("~s: map ~s declared ~p entries but kernel empty",
                                       [T, N, X])];
                    _ -> []
                end
        end
    end, Maps_).

check_vmaps(T, VMaps, Block) ->
    lists:flatmap(fun(#{name := N, entries := E}) ->
        NameL = binary_to_list(iolist_to_binary(N)),
        case string:find(Block, "map " ++ NameL) of
            nomatch -> [io_lib:format("~s: vmap ~s missing", [T, N])];
            VmBlock ->
                case {length(E), count_elements_line(VmBlock)} of
                    {0, _} -> [];
                    {X, 0} when X > 0 ->
                        [io_lib:format("~s: vmap ~s declared ~p entries but kernel empty",
                                       [T, N, X])];
                    _ -> []
                end
        end
    end, VMaps).

check_flowtables(T, FTs, Block) ->
    lists:filtermap(fun(#{name := N}) ->
        NameL = binary_to_list(iolist_to_binary(N)),
        case string:find(Block, "flowtable " ++ NameL) of
            nomatch -> {true, io_lib:format("~s: flowtable ~s missing", [T, N])};
            _ -> false
        end
    end, FTs).

check_chains(T, Chains, Block) ->
    lists:filtermap(fun(#{name := N}) ->
        NameL = binary_to_list(iolist_to_binary(N)),
        case string:find(Block, "chain " ++ NameL) of
            nomatch -> {true, io_lib:format("~s: chain ~s missing", [T, N])};
            _ -> false
        end
    end, Chains).

count_elements_line(Block) ->
    %% look for `elements = { ... }` within the block and count
    %% comma separators (naive — every "," inside braces counts).
    case string:find(Block, "elements = {") of
        nomatch -> 0;
        Rest ->
            Inside = extract_until_matching(
                       lists:sublist(Rest, 13, length(Rest)), 1, []),
            %% Elements are comma-separated.  Count commas + 1.
            Commas = length([1 || C <- Inside, C =:= $,]),
            case string:trim(Inside) of
                "" -> 0;
                _  -> Commas + 1
            end
    end.

%% ─── loader ─────────────────────────────────────────────────────

patch_and_load(TermFile, BinPath, Parent) ->
    {ok, Config0} = erlkoenig_config:parse(TermFile),
    Pods = [patch_pod(P, BinPath) || P <- maps:get(pods, Config0, [])],
    Host = maps:get(host, Config0, #{}),
    Zones = maps:get(zones, Config0, []),
    Remap = fun(#{network := #{parent := _} = Net} = M) ->
        M#{network => Net#{parent => Parent}};
        (M) -> M
    end,
    Patched = Config0#{pods => Pods,
                       host => Remap(Host),
                       zones => [Remap(Z) || Z <- Zones]},
    %% Strip signature_required so unsigned demo binary spawns
    Patched2 = strip_sig_opts(Patched),
    ok = file:write_file(TermFile,
                          io_lib:format("~tp.~n", [Patched2])),
    case erlkoenig_config:load(TermFile) of
        {ok, _} -> ok;
        Other -> {error, Other}
    end.

patch_pod(Pod, BinPath) ->
    Cts = [maps:without([signature_required, sig_path],
                         C#{binary => BinPath})
           || C <- maps:get(containers, Pod, [])],
    Pod#{containers => Cts}.

strip_sig_opts(#{pods := Pods} = C) ->
    C#{pods => [strip_pod_sigs(P) || P <- Pods]};
strip_sig_opts(C) -> C.

strip_pod_sigs(Pod) ->
    Cts = [maps:without([signature_required, sig_path, files], C)
           || C <- maps:get(containers, Pod, [])],
    Pod#{containers => Cts}.
