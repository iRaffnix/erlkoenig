%%% @doc Syscall matrix end-to-end tests.
%%%
%%% Tests that erlkoenig_elf correctly extracts syscall numbers from
%%% real compiled binaries (assembly and Go), validating against
%%% strace ground truth where available.
%%%
%%% Prerequisites:
%%%   make test-matrix-build    (compile test binaries)
%%%   make test-matrix-strace   (optional: gather strace data)
-module(elf_syscall_matrix_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%% ---------------------------------------------------------------------------
%% Test generators
%% ---------------------------------------------------------------------------

asm_matrix_test_() ->
    BinDir = asm_bin_dir(),
    case filelib:is_dir(BinDir) of
        false ->
            [];
        true ->
            Bins = filelib:wildcard(filename:join(BinDir, "syscall_*")),
            [asm_test_case(B) || B <- lists:sort(Bins)]
    end.

go_matrix_test_() ->
    BinDir = go_bin_dir(),
    case filelib:is_dir(BinDir) of
        false ->
            [];
        true ->
            Bins = filelib:wildcard(filename:join(BinDir, "cat_*")),
            [go_test_case(B) || B <- lists:sort(Bins)]
    end.

%% ---------------------------------------------------------------------------
%% Assembly test cases
%% ---------------------------------------------------------------------------

asm_test_case(BinPath) ->
    Base = filename:basename(BinPath),
    {Nr, Name} = parse_asm_filename(Base),
    Title = lists:flatten(io_lib:format("asm/~s (~b)", [Name, Nr])),
    {Title, {timeout, 30, fun() -> run_asm_test(BinPath, Nr, Name) end}}.

run_asm_test(BinPath, Nr, Name) ->
    %% Parse the binary
    {ok, Bin} = file:read_file(BinPath),
    {ok, Elf} = elf_parse:from_binary(Bin),

    %% Extract syscalls
    {ok, Result} = elf_syscall:extract(Elf),
    Resolved = maps:get(resolved, Result),

    %% Target syscall MUST be in resolved set
    ?assertMatch(
        {ok, _},
        maps:find(Nr, Resolved),
        lists:flatten(
            io_lib:format(
                "Syscall ~b (~s) not found in resolved set. Got: ~p",
                [Nr, Name, maps:keys(Resolved)]
            )
        )
    ),

    %% For non-exit syscalls, exit(60) should also be present
    IsExit = lists:member(Nr, [60, 231]),
    case IsExit of
        true ->
            ok;
        false ->
            ?assertMatch(
                {ok, _},
                maps:find(60, Resolved),
                "exit(60) not found in resolved set"
            )
    end,

    %% Strace comparison if available
    StraceFile = strace_file(asm, BinPath),
    case filelib:is_regular(StraceFile) of
        false ->
            ok;
        true ->
            StraceSyscalls = parse_strace(StraceFile),
            ResolvedNames = [N || {_, N} <- maps:to_list(Resolved)],
            Missing = [
                S
             || S <- StraceSyscalls,
                not lists:member(S, ResolvedNames)
            ],
            ?assertEqual(
                [],
                Missing,
                lists:flatten(
                    io_lib:format(
                        "Strace syscalls not found in static analysis: ~p",
                        [Missing]
                    )
                )
            )
    end.

%% ---------------------------------------------------------------------------
%% Go test cases
%% ---------------------------------------------------------------------------

go_test_case(BinPath) ->
    Base = filename:basename(BinPath),
    Title = lists:flatten(io_lib:format("go/~s", [Base])),
    {Title, {timeout, 60, fun() -> run_go_test(BinPath) end}}.

run_go_test(BinPath) ->
    %% Parse the binary — must not crash
    {ok, Bin} = file:read_file(BinPath),
    {ok, Elf} = elf_parse:from_binary(Bin),

    %% Extract syscalls — must not crash
    {ok, Result} = elf_syscall:extract(Elf),
    Resolved = maps:get(resolved, Result),
    UnresolvedCount = maps:get(unresolved_count, Result),

    %% Must find at least some syscalls
    TotalDetected = map_size(Resolved) + UnresolvedCount,
    ?assert(
        TotalDetected > 0,
        "No syscalls detected in Go binary"
    ),

    %% If strace data exists, compute coverage
    StraceFile = strace_file(go, BinPath),
    case filelib:is_regular(StraceFile) of
        false ->
            ok;
        true ->
            StraceSyscalls = parse_strace(StraceFile),
            ResolvedNames = [N || {_, N} <- maps:to_list(Resolved)],
            Found = [
                S
             || S <- StraceSyscalls,
                lists:member(S, ResolvedNames)
            ],
            Coverage =
                case length(StraceSyscalls) of
                    0 -> 100.0;
                    Total -> length(Found) / Total * 100.0
                end,
            io:format(
                user,
                "  ~s: ~.1f% coverage (~b/~b strace syscalls, "
                "~b resolved, ~b unresolved)~n",
                [
                    filename:basename(BinPath),
                    Coverage,
                    length(Found),
                    length(StraceSyscalls),
                    map_size(Resolved),
                    UnresolvedCount
                ]
            ),
            %% Warn but don't fail on low coverage for Go binaries
            case Coverage < 80.0 of
                true ->
                    io:format(
                        user,
                        "  WARNING: Low coverage for ~s: ~.1f%~n",
                        [filename:basename(BinPath), Coverage]
                    );
                false ->
                    ok
            end
    end.

%% ---------------------------------------------------------------------------
%% Strace parser
%% ---------------------------------------------------------------------------

%% Parse strace -c -S name summary output.
%% Format:
%%   % time     seconds  usecs/call     calls    errors  syscall
%%   ------ ----------- ----------- --------- --------- ----------------
%%     0.00    0.000000           0         1           close
%%     ...
%%   ------ ----------- ----------- --------- --------- ----------------
%%   100.00    0.000123                     5         2  total
parse_strace(File) ->
    {ok, Data} = file:read_file(File),
    Lines = string:split(binary_to_list(Data), "\n", all),
    parse_strace_lines(Lines, []).

parse_strace_lines([], Acc) ->
    lists:reverse(Acc);
parse_strace_lines([Line | Rest], Acc) ->
    Trimmed = string:trim(Line),
    case parse_strace_line(Trimmed) of
        {ok, Name} -> parse_strace_lines(Rest, [list_to_binary(Name) | Acc]);
        skip -> parse_strace_lines(Rest, Acc)
    end.

parse_strace_line([]) ->
    skip;
% header
parse_strace_line("%" ++ _) ->
    skip;
% separator
parse_strace_line("-" ++ _) ->
    skip;
parse_strace_line(Line) ->
    %% Try to extract syscall name (last field in the line)
    case string:tokens(Line, " \t") of
        Tokens when length(Tokens) >= 6 ->
            Last = lists:last(Tokens),
            case Last of
                "total" ->
                    skip;
                Name ->
                    %% Verify first token looks like a percentage
                    case hd(Tokens) of
                        [C | _] when C >= $0, C =< $9 -> {ok, Name};
                        _ -> skip
                    end
            end;
        _ ->
            skip
    end.

%% ---------------------------------------------------------------------------
%% Helpers
%% ---------------------------------------------------------------------------

parse_asm_filename(Basename) ->
    %% syscall_NNN_name -> {NNN, "name"}
    case
        re:run(
            Basename,
            "^syscall_(\\d+)_(.+)$",
            [{capture, all_but_first, list}]
        )
    of
        {match, [NrStr, Name]} ->
            {list_to_integer(NrStr), Name};
        nomatch ->
            error({bad_asm_filename, Basename})
    end.

matrix_dir() ->
    %% rebar3 runs tests from the project root
    {ok, Cwd} = file:get_cwd(),
    Candidate = filename:join([Cwd, "test", "syscall_matrix"]),
    case filelib:is_dir(Candidate) of
        true ->
            Candidate;
        false ->
            %% Walk up from CWD looking for test/syscall_matrix
            find_matrix_dir(Cwd)
    end.

find_matrix_dir(Dir) ->
    Candidate = filename:join([Dir, "test", "syscall_matrix"]),
    case filelib:is_dir(Candidate) of
        true ->
            Candidate;
        false ->
            Parent = filename:dirname(Dir),
            case Parent of
                Dir -> Candidate;
                _ -> find_matrix_dir(Parent)
            end
    end.

asm_bin_dir() -> filename:join(matrix_dir(), "bin/asm").
go_bin_dir() -> filename:join(matrix_dir(), "bin/go").

strace_file(asm, BinPath) ->
    Base = filename:basename(BinPath),
    filename:join([matrix_dir(), "strace", "asm", Base ++ ".strace"]);
strace_file(go, BinPath) ->
    Base = filename:basename(BinPath),
    filename:join([matrix_dir(), "strace", "go", Base ++ ".strace"]).
