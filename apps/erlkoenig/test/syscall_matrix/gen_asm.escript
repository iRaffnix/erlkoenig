#!/usr/bin/env escript
%% -*- erlang -*-
%%% @doc Generate assembly test files from syscall_defs.
%%%
%%% Each generated .S file contains exactly one target syscall
%%% followed by exit(0), using Intel syntax.

-mode(compile).

main(_Args) ->
    ScriptDir = filename:dirname(escript:script_name()),
    AsmDir = filename:join(ScriptDir, "asm"),
    ok = filelib:ensure_dir(filename:join(AsmDir, "dummy")),

    %% Add the syscall_matrix dir to code path for syscall_defs
    true = code:add_pathz(ScriptDir),

    %% Compile syscall_defs if needed
    DefsFile = filename:join(ScriptDir, "syscall_defs.erl"),
    {ok, syscall_defs, Bin} = compile:file(DefsFile, [binary, return_errors]),
    {module, syscall_defs} = code:load_binary(syscall_defs, DefsFile, Bin),

    Defs = syscall_defs:x86_64(),
    Generated = lists:foldl(fun(Def, Acc) ->
        case generate(AsmDir, Def) of
            ok -> Acc + 1;
            skip -> Acc
        end
    end, 0, Defs),
    io:format("Generated ~b assembly files in ~s~n", [Generated, AsmDir]).

generate(_Dir, {_Nr, _Name, skip, _Args}) -> skip;
generate(_Dir, {_Nr, _Name, blocking, _Args}) -> skip;
generate(Dir, {Nr, Name, Tier, Args}) ->
    Filename = io_lib:format("syscall_~3..0b_~s.S", [Nr, Name]),
    Path = filename:join(Dir, lists:flatten(Filename)),
    Asm = format_asm(Nr, Name, Tier, Args),
    ok = file:write_file(Path, Asm),
    ok.

format_asm(Nr, Name, Tier, Args) ->
    Header = io_lib:format(
        "# syscall ~b: ~s (~s)\n"
        ".intel_syntax noprefix\n"
        ".global _start\n"
        ".text\n"
        "_start:\n",
        [Nr, Name, Tier]),

    StackSetup = stack_setup(Args),
    ArgSetup = arg_setup(Args),
    Syscall = io_lib:format(
        "    mov eax, ~b\n"
        "    syscall\n",
        [Nr]),

    Exit = case Tier of
        exit_like -> "";
        _ ->
            "    mov eax, 60\n"
            "    xor edi, edi\n"
            "    syscall\n"
    end,

    StackCleanup = stack_cleanup(Args),

    lists:flatten([Header, StackSetup, ArgSetup, Syscall,
                   StackCleanup, Exit]).

%% Check if we need stack allocation for timespec/timeval structs
stack_setup(Args) ->
    case needs_stack(Args) of
        false -> "";
        timeval ->
            "    sub rsp, 16\n"
            "    mov qword ptr [rsp], 0\n"
            "    mov qword ptr [rsp+8], 0\n";
        timespec ->
            "    sub rsp, 16\n"
            "    mov qword ptr [rsp], 0\n"
            "    mov qword ptr [rsp+8], 0\n"
    end.

stack_cleanup(Args) ->
    case needs_stack(Args) of
        false -> "";
        _ -> "    add rsp, 16\n"
    end.

needs_stack(Args) ->
    case lists:keyfind(r8, 1, Args) of
        {r8, stack_zero_timeval} -> timeval;
        {r8, stack_zero_timespec} -> timespec;
        _ ->
            case lists:keyfind(rdx, 1, Args) of
                {rdx, stack_zero_timespec} -> timespec;
                _ -> false
            end
    end.

arg_setup(Args) ->
    %% Default: zero all arg registers
    Regs = [rdi, rsi, rdx, r10, r8, r9],
    UsedRegs = [R || {R, _} <- Args],
    %% Zero registers not explicitly set
    DefaultZero = lists:flatten([
        zero_reg(R) || R <- Regs, not lists:member(R, UsedRegs)
    ]),
    %% Set explicitly specified registers
    Explicit = lists:flatten([
        set_reg(R, V) || {R, V} <- Args
    ]),
    DefaultZero ++ Explicit.

zero_reg(rdi)  -> "    xor edi, edi\n";
zero_reg(rsi)  -> "    xor esi, esi\n";
zero_reg(rdx)  -> "    xor edx, edx\n";
zero_reg(r10)  -> "    xor r10d, r10d\n";
zero_reg(r8)   -> "    xor r8d, r8d\n";
zero_reg(r9)   -> "    xor r9d, r9d\n".

set_reg(R, stack_zero_timeval)  -> io_lib:format("    mov ~s, rsp\n", [reg_name(R)]);
set_reg(R, stack_zero_timespec) -> io_lib:format("    mov ~s, rsp\n", [reg_name(R)]);
set_reg(R, V) when is_integer(V) -> io_lib:format("    mov ~s, ~b\n", [reg32_name(R), V]).

reg_name(rdi) -> "rdi";
reg_name(rsi) -> "rsi";
reg_name(rdx) -> "rdx";
reg_name(r10) -> "r10";
reg_name(r8)  -> "r8";
reg_name(r9)  -> "r9".

reg32_name(rdi) -> "edi";
reg32_name(rsi) -> "esi";
reg32_name(rdx) -> "edx";
reg32_name(r10) -> "r10d";
reg32_name(r8)  -> "r8d";
reg32_name(r9)  -> "r9d".
