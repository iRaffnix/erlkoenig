%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%

-module(ek).
-moduledoc """
Erlkoenig Operator Shell.

Two-letter module for interactive server administration.
Every function prints formatted output and returns ok.
Use erlkoenig:* for programmatic access.

  ek:help().           -- Show all commands
  ek:ps().             -- List containers
  ek:top().            -- Live resource usage
  ek:inspect(web).     -- Container details
  ek:logs(web).        -- Stream stdout/stderr
  ek:stop(web).        -- Stop container
  ek:restart(web).     -- Restart container
  ek:load(File).       -- Load DSL config
  ek:reload(File).     -- Delta-update config
  ek:dns(Name).        -- DNS lookup
  ek:health().         -- Health check status
  ek:zones().          -- List network zones
  ek:events().         -- Stream lifecycle events
""".

-export([help/0, ps/0, top/0,
         inspect/1, logs/1, stop/1, restart/1,
         load/1, reload/1,
         dns/1, health/0, zones/0, events/0, events/1,
         limits/0, limits/1,
         export/0, export/1]).

%% capture/1 — Run a fun that uses io:format, return output as string.
%% Useful for eval/rpc where io:format goes to a remote group_leader.
-export([capture/1]).

%% ANSI colors
-define(GREEN,  "\e[32m").
-define(RED,    "\e[31m").
-define(YELLOW, "\e[33m").
-define(CYAN,   "\e[36m").
-define(BOLD,   "\e[1m").
-define(DIM,    "\e[2m").
-define(RESET,  "\e[0m").

%%====================================================================
%% help
%%====================================================================

-spec help() -> ok.
help() ->
    io:format(
      "~n"
      ?BOLD "  Erlkoenig Operator Shell" ?RESET "~n"
      "~n"
      ?BOLD "  Containers" ?RESET "~n"
      "    ek:ps()              List all containers~n"
      "    ek:top()             Resource usage (CPU, memory, PIDs)~n"
      "    ek:inspect(Name)     Detailed container info~n"
      "    ek:logs(Name)        Stream stdout/stderr (Ctrl-C to stop)~n"
      "    ek:stop(Name)        Stop a container~n"
      "    ek:restart(Name)     Restart a container~n"
      "~n"
      ?BOLD "  Configuration" ?RESET "~n"
      "    ek:load(File)        Load .term config, spawn containers~n"
      "    ek:reload(File)      Delta-update running config~n"
      "~n"
      ?BOLD "  Network & Security" ?RESET "~n"
      "    ek:dns(Name)         DNS lookup (name.erlkoenig)~n"
      "    ek:zones()           List network zones~n"
      "    ek:health()          Health check status~n"
      "~n"
      ?BOLD "  Monitoring" ?RESET "~n"
      "    ek:events()          Stream lifecycle events~n"
      "    ek:events(N)         Show last N events~n"
      "~n"
      ?DIM "  Name = atom | binary | string. Examples: web, <<\"web\">>, \"web\"" ?RESET "~n"
      ?DIM "  For raw data: erlkoenig:list(), erlkoenig:inspect(Pid)" ?RESET "~n"
      "~n"),
    ok.

%%====================================================================
%% ps — list containers
%%====================================================================

-spec ps() -> ok.
ps() ->
    Containers = erlkoenig:list(),
    case Containers of
        [] ->
            io:format("~n  No containers running.~n~n"),
            ok;
        _ ->
            Header = io_lib:format(
                "~n  ~s~-14s ~-10s ~-16s ~-10s ~-10s ~-6s~s~n",
                [?BOLD, "NAME", "STATE", "IP", "RX", "TX", "RESTARTS", ?RESET]),
            io:format("~s", [Header]),
            io:format("  ~s~s~n", [?DIM, lists:duplicate(72, $-)]),
            io:format("~s", [?RESET]),
            lists:foreach(fun(Ct) -> print_ps_row(Ct) end, Containers),
            io:format("~n"),
            ok
    end.

print_ps_row(Ct) ->
    Name = format_name(maps:get(name, Ct, maps:get(id, Ct))),
    State = maps:get(state, Ct),
    Ip = format_ip(maps:get(net_info, Ct, undefined)),
    Restarts = integer_to_list(maps:get(restart_count, Ct, 0)),
    {Rx, Tx} = format_traffic(Ct),
    Color = state_color(State),
    io:format("  ~-14s ~s~-10s~s ~-16s ~-10s ~-10s ~-6s~n",
              [Name, Color, atom_to_list(State), ?RESET, Ip, Rx, Tx, Restarts]).

%%====================================================================
%% top — resource usage
%%====================================================================

-spec top() -> ok.
top() ->
    Containers = erlkoenig:list(),
    case Containers of
        [] ->
            io:format("~n  No containers running.~n~n"),
            ok;
        _ ->
            Header = io_lib:format(
                "~n  ~s~-14s ~-10s ~-8s ~-8s ~-6s ~-10s ~-10s ~-8s ~-8s~s~n",
                [?BOLD, "NAME", "STATE", "CPU", "MEM", "PIDS",
                 "RX", "TX", "RX PKT", "TX PKT", ?RESET]),
            io:format("~s", [Header]),
            io:format("  ~s~s~n", [?DIM, lists:duplicate(88, $-)]),
            io:format("~s", [?RESET]),
            lists:foreach(fun(Ct) -> print_top_row(Ct) end, Containers),
            io:format("~n"),
            ok
    end.

print_top_row(Ct) ->
    Name = format_name(maps:get(name, Ct, maps:get(id, Ct))),
    State = maps:get(state, Ct),
    Id = maps:get(id, Ct),
    Color = state_color(State),
    {Cpu, Mem, Pids} =
        case State of
            running ->
                case erlkoenig_cgroup:read_stats(Id) of
                    {ok, Stats} ->
                        {format_cpu(maps:get(cpu_usec, Stats, 0)),
                         format_bytes(maps:get(memory_bytes, Stats, 0)),
                         integer_to_list(maps:get(pids_current, Stats, 0))};
                    _ ->
                        {"-", "-", "-"}
                end;
            _ ->
                {"-", "-", "-"}
        end,
    {Rx, Tx} = format_traffic(Ct),
    {RxPkt, TxPkt} = format_traffic_pkts(Ct),
    io:format("  ~-14s ~s~-10s~s ~-8s ~-8s ~-6s ~-10s ~-10s ~-8s ~-8s~n",
              [Name, Color, atom_to_list(State), ?RESET,
               Cpu, Mem, Pids, Rx, Tx, RxPkt, TxPkt]).

%%====================================================================
%% inspect — container details
%%====================================================================

-spec inspect(atom() | binary() | string()) -> ok.
inspect(Name) ->
    case find_container(Name) of
        {ok, Ct} ->
            io:format("~n"),
            print_kv("Name", format_name(maps:get(name, Ct, "-"))),
            print_kv("ID", maps:get(id, Ct)),
            State = maps:get(state, Ct),
            print_kv("State", [state_color(State), atom_to_list(State), ?RESET]),
            print_kv("Zone", atom_to_list(maps:get(zone, Ct, default))),
            print_kv("Binary", maps:get(binary, Ct, "-")),
            print_kv("OS PID", format_int(maps:get(os_pid, Ct, undefined))),
            print_kv("Restart Policy", io_lib:format("~p", [maps:get(restart, Ct, none)])),
            print_kv("Restart Count", format_int(maps:get(restart_count, Ct, 0))),
            print_kv("Seccomp", atom_to_list(maps:get(seccomp, Ct, none))),
            case maps:get(net_info, Ct, undefined) of
                undefined -> ok;
                Net ->
                    io:format("~n  ~s--- Network ---~s~n", [?DIM, ?RESET]),
                    print_kv("IP", format_ip4(maps:get(ip, Net))),
                    GwVal = maps:get(gateway, Net, undefined),
                    print_kv("Gateway", case GwVal of
                        undefined -> "-";
                        _ -> format_ip4(GwVal)
                    end),
                    Veth = maps:get(host_veth, Net, undefined),
                    Iface = maps:get(iface, Net, maps:get(container_veth, Net, "-")),
                    print_kv("Interface", Iface),
                    case Veth of
                        undefined -> ok;
                        _ -> print_kv("Host veth", Veth)
                    end,
                    case State of
                        running when is_binary(Veth) ->
                            VethStats = read_all_veth_stats(Veth),
                            io:format("~n  ~s--- Traffic (container perspective) ---~s~n",
                                      [?DIM, ?RESET]),
                            %% Host veth RX = Container TX, swap for display
                            print_kv("RX bytes", format_bytes(maps:get(tx_bytes, VethStats, 0))),
                            print_kv("RX packets", format_int(maps:get(tx_packets, VethStats, 0))),
                            print_kv("RX dropped", format_int_warn(maps:get(tx_dropped, VethStats, 0))),
                            print_kv("RX errors", format_int_warn(maps:get(tx_errors, VethStats, 0))),
                            print_kv("TX bytes", format_bytes(maps:get(rx_bytes, VethStats, 0))),
                            print_kv("TX packets", format_int(maps:get(rx_packets, VethStats, 0))),
                            print_kv("TX dropped", format_int_warn(maps:get(rx_dropped, VethStats, 0))),
                            print_kv("TX errors", format_int_warn(maps:get(rx_errors, VethStats, 0)));
                        _ -> ok
                    end
            end,
            case maps:get(limits, Ct, #{}) of
                Limits when map_size(Limits) > 0 ->
                    io:format("~n  ~s--- Limits ---~s~n", [?DIM, ?RESET]),
                    maps:foreach(fun(K, V) ->
                        print_kv(atom_to_list(K), io_lib:format("~p", [V]))
                    end, Limits);
                _ -> ok
            end,
            case maps:get(exit_info, Ct, undefined) of
                undefined -> ok;
                Exit ->
                    io:format("~n  ~s--- Exit ---~s~n", [?DIM, ?RESET]),
                    print_kv("Exit code", format_int(maps:get(exit_code, Exit, undefined))),
                    print_kv("Signal", format_int(maps:get(term_signal, Exit, undefined)))
            end,
            io:format("~n"),
            ok;
        not_found ->
            print_error("Container '~s' not found", [to_str(Name)])
    end.

%%====================================================================
%% limits — SOLL/IST resource overview
%%====================================================================

-spec limits(atom() | binary() | string()) -> ok.
limits(Name) ->
    case find_container(Name) of
        {ok, #{id := Id, state := State, limits := Limits} = Ct} ->
            CName = to_str(maps:get(name, Ct, Id)),
            io:format("~n  ~s~s~s~n~n", [?BOLD, CName, ?RESET]),
            case State of
                running ->
                    case erlkoenig_cgroup:read_stats(Id) of
                        {ok, Stats} ->
                            print_limit_row("Memory",
                                maps:get(memory_bytes, Stats, 0),
                                maps:get(memory, Limits, undefined),
                                fun format_bytes/1),
                            print_limit_row("Mem Peak",
                                maps:get(memory_peak, Stats, 0),
                                maps:get(memory, Limits, undefined),
                                fun format_bytes/1),
                            print_limit_row("PIDs",
                                maps:get(pids_current, Stats, 0),
                                maps:get(pids, Limits, undefined),
                                fun integer_to_list/1),
                            CpuLim = case maps:get(cpu, Limits, undefined) of
                                undefined -> ?DIM ++ "unlimited" ++ ?RESET;
                                N -> integer_to_list(N) ++ " cores"
                            end,
                            io:format("  ~s~-12s~s ~10s   ~s~n",
                                      [?DIM, "CPU used", ?RESET,
                                       format_cpu(maps:get(cpu_usec, Stats, 0)),
                                       CpuLim]);
                        _ ->
                            io:format("  ~scgroup stats not available~s~n",
                                      [?DIM, ?RESET])
                    end;
                _ ->
                    io:format("  ~sContainer not running~s~n", [?DIM, ?RESET])
            end,
            io:format("~n"),
            ok;
        {ok, #{id := Id}} ->
            io:format("~n  ~s: no limits configured~n~n", [to_str(Id)]),
            ok;
        not_found ->
            print_error("Container '~s' not found", [to_str(Name)])
    end.

-spec limits() -> ok.
limits() ->
    case erlkoenig:list() of
        [] ->
            io:format("~n  No containers running.~n~n"),
            ok;
        Containers ->
            io:format("~n  ~s~-14s ~-10s ~-12s ~-12s ~-8s ~-10s ~-10s~s~n",
                       [?BOLD, "NAME", "STATE", "MEM", "MEM LIMIT",
                        "PIDS", "PID LIMIT", "MEM %", ?RESET]),
            io:format("  ~s~s~n~s", [?DIM, lists:duplicate(82, $-), ?RESET]),
            lists:foreach(fun(Ct) -> print_limits_row(Ct) end, Containers),
            io:format("~n"),
            ok
    end.

print_limits_row(Ct) ->
    Name = to_str(maps:get(name, Ct, maps:get(id, Ct))),
    State = maps:get(state, Ct),
    Id = maps:get(id, Ct),
    Limits = maps:get(limits, Ct, #{}),
    case State of
        running ->
            case erlkoenig_cgroup:read_stats(Id) of
                {ok, Stats} ->
                    MemCur = maps:get(memory_bytes, Stats, 0),
                    MemMax = maps:get(memory, Limits, undefined),
                    PidCur = maps:get(pids_current, Stats, 0),
                    PidMax = maps:get(pids, Limits, undefined),
                    MemPct = format_pct(MemCur, MemMax),
                    io:format("  ~-14s ~s~-10s~s ~-12s ~-12s ~-8s ~-10s ~s~s~s~n",
                              [Name, state_color(State), atom_to_list(State), ?RESET,
                               format_bytes(MemCur), format_limit(MemMax, fun format_bytes/1),
                               integer_to_list(PidCur), format_limit(PidMax, fun integer_to_list/1),
                               pct_color(MemCur, MemMax), MemPct, ?RESET]);
                _ ->
                    io:format("  ~-14s ~s~-10s~s ~-12s ~-12s~n",
                              [Name, state_color(State), atom_to_list(State), ?RESET, "-", "-"])
            end;
        _ ->
            io:format("  ~-14s ~s~-10s~s~n",
                      [Name, state_color(State), atom_to_list(State), ?RESET])
    end.

print_limit_row(Label, Current, Limit, FmtFun) ->
    CurStr = FmtFun(Current),
    LimStr = case Limit of
        undefined -> ?DIM ++ "unlimited" ++ ?RESET;
        _         -> FmtFun(Limit)
    end,
    Pct = format_pct(Current, Limit),
    Bar = progress_bar(Current, Limit, 20),
    Color = pct_color(Current, Limit),
    io:format("  ~s~-12s~s ~10s / ~-12s ~s~s~s  ~s~n",
              [?DIM, Label, ?RESET, CurStr, LimStr, Color, Pct, ?RESET, Bar]).

format_pct(_, undefined) -> "-";
format_pct(_, 0) -> "-";
format_pct(Current, Max) ->
    Pct = (Current * 100) div Max,
    integer_to_list(Pct) ++ "%".

pct_color(_, undefined) -> "";
pct_color(_, 0) -> "";
pct_color(Current, Max) ->
    Pct = (Current * 100) div Max,
    if Pct >= 90 -> ?RED;
       Pct >= 70 -> ?YELLOW;
       true      -> ?GREEN
    end.

progress_bar(_, undefined, Width) ->
    ?DIM ++ "[" ++ lists:duplicate(Width, $-) ++ "]" ++ ?RESET;
progress_bar(_, 0, Width) ->
    ?DIM ++ "[" ++ lists:duplicate(Width, $-) ++ "]" ++ ?RESET;
progress_bar(Current, Max, Width) ->
    Pct = min(100, (Current * 100) div Max),
    Filled = (Pct * Width) div 100,
    Empty = Width - Filled,
    Color = if Pct >= 90 -> ?RED;
               Pct >= 70 -> ?YELLOW;
               true      -> ?GREEN
            end,
    Color ++ "[" ++ lists:duplicate(Filled, $#) ++ lists:duplicate(Empty, $-) ++ "]" ++ ?RESET.

format_limit(undefined, _FmtFun) -> "unlimited";
format_limit(Val, FmtFun) -> FmtFun(Val).

%%====================================================================
%% export — generate .exs DSL from running containers
%%====================================================================

-spec export() -> ok.
export() ->
    Containers = erlkoenig:list(),
    case Containers of
        [] ->
            io:format("# No containers running.~n"),
            ok;
        _ ->
            io:format("defmodule Exported do~n"),
            io:format("  use Erlkoenig.DSL~n"),
            lists:foreach(fun(Ct) ->
                export_container(Ct)
            end, Containers),
            io:format("end~n"),
            ok
    end.

-spec export(file:filename()) -> ok.
export(Filename) when is_list(Filename) ->
    Output = capture(fun() -> export() end),
    _ = file:write_file(Filename, Output),
    io:format("Exported to ~s~n", [Filename]),
    ok.

export_container(Ct) ->
    Name = maps:get(name, Ct, maps:get(id, Ct)),
    NameAtom = binary_to_atom_safe(Name),
    Binary = maps:get(binary, Ct),
    Ip = maps:get(ip, maps:get(net_info, Ct, #{}), undefined),
    Zone = maps:get(zone, Ct, default),
    Args = maps:get(args, Ct, []),
    Ports = maps:get(ports, Ct, []),
    Limits = maps:get(limits, Ct, #{}),
    Restart = maps:get(restart, Ct, no_restart),
    io:format("~n  container :~s do~n", [NameAtom]),
    io:format("    binary ~p~n", [binary_to_list(Binary)]),
    case Zone of
        default -> ok;
        _       -> io:format("    zone :~s~n", [Zone])
    end,
    case Ip of
        undefined -> ok;
        {A, B, C, D} ->
            io:format("    ip {~b, ~b, ~b, ~b}~n", [A, B, C, D])
    end,
    case Args of
        [] -> ok;
        _  -> io:format("    args ~p~n",
                         [[binary_to_list(A) || A <- Args]])
    end,
    case Ports of
        [] -> ok;
        _  -> io:format("    ports ~p~n", [Ports])
    end,
    case map_size(Limits) of
        0 -> ok;
        _ ->
            LimParts = lists:filtermap(fun
                ({cpu, V})    -> {true, io_lib:format("cpu: ~b", [V])};
                ({memory, V}) -> {true, io_lib:format("memory: ~p", [format_mem_limit(V)])};
                ({pids, V})   -> {true, io_lib:format("pids: ~b", [V])};
                (_)           -> false
            end, maps:to_list(Limits)),
            case LimParts of
                [] -> ok;
                _  -> io:format("    limits ~s~n",
                                [lists:join(", ", LimParts)])
            end
    end,
    case Restart of
        no_restart -> ok;
        always     -> io:format("    restart :always~n");
        on_failure -> io:format("    restart :on_failure~n");
        {on_failure, N} ->
            io:format("    restart {:on_failure, ~b}~n", [N]);
        _ -> ok
    end,
    io:format("  end~n").

binary_to_atom_safe(Bin) when is_binary(Bin) ->
    Str = binary_to_list(Bin),
    case lists:all(fun(C) ->
        (C >= $a andalso C =< $z) orelse
        (C >= $0 andalso C =< $9) orelse
        C =:= $_ end, Str) of
        true  -> Str;
        false -> "\"" ++ Str ++ "\""
    end.

format_mem_limit(Bytes) when Bytes >= 1073741824, Bytes rem 1073741824 =:= 0 ->
    integer_to_list(Bytes div 1073741824) ++ "G";
format_mem_limit(Bytes) when Bytes >= 1048576, Bytes rem 1048576 =:= 0 ->
    integer_to_list(Bytes div 1048576) ++ "M";
format_mem_limit(Bytes) when Bytes >= 1024, Bytes rem 1024 =:= 0 ->
    integer_to_list(Bytes div 1024) ++ "K";
format_mem_limit(Bytes) ->
    integer_to_list(Bytes).

%%====================================================================
%% logs — attach to container output
%%====================================================================

-spec logs(atom() | binary() | string()) -> ok.
logs(Name) ->
    case find_container(Name) of
        {ok, #{state := running} = Ct} ->
            Pid = maps:get(pid, Ct, undefined),
            case Pid of
                undefined ->
                    %% Find the process pid from pg
                    case find_pid(Name) of
                        {ok, P} -> do_logs(P, Name);
                        not_found -> print_error("Cannot attach to '~s'", [to_str(Name)])
                    end;
                P ->
                    do_logs(P, Name)
            end;
        {ok, #{state := State}} ->
            print_error("Container '~s' is ~p, not running", [to_str(Name), State]);
        not_found ->
            print_error("Container '~s' not found", [to_str(Name)])
    end.

do_logs(Pid, Name) ->
    _ = erlkoenig:attach(Pid),
    io:format("~n  ~sAttached to ~s. Press Ctrl-C to detach.~s~n~n",
              [?DIM, to_str(Name), ?RESET]),
    logs_loop(Pid).

logs_loop(Pid) ->
    receive
        {container_stdout, Pid, _Id, Data} ->
            io:format("~s", [Data]),
            logs_loop(Pid);
        {container_stderr, Pid, _Id, Data} ->
            io:format(?RED "~s" ?RESET, [Data]),
            logs_loop(Pid);
        {container_stopped, _Id, _} ->
            io:format("~n  ~sContainer stopped.~s~n~n", [?DIM, ?RESET]),
            ok
    after 30000 ->
        logs_loop(Pid)
    end.

%%====================================================================
%% stop / restart
%%====================================================================

-spec stop(atom() | binary() | string()) -> ok.
stop(Name) ->
    case find_pid(Name) of
        {ok, Pid} ->
            _ = erlkoenig:stop(Pid),
            io:format("  ~sStopped ~s~s~n", [?GREEN, to_str(Name), ?RESET]),
            ok;
        not_found ->
            print_error("Container '~s' not found", [to_str(Name)])
    end.

-spec restart(atom() | binary() | string()) -> ok.
restart(Name) ->
    case find_pid(Name) of
        {ok, Pid} ->
            Info = erlkoenig:inspect(Pid),
            case maps:get(restart, Info, no_restart) of
                no_restart ->
                    print_error("Container '~s' has no restart policy", [to_str(Name)]);
                _ ->
                    _ = erlkoenig:stop(Pid),
                    io:format("  ~sRestarting ~s (waiting for supervisor)~s~n",
                              [?YELLOW, to_str(Name), ?RESET]),
                    ok
            end;
        not_found ->
            print_error("Container '~s' not found", [to_str(Name)])
    end.

%%====================================================================
%% load / reload
%%====================================================================

-spec load(string() | binary()) -> ok.
load(File) ->
    Path = to_str(File),
    case erlkoenig_config:load(Path) of
        {ok, Pids} ->
            io:format("  ~sLoaded ~s — ~p container(s) spawned~s~n",
                      [?GREEN, Path, length(Pids), ?RESET]),
            ok;
        {error, Reason} ->
            print_error("Failed to load ~s: ~p", [Path, Reason])
    end.

-spec reload(string() | binary()) -> ok.
reload(File) ->
    Path = to_str(File),
    case erlkoenig_config:reload(Path) of
        {ok, _} ->
            io:format("  ~sReloaded ~s~s~n", [?GREEN, Path, ?RESET]),
            ok;
        {error, Reason} ->
            print_error("Failed to reload ~s: ~p", [Path, Reason])
    end.

%%====================================================================
%% dns
%%====================================================================

-spec dns(atom() | binary() | string()) -> ok.
dns(Name) ->
    Bin = to_bin(Name),
    case erlkoenig_dns:lookup(Bin) of
        {ok, Ip} ->
            io:format("  ~s → ~s~n", [Bin, format_ip4(Ip)]),
            ok;
        not_found ->
            print_error("DNS: '~s' not found", [to_str(Name)])
    end.

%%====================================================================
%% health
%%====================================================================

-spec health() -> ok.
health() ->
    Status = erlkoenig_health:status(),
    case Status of
        [] ->
            io:format("~n  No health checks configured.~n~n"),
            ok;
        _ ->
            Header = io_lib:format(
                "~n  ~s~-14s ~-16s ~-8s ~-10s ~-10s~s~n",
                [?BOLD, "CONTAINER", "IP:PORT", "STATUS", "FAILURES", "RETRIES", ?RESET]),
            io:format("~s", [Header]),
            io:format("  ~s~s~n", [?DIM, lists:duplicate(62, $-)]),
            io:format("~s", [?RESET]),
            lists:foreach(fun(H) -> print_health_row(H) end, Status),
            io:format("~n"),
            ok
    end.

print_health_row(H) ->
    Pid = maps:get(pid, H),
    CtName = try
        Info = erlkoenig:inspect(Pid),
        format_name(maps:get(name, Info, maps:get(id, Info)))
    catch _:_ -> "?"
    end,
    Ip = format_ip4(maps:get(ip, H, {0,0,0,0})),
    Port = integer_to_list(maps:get(port, H, 0)),
    Failures = maps:get(failures, H, 0),
    Retries = maps:get(retries, H, 0),
    {Status, Color} = case Failures of
        0 -> {"healthy", ?GREEN};
        N when N < Retries -> {"degraded", ?YELLOW};
        _ -> {"failing", ?RED}
    end,
    io:format("  ~-14s ~-16s ~s~-8s~s ~-10s ~-10s~n",
              [CtName, Ip ++ ":" ++ Port, Color, Status, ?RESET,
               integer_to_list(Failures), integer_to_list(Retries)]).

%%====================================================================
%% zones
%%====================================================================

-spec zones() -> ok.
zones() ->
    ZoneNames = erlkoenig_zone:zones(),
    case ZoneNames of
        [] ->
            io:format("~n  No zones configured.~n~n"),
            ok;
        _ ->
            Header = io_lib:format(
                "~n  ~s~-14s ~-18s ~-16s ~-16s~s~n",
                [?BOLD, "ZONE", "SUBNET", "GATEWAY", "BRIDGE", ?RESET]),
            io:format("~s", [Header]),
            io:format("  ~s~s~n", [?DIM, lists:duplicate(62, $-)]),
            io:format("~s", [?RESET]),
            lists:foreach(fun(Z) ->
                Config = erlkoenig_zone:zone_config(Z),
                Net = maps:get(network, Config, #{}),
                Subnet = format_ip4(maps:get(subnet, Net, {0,0,0,0})),
                Mask = integer_to_list(maps:get(netmask, Net, 24)),
                Gateway = case maps:get(gateway, Net, undefined) of
                    undefined -> "-";
                    GwIp -> format_ip4(GwIp)
                end,
                Mode = to_str(maps:get(mode, Net, bridge)),
                io:format("  ~-14s ~-18s ~-16s ~-16s~n",
                          [atom_to_list(Z), Subnet ++ "/" ++ Mask, Gateway, Mode])
            end, ZoneNames),
            io:format("~n"),
            ok
    end.

%%====================================================================
%% events
%%====================================================================

-spec events() -> no_return().
events() ->
    io:format("~n  ~sStreaming events. Press Ctrl-C to stop.~s~n~n",
              [?DIM, ?RESET]),
    _ = erlkoenig_events:subscribe(ek_event_printer, self()),
    events_loop().

-spec events(pos_integer()) -> ok.
events(N) when is_integer(N), N > 0 ->
    io:format("~n  ~sLast ~p event(s) — use ek:events() to stream live~s~n~n",
              [?DIM, N, ?RESET]),
    %% Event log does not store history; just start streaming
    _ = erlkoenig_events:subscribe(ek_event_printer, self()),
    events_loop_n(N).

events_loop() ->
    receive
        {ek_event, Event} ->
            print_event(Event),
            events_loop()
    after 30000 ->
        events_loop()
    end.

events_loop_n(0) ->
    _ = erlkoenig_events:unsubscribe(ek_event_printer, self()),
    ok;
events_loop_n(N) ->
    receive
        {ek_event, Event} ->
            print_event(Event),
            events_loop_n(N - 1)
    after 30000 ->
        events_loop_n(N)
    end.

print_event({container_started, Id, Pid}) ->
    io:format("  ~s[started]~s  ~s (pid=~p)~n", [?GREEN, ?RESET, Id, Pid]);
print_event({container_stopped, Id, ExitInfo}) ->
    Code = maps:get(exit_code, ExitInfo, "?"),
    io:format("  ~s[stopped]~s  ~s (exit=~p)~n", [?RED, ?RESET, Id, Code]);
print_event({container_failed, Id, Reason}) ->
    io:format("  ~s[failed]~s   ~s (~p)~n", [?RED, ?RESET, Id, Reason]);
print_event({container_restarting, Id, Attempt}) ->
    io:format("  ~s[restart]~s  ~s (attempt #~p)~n", [?YELLOW, ?RESET, Id, Attempt]);
print_event({container_oom, Id}) ->
    io:format("  ~s[oom]~s     ~s~n", [?RED, ?RESET, Id]);
print_event(Other) ->
    io:format("  [event]   ~p~n", [Other]).

%%====================================================================
%% Internal — name resolution
%%====================================================================

-doc "Find a container info map by name (atom, binary, or string).".
-spec find_container(atom() | binary() | string()) -> {ok, map()} | not_found.
find_container(Name) ->
    Bin = to_bin(Name),
    Containers = erlkoenig:list(),
    case lists:search(fun(Ct) ->
        to_bin(maps:get(name, Ct, <<>>)) =:= Bin orelse
        maps:get(id, Ct, <<>>) =:= Bin
    end, Containers) of
        {value, Ct} -> {ok, Ct};
        false -> not_found
    end.

-doc "Find a container's Erlang pid by name.".
-spec find_pid(atom() | binary() | string()) -> {ok, pid()} | not_found.
find_pid(Name) ->
    Bin = to_bin(Name),
    Pids = try pg:get_members(erlkoenig_pg, erlkoenig_cts)
           catch error:_ -> []
           end,
    find_pid_loop(Bin, Pids).

find_pid_loop(_Bin, []) -> not_found;
find_pid_loop(Bin, [Pid | Rest]) ->
    try erlkoenig_ct:get_info(Pid) of
        #{name := N} when N =:= Bin -> {ok, Pid};
        #{id := Id} when Id =:= Bin -> {ok, Pid};
        _ -> find_pid_loop(Bin, Rest)
    catch _:_ -> find_pid_loop(Bin, Rest)
    end.

%%====================================================================
%% Internal — formatting
%%====================================================================

to_bin(Name) when is_atom(Name) -> atom_to_binary(Name);
to_bin(Name) when is_list(Name) -> list_to_binary(Name);
to_bin(Name) when is_binary(Name) -> Name.

to_str(Name) when is_atom(Name) -> atom_to_list(Name);
to_str(Name) when is_binary(Name) -> binary_to_list(Name);
to_str(Name) when is_list(Name) -> Name.

format_name(undefined) -> "-";
format_name(Name) -> to_str(Name).

format_ip(undefined) -> "-";
format_ip(#{ip := Ip}) -> format_ip4(Ip);
format_ip(_) -> "-".

format_ip4({A, B, C, D}) ->
    lists:flatten(io_lib:format("~p.~p.~p.~p", [A, B, C, D])).

format_int(undefined) -> "-";
format_int(N) when is_integer(N) -> integer_to_list(N).

format_int_warn(0) -> "0";
format_int_warn(N) when is_integer(N) ->
    ?RED ++ integer_to_list(N) ++ ?RESET.

format_traffic(Ct) ->
    case maps:get(state, Ct) of
        running ->
            %% Host veth RX = Container TX, Host veth TX = Container RX
            case maps:get(net_info, Ct, undefined) of
                #{host_veth := Veth} ->
                    Rx = read_veth_stat(Veth, "tx_bytes"),
                    Tx = read_veth_stat(Veth, "rx_bytes"),
                    {format_bytes(Rx), format_bytes(Tx)};
                _ -> {"-", "-"}
            end;
        _ -> {"-", "-"}
    end.

format_traffic_pkts(Ct) ->
    case maps:get(state, Ct) of
        running ->
            case maps:get(net_info, Ct, undefined) of
                #{host_veth := Veth} ->
                    Rx = read_veth_stat(Veth, "tx_packets"),
                    Tx = read_veth_stat(Veth, "rx_packets"),
                    {integer_to_list(Rx), integer_to_list(Tx)};
                _ -> {"-", "-"}
            end;
        _ -> {"-", "-"}
    end.

read_veth_stat(Veth, Stat) ->
    Path = "/sys/class/net/" ++ binary_to_list(Veth) ++ "/statistics/" ++ Stat,
    case file:read_file(list_to_binary(Path)) of
        {ok, Bin} ->
            try list_to_integer(string:trim(binary_to_list(Bin)))
            catch _:_ -> 0
            end;
        _ -> 0
    end.

read_all_veth_stats(Veth) ->
    Stats = [rx_bytes, rx_packets, rx_dropped, rx_errors,
             tx_bytes, tx_packets, tx_dropped, tx_errors],
    maps:from_list([{S, read_veth_stat(Veth, atom_to_list(S))} || S <- Stats]).

format_cpu(Usec) when is_integer(Usec) ->
    %% Show as seconds with 1 decimal
    Secs = Usec / 1_000_000,
    lists:flatten(io_lib:format("~.1fs", [Secs]));
format_cpu(_) -> "-".

format_bytes(B) when is_integer(B), B >= 1_073_741_824 ->
    lists:flatten(io_lib:format("~.1fG", [B / 1_073_741_824]));
format_bytes(B) when is_integer(B), B >= 1_048_576 ->
    lists:flatten(io_lib:format("~.1fM", [B / 1_048_576]));
format_bytes(B) when is_integer(B), B >= 1024 ->
    lists:flatten(io_lib:format("~.1fK", [B / 1024]));
format_bytes(B) when is_integer(B) ->
    integer_to_list(B) ++ "B";
format_bytes(_) -> "-".

state_color(running) -> ?GREEN;
state_color(stopped) -> ?RED;
state_color(failed) -> ?RED;
state_color(restarting) -> ?YELLOW;
state_color(creating) -> ?YELLOW;
state_color(_) -> "".

print_kv(Key, Value) ->
    io:format("  ~s~-18s~s ~s~n", [?DIM, Key, ?RESET, to_str_safe(Value)]).

to_str_safe(V) when is_binary(V) -> binary_to_list(V);
to_str_safe(V) when is_list(V) -> lists:flatten(V);
to_str_safe(V) when is_atom(V) -> atom_to_list(V);
to_str_safe(V) when is_integer(V) -> integer_to_list(V);
to_str_safe(V) -> lists:flatten(io_lib:format("~p", [V])).

print_error(Fmt, Args) ->
    io:format("  " ?RED ++ Fmt ++ ?RESET "~n", Args),
    ok.

%%====================================================================
%% capture/1 — Capture io:format output as a string.
%%
%% Runs Fun in the calling process with a temporary group_leader
%% that collects all io_request messages. Returns the collected
%% output as a flat string.
%%
%% Use case: ek:capture(fun() -> ek:ps() end). via eval/rpc
%%====================================================================

-spec capture(fun(() -> term())) -> string().
capture(Fun) ->
    Self = self(),
    GL = group_leader(),
    Collector = spawn_link(fun() -> capture_loop([]) end),
    group_leader(Collector, Self),
    try Fun()
    after group_leader(GL, Self)
    end,
    Collector ! {get, Self},
    receive {capture_result, R} -> R end.

capture_loop(Acc) ->
    receive
        {io_request, From, ReplyAs, {put_chars, _, Chars}} ->
            From ! {io_reply, ReplyAs, ok},
            capture_loop([Acc, Chars]);
        {io_request, From, ReplyAs, {put_chars, _, M, F, A}} ->
            Str = apply(M, F, A),
            From ! {io_reply, ReplyAs, ok},
            capture_loop([Acc, Str]);
        {io_request, From, ReplyAs, _} ->
            From ! {io_reply, ReplyAs, ok},
            capture_loop(Acc);
        {get, Pid} ->
            Pid ! {capture_result,
                   unicode:characters_to_list(iolist_to_binary(Acc))}
    end.
