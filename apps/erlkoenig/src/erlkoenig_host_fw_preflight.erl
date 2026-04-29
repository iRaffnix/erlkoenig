%%%-------------------------------------------------------------------
%%% @doc Host firewall lockout preflight.
%%%
%%% Inspects a parsed config term BEFORE it is applied. If the stack
%%% would take over the host firewall with `policy: drop' on the input
%%% chain and would not explicitly accept the operator's currently
%%% live SSH listener port(s), the preflight emits one or more
%%% findings and the caller is expected to abort the load — unless
%%% the operator passed an explicit override.
%%%
%%% Scope (v1, intentionally narrow):
%%%   - Only `nft_tables' with name `<<"host">>' and a chain on
%%%     hook=input with policy=drop is considered.
%%%   - Only `tcp_dport' accept-rules count toward the SSH whitelist.
%%%     Source-IP allowlists (`ip_saddr') are out of scope: this is
%%%     glasbox-friendly (operator must declare the port explicitly)
%%%     and avoids assuming we know the operator's source IP.
%%%   - SSH-port detection is best-effort: `ss', then `sshd -T',
%%%     then `/etc/ssh/sshd_config'. If none find anything, the
%%%     verdict is `no_concern' (we are not going to refuse all
%%%     host-fw stacks just because the daemon could not probe).
%%%   - Honeypot collision (current SSH port appears in
%%%     `ct_guard.honeypot_ports') produces an additional finding,
%%%     which is harder than a plain accept-list miss because
%%%     reconnects can result in time-bounded operator-IP bans.
%%%
%%% Out of scope for v1: operator-source-IP discovery, ip_saddr
%%% allowlist semantics, BPF/devfilter analysis. Tracked in
%%% docs/ARCHITECTURE_BACKLOG.md.
%%% @end
%%%-------------------------------------------------------------------
-module(erlkoenig_host_fw_preflight).

-export([analyze/1, analyze/2]).
-export([format_findings/1]).
-export([probe_ssh_ports/0]).

-type ssh_port()    :: 1..65535.
-type accepted()    :: [ssh_port()].
-type honeypot()    :: [ssh_port()].
-type finding()     :: #{kind    := atom(),
                         port    := ssh_port(),
                         detail  := binary(),
                         _       => term()}.
-type verdict()     :: {ok, no_concern}
                     | {abort, [finding(), ...]}.

%%====================================================================
%% Public API
%%====================================================================

-doc """
Analyze a parsed config map. SSH listening ports are probed from the
local host. Returns `{ok, no_concern}' or `{abort, Findings}'.
""".
-spec analyze(map()) -> verdict().
analyze(Config) ->
    analyze(Config, probe_ssh_ports()).

-doc """
Test-friendly variant: caller supplies the SSH listening port list.
With an empty list, the verdict is always `no_concern' — there is
nothing to lock out.
""".
-spec analyze(map(), [ssh_port()]) -> verdict().
analyze(_Config, []) ->
    {ok, no_concern};
analyze(Config, SshPorts) when is_map(Config) ->
    case host_input_drop_chain(Config) of
        none ->
            {ok, no_concern};
        {ok, AcceptedDports} ->
            HoneypotPorts = honeypot_ports(Config),
            classify(SshPorts, AcceptedDports, HoneypotPorts)
    end.

-doc """
Render findings into a human-readable iolist. Used by the
config-load entry to surface diagnostics in the operator's terminal
when the abort fires.
""".
-spec format_findings([finding()]) -> iolist().
format_findings(Findings) ->
    [format_finding(F) || F <- Findings].

%%====================================================================
%% DSL term traversal
%%====================================================================

-spec host_input_drop_chain(map()) -> none | {ok, accepted()}.
host_input_drop_chain(Config) ->
    NftTables = maps:get(nft_tables, Config, []),
    case host_table(NftTables) of
        none ->
            none;
        {ok, HostTable} ->
            Chains = maps:get(chains, HostTable, []),
            case input_drop_chain(Chains) of
                none ->
                    none;
                {ok, Chain} ->
                    {ok, accepted_tcp_dports(maps:get(rules, Chain, []))}
            end
    end.

host_table([]) ->
    none;
host_table([T | Rest]) when is_map(T) ->
    case maps:get(name, T, undefined) of
        <<"host">> -> {ok, T};
        _          -> host_table(Rest)
    end;
host_table([_ | Rest]) ->
    host_table(Rest).

input_drop_chain([]) ->
    none;
input_drop_chain([Ch | Rest]) when is_map(Ch) ->
    case {maps:get(hook, Ch, undefined), maps:get(policy, Ch, undefined)} of
        {input, drop} -> {ok, Ch};
        _             -> input_drop_chain(Rest)
    end;
input_drop_chain([_ | Rest]) ->
    input_drop_chain(Rest).

-spec accepted_tcp_dports(list()) -> accepted().
accepted_tcp_dports(Rules) ->
    lists:usort(
      lists:flatmap(
        fun ({accept, M}) when is_map(M) ->
                case maps:get(tcp_dport, M, undefined) of
                    P when is_integer(P), P > 0, P =< 65535 -> [P];
                    _                                       -> []
                end;
            (_) ->
                []
        end, Rules)).

-spec honeypot_ports(map()) -> honeypot().
honeypot_ports(Config) ->
    case maps:find(ct_guard, Config) of
        {ok, Guard} when is_map(Guard) ->
            Ports = maps:get(honeypot_ports, Guard, []),
            [P || P <- Ports, is_integer(P), P > 0, P =< 65535];
        _ ->
            []
    end.

%%====================================================================
%% Classification
%%====================================================================

-spec classify([ssh_port()], accepted(), honeypot()) -> verdict().
classify(SshPorts, AcceptedDports, HoneypotPorts) ->
    Findings =
        [ #{kind    => ssh_port_not_accepted,
            port    => P,
            accepted => AcceptedDports,
            detail  => iolist_to_binary(io_lib:format(
                "SSH listens on ~w but the host input chain (policy=drop) "
                "does not accept tcp_dport=~w; reconnects will be dropped",
                [P, P]))}
          || P <- SshPorts, not lists:member(P, AcceptedDports)
        ]
     ++ [ #{kind    => ssh_port_in_honeypot,
            port    => P,
            detail  => iolist_to_binary(io_lib:format(
                "SSH listens on ~w which is also in ct_guard.honeypot_ports; "
                "reconnects to this port can result in time-bounded operator-IP bans",
                [P]))}
          || P <- SshPorts, lists:member(P, HoneypotPorts)
        ],
    case Findings of
        []  -> {ok, no_concern};
        _   -> {abort, Findings}
    end.

%%====================================================================
%% SSH port detection
%%====================================================================

-doc """
Probe local SSH listening port(s). Tries `ss', then `sshd -T', then
`/etc/ssh/sshd_config'. Returns a sorted unique list. Empty list
means we could not find anything — the caller should treat that as
`no_concern' (best effort).
""".
-spec probe_ssh_ports() -> [ssh_port()].
probe_ssh_ports() ->
    Probes = [fun probe_via_ss/0,
              fun probe_via_sshd_T/0,
              fun probe_via_sshd_config/0],
    first_nonempty(Probes).

first_nonempty([]) ->
    [];
first_nonempty([Probe | Rest]) ->
    case catch Probe() of
        L when is_list(L), L =/= [] -> lists:usort(L);
        _                           -> first_nonempty(Rest)
    end.

%%--------------------------------------------------------------------
%% probe_via_ss: parse `ss -tlnp' output, look for sshd processes.
%% Format (kernel-dependent but stable across modern util-linux):
%%
%%   State  Recv-Q  Send-Q  Local Address:Port  Peer ...  Process
%%   LISTEN 0       128     0.0.0.0:22          0.0.0.0:* users:(("sshd",pid=...))
%%   LISTEN 0       128     [::]:22             [::]:*    users:(("sshd",pid=...))
%%--------------------------------------------------------------------
probe_via_ss() ->
    Out = os_cmd_safe("ss -tlnp 2>/dev/null"),
    Lines = string:split(Out, "\n", all),
    lists:flatten(
      [parse_ss_line(L) || L <- Lines, contains_sshd(L)]).

contains_sshd(Line) ->
    string:str(Line, "sshd") > 0.

parse_ss_line(Line) ->
    Tokens = string:tokens(Line, " \t"),
    case Tokens of
        [_State, _RecvQ, _SendQ, BindPort | _] ->
            extract_port(BindPort);
        _ ->
            []
    end.

%%--------------------------------------------------------------------
%% probe_via_sshd_T: ask sshd itself. `sshd -T' prints the resolved
%% effective config one key per line.
%%
%%   port 22
%%   port 2222    (multiple)
%%--------------------------------------------------------------------
probe_via_sshd_T() ->
    Out = os_cmd_safe("sshd -T 2>/dev/null"),
    Lines = string:split(Out, "\n", all),
    lists:flatten(
      [extract_sshd_T_port(L) || L <- Lines]).

extract_sshd_T_port(Line) ->
    case string:tokens(Line, " \t") of
        ["port", PortStr | _] ->
            case string:to_integer(PortStr) of
                {P, ""} when P > 0, P =< 65535 -> [P];
                _                              -> []
            end;
        _ ->
            []
    end.

%%--------------------------------------------------------------------
%% probe_via_sshd_config: last resort, parse /etc/ssh/sshd_config.
%% Misses Match-block overrides and Include directives — accepted
%% best-effort cost in v1.
%%--------------------------------------------------------------------
probe_via_sshd_config() ->
    case file:read_file("/etc/ssh/sshd_config") of
        {ok, Bin} ->
            parse_sshd_config_ports(Bin);
        _ ->
            []
    end.

parse_sshd_config_ports(Bin) ->
    Lines = string:split(binary_to_list(Bin), "\n", all),
    lists:flatten([parse_sshd_config_line(L) || L <- Lines]).

parse_sshd_config_line(Line) ->
    Trimmed = string:trim(Line),
    case Trimmed of
        "#" ++ _ -> [];
        ""       -> [];
        _ ->
            case string:tokens(Trimmed, " \t") of
                [Key, PortStr | _] ->
                    case string:lowercase(Key) of
                        "port" ->
                            case string:to_integer(PortStr) of
                                {P, ""} when P > 0, P =< 65535 -> [P];
                                _                              -> []
                            end;
                        _ ->
                            []
                    end;
                _ ->
                    []
            end
    end.

%%--------------------------------------------------------------------
%% extract_port(BindPort): handle "0.0.0.0:22", "[::]:22", "*:22",
%% "127.0.0.1:2222". Strategy: take the suffix after the last colon,
%% parse as integer.
%%--------------------------------------------------------------------
extract_port(BindPort) when is_list(BindPort) ->
    case string:split(BindPort, ":", trailing) of
        [_, PortStr] ->
            case string:to_integer(PortStr) of
                {P, ""} when P > 0, P =< 65535 -> [P];
                _                              -> []
            end;
        _ ->
            []
    end.

%%--------------------------------------------------------------------
%% os_cmd_safe: os:cmd/1 wrapper that returns "" on errors.
%%--------------------------------------------------------------------
os_cmd_safe(Cmd) ->
    case catch os:cmd(Cmd) of
        Out when is_list(Out) -> Out;
        _                     -> ""
    end.

%%====================================================================
%% Output formatting
%%====================================================================

format_finding(#{kind := ssh_port_not_accepted, port := P,
                 accepted := Accepted, detail := D}) ->
    io_lib:format(
      "  [LOCKOUT-RISK] ssh-port ~w not in input-chain accept-list "
      "(accepted: ~w)~n        ~ts~n",
      [P, Accepted, D]);
format_finding(#{kind := ssh_port_in_honeypot, port := P, detail := D}) ->
    io_lib:format(
      "  [HONEYPOT-COLLISION] ssh-port ~w is in ct_guard.honeypot_ports~n"
      "        ~ts~n",
      [P, D]).
