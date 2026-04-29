%%%-------------------------------------------------------------------
%%% @doc Unit tests for erlkoenig_host_fw_preflight.
%%%
%%% Exercises analyze/2 against synthetic configs that mirror the
%%% term shape produced by the DSL compiler. Live SSH probing is
%%% not exercised here — that's a separate integration concern.
%%% @end
%%%-------------------------------------------------------------------
-module(erlkoenig_host_fw_preflight_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Empty / no-host-fw configs → no_concern
%%====================================================================

empty_config_no_concern_test() ->
    ?assertEqual({ok, no_concern},
                 erlkoenig_host_fw_preflight:analyze(#{}, [22])).

no_nft_tables_no_concern_test() ->
    ?assertEqual({ok, no_concern},
                 erlkoenig_host_fw_preflight:analyze(
                   #{pods => [], zones => []}, [22])).

no_host_table_no_concern_test() ->
    Cfg = #{nft_tables => [#{name => <<"erlkoenig">>, chains => []}]},
    ?assertEqual({ok, no_concern},
                 erlkoenig_host_fw_preflight:analyze(Cfg, [22])).

host_table_without_input_drop_no_concern_test() ->
    Cfg = #{nft_tables => [#{name => <<"host">>,
                             chains => [#{name => <<"input">>,
                                          hook => input,
                                          policy => accept,
                                          rules => []}]}]},
    ?assertEqual({ok, no_concern},
                 erlkoenig_host_fw_preflight:analyze(Cfg, [22])).

%%====================================================================
%% No probed SSH ports → caller cannot make a verdict
%%====================================================================

empty_ssh_ports_no_concern_test() ->
    Cfg = host_input_drop_with_dport(22222),
    ?assertEqual({ok, no_concern},
                 erlkoenig_host_fw_preflight:analyze(Cfg, [])).

%%====================================================================
%% Host-FW examples — abort on lockout-risk
%%====================================================================

ssh_port_not_in_dport_whitelist_aborts_test() ->
    Cfg = host_input_drop_with_dport(22222),
    {abort, Findings} =
        erlkoenig_host_fw_preflight:analyze(Cfg, [22]),
    ?assertMatch([#{kind := ssh_port_not_accepted, port := 22} | _],
                 Findings).

ssh_port_in_dport_whitelist_passes_test() ->
    Cfg = host_input_drop_with_dport(22),
    ?assertEqual({ok, no_concern},
                 erlkoenig_host_fw_preflight:analyze(Cfg, [22])).

%% Multi-port sshd (e.g. 22 + 2222) — even if ONE is whitelisted,
%% the other counts as drift.
multi_ssh_one_whitelisted_one_not_test() ->
    Cfg = host_input_drop_with_dport(22),
    {abort, Findings} =
        erlkoenig_host_fw_preflight:analyze(Cfg, [22, 2222]),
    Ports = [maps:get(port, F) || F <- Findings,
                                  maps:get(kind, F) =:= ssh_port_not_accepted],
    ?assertEqual([2222], Ports).

empty_input_chain_with_drop_aborts_test() ->
    %% policy=drop with zero accept rules — full lockout.
    Cfg = #{nft_tables => [#{name => <<"host">>,
                             chains => [#{name => <<"input">>,
                                          hook => input,
                                          policy => drop,
                                          rules => []}]}]},
    {abort, [#{kind := ssh_port_not_accepted}]} =
        erlkoenig_host_fw_preflight:analyze(Cfg, [22]).

%%====================================================================
%% Honeypot collision — extra hard finding
%%====================================================================

ssh_port_in_honeypot_extra_finding_test() ->
    %% tutorial.exs pattern: SSH on 22, host accepts only 22222,
    %% guard honeypots include 22 → two findings.
    Cfg = (host_input_drop_with_dport(22222))#{
        ct_guard => #{honeypot_ports => [21, 22, 23, 445]}},
    {abort, Findings} =
        erlkoenig_host_fw_preflight:analyze(Cfg, [22]),
    Kinds = lists:sort([maps:get(kind, F) || F <- Findings]),
    ?assertEqual([ssh_port_in_honeypot, ssh_port_not_accepted], Kinds).

honeypot_only_when_listed_test() ->
    %% SSH on 22, host accepts 22, guard honeypots SSH port → still a
    %% finding because reconnect would be banned.
    Cfg = (host_input_drop_with_dport(22))#{
        ct_guard => #{honeypot_ports => [22]}},
    {abort, [#{kind := ssh_port_in_honeypot, port := 22}]} =
        erlkoenig_host_fw_preflight:analyze(Cfg, [22]).

honeypot_unrelated_port_no_finding_test() ->
    %% Honeypot list does not include the SSH port — only the missing
    %% accept finding fires (or none if accept matches).
    Cfg = (host_input_drop_with_dport(22))#{
        ct_guard => #{honeypot_ports => [21, 23]}},
    ?assertEqual({ok, no_concern},
                 erlkoenig_host_fw_preflight:analyze(Cfg, [22])).

%%====================================================================
%% Defensive: malformed entries don't crash
%%====================================================================

non_integer_dport_ignored_test() ->
    Cfg = #{nft_tables => [
                #{name => <<"host">>,
                  chains => [#{name => <<"input">>,
                               hook => input,
                               policy => drop,
                               rules => [
                                   {accept, #{tcp_dport => "garbage"}},
                                   {accept, #{tcp_dport => 99999}},  %% out of range
                                   {accept, #{tcp_dport => 22}}
                               ]}]}]},
    ?assertEqual({ok, no_concern},
                 erlkoenig_host_fw_preflight:analyze(Cfg, [22])).

malformed_table_skipped_test() ->
    Cfg = #{nft_tables => [
                not_a_map,
                #{name => <<"host">>,
                  chains => [#{name => <<"input">>,
                               hook => input,
                               policy => drop,
                               rules => [{accept, #{tcp_dport => 22}}]}]}]},
    ?assertEqual({ok, no_concern},
                 erlkoenig_host_fw_preflight:analyze(Cfg, [22])).

%%====================================================================
%% format_findings/1 produces non-empty iolist
%%====================================================================

format_findings_renders_test() ->
    {abort, Findings} =
        erlkoenig_host_fw_preflight:analyze(
          host_input_drop_with_dport(22222), [22]),
    Out = iolist_to_binary(
            erlkoenig_host_fw_preflight:format_findings(Findings)),
    ?assert(byte_size(Out) > 0),
    ?assert(binary:match(Out, <<"LOCKOUT-RISK">>) =/= nomatch).

%%====================================================================
%% helpers
%%====================================================================

host_input_drop_with_dport(Dport) ->
    #{nft_tables => [
          #{name => <<"host">>,
            chains => [
                #{name => <<"input">>,
                  hook => input,
                  policy => drop,
                  rules => [
                      {accept, #{ct_state => [established, related]}},
                      {accept, #{iifname => <<"lo">>}},
                      {accept, #{ip_protocol => icmp}},
                      {accept, #{tcp_dport => Dport}}
                  ]}]}]}.
