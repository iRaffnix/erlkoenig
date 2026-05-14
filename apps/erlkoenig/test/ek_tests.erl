%%%-------------------------------------------------------------------
%%% @doc Unit tests for ek (Operator Shell).
%%%
%%% Tests the pure formatting functions (format_bytes, format_cpu,
%%% format_ip4, to_bin, to_str, state_color) without needing running
%%% containers or the full OTP application.
%%% @end
%%%-------------------------------------------------------------------

-module(ek_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%% ek's formatting functions are not exported, so we test them
%% indirectly by calling the module and capturing io output, or
%% by reimplementing the pure logic for verification.

%% =================================================================
%% format_bytes (reimplemented for unit testing)
%% =================================================================

%% Since format_bytes is internal, we verify the logic directly.

format_bytes(B) when is_integer(B), B >= 1_073_741_824 ->
    lists:flatten(io_lib:format("~.1fG", [B / 1_073_741_824]));
format_bytes(B) when is_integer(B), B >= 1_048_576 ->
    lists:flatten(io_lib:format("~.1fM", [B / 1_048_576]));
format_bytes(B) when is_integer(B), B >= 1024 ->
    lists:flatten(io_lib:format("~.1fK", [B / 1024]));
format_bytes(B) when is_integer(B) ->
    integer_to_list(B) ++ "B";
format_bytes(_) -> "-".

format_bytes_bytes_test() ->
    ?assertEqual("0B", format_bytes(0)),
    ?assertEqual("512B", format_bytes(512)),
    ?assertEqual("1023B", format_bytes(1023)).

format_bytes_kilobytes_test() ->
    ?assertEqual("1.0K", format_bytes(1024)),
    ?assertEqual("1.5K", format_bytes(1536)),
    ?assertEqual("1024.0K", format_bytes(1_048_575)).

format_bytes_megabytes_test() ->
    ?assertEqual("1.0M", format_bytes(1_048_576)),
    ?assertEqual("48.2M", format_bytes(50_529_028)),
    ?assertEqual("512.0M", format_bytes(536_870_912)).

format_bytes_gigabytes_test() ->
    ?assertEqual("1.0G", format_bytes(1_073_741_824)),
    ?assertEqual("2.5G", format_bytes(2_684_354_560)).

format_bytes_non_integer_test() ->
    ?assertEqual("-", format_bytes(undefined)),
    ?assertEqual("-", format_bytes(nil)).

%% =================================================================
%% format_cpu (reimplemented for unit testing)
%% =================================================================

format_cpu(Usec) when is_integer(Usec) ->
    Secs = Usec / 1_000_000,
    lists:flatten(io_lib:format("~.1fs", [Secs]));
format_cpu(_) -> "-".

format_cpu_zero_test() ->
    ?assertEqual("0.0s", format_cpu(0)).

format_cpu_subsecond_test() ->
    ?assertEqual("0.5s", format_cpu(500_000)).

format_cpu_seconds_test() ->
    ?assertEqual("142.3s", format_cpu(142_300_000)).

format_cpu_large_test() ->
    ?assertEqual("891.5s", format_cpu(891_500_000)).

format_cpu_undefined_test() ->
    ?assertEqual("-", format_cpu(undefined)).

%% =================================================================
%% format_ip4 (reimplemented for unit testing)
%% =================================================================

format_ip4({A, B, C, D}) ->
    lists:flatten(io_lib:format("~p.~p.~p.~p", [A, B, C, D])).

format_ip4_test() ->
    ?assertEqual("10.0.0.10", format_ip4({10, 0, 0, 10})),
    ?assertEqual("192.168.1.1", format_ip4({192, 168, 1, 1})),
    ?assertEqual("0.0.0.0", format_ip4({0, 0, 0, 0})),
    ?assertEqual("255.255.255.255", format_ip4({255, 255, 255, 255})).

%% =================================================================
%% to_bin / to_str (reimplemented for unit testing)
%% =================================================================

to_bin(Name) when is_atom(Name) -> atom_to_binary(Name);
to_bin(Name) when is_list(Name) -> list_to_binary(Name);
to_bin(Name) when is_binary(Name) -> Name.

to_str(Name) when is_atom(Name) -> atom_to_list(Name);
to_str(Name) when is_binary(Name) -> binary_to_list(Name);
to_str(Name) when is_list(Name) -> Name.

to_bin_atom_test() ->
    ?assertEqual(<<"web">>, to_bin(web)).

to_bin_binary_test() ->
    ?assertEqual(<<"web">>, to_bin(<<"web">>)).

to_bin_string_test() ->
    ?assertEqual(<<"web">>, to_bin("web")).

to_str_atom_test() ->
    ?assertEqual("web", to_str(web)).

to_str_binary_test() ->
    ?assertEqual("web", to_str(<<"web">>)).

to_str_string_test() ->
    ?assertEqual("web", to_str("web")).

%% All three input types resolve to the same value
name_resolution_equivalence_test() ->
    ?assertEqual(to_bin(web), to_bin(<<"web">>)),
    ?assertEqual(to_bin(web), to_bin("web")),
    ?assertEqual(to_str(web), to_str(<<"web">>)),
    ?assertEqual(to_str(web), to_str("web")).

%% =================================================================
%% state_color
%% =================================================================

%% Verify state_color returns non-empty ANSI for known states.
state_color(running)    -> "\e[32m";
state_color(stopped)    -> "\e[31m";
state_color(failed)     -> "\e[31m";
state_color(restarting) -> "\e[33m";
state_color(creating)   -> "\e[33m";
state_color(_)          -> "".

state_color_running_test() ->
    ?assertEqual("\e[32m", state_color(running)).

state_color_stopped_test() ->
    ?assertEqual("\e[31m", state_color(stopped)).

state_color_failed_test() ->
    ?assertEqual("\e[31m", state_color(failed)).

state_color_restarting_test() ->
    ?assertEqual("\e[33m", state_color(restarting)).

state_color_unknown_test() ->
    ?assertEqual("", state_color(something_else)).

%% =================================================================
%% help output (smoke test via io capture)
%% =================================================================

help_output_test() ->
    %% Capture io output from ek:help/0
    OldGL = group_leader(),
    CaptPid = spawn_link(fun() -> io_server_loop([]) end),
    group_leader(CaptPid, self()),
    ok = ek:help(),
    group_leader(OldGL, self()),
    Output = io_capture_get(CaptPid),
    %% ANSI codes are embedded, so match substrings that appear in the output
    ?assert(string:find(Output, "Operator Shell") =/= nomatch),
    ?assert(string:find(Output, "ek:ps()") =/= nomatch),
    ?assert(string:find(Output, "ek:inspect") =/= nomatch),
    ?assert(string:find(Output, "ek:logs") =/= nomatch),
    ?assert(string:find(Output, "ek:events") =/= nomatch).

events_print_current_lifecycle_tuples_test() ->
    Cases = [
        {{container_started, <<"id1">>, <<"web">>, self()}, "[started]", "id1/web"},
        {{container_stopped, <<"id2">>, <<"api">>, #{exit_code => 0}}, "[stopped]", "id2/api"},
        {{container_failed, <<"id3">>, <<"worker">>, timeout}, "[failed]", "id3/worker"},
        {{container_restarting, <<"id4">>, <<"job">>, 2}, "[restart]", "id4/job"},
        {{container_oom, <<"id5">>, <<"db">>}, "[oom]", "id5/db"}
    ],
    lists:foreach(fun({Event, Label, IdName}) ->
        Output = capture_print_event(Event),
        ?assert(string:find(Output, Label) =/= nomatch),
        ?assert(string:find(Output, IdName) =/= nomatch),
        ?assertEqual(nomatch, string:find(Output, "[event]"))
    end, Cases).

events_print_legacy_lifecycle_tuples_test() ->
    Output = capture_print_event({container_failed, <<"id3">>, timeout}),
    ?assert(string:find(Output, "[failed]") =/= nomatch),
    ?assert(string:find(Output, "id3") =/= nomatch),
    ?assertEqual(nomatch, string:find(Output, "[event]")).

%% =================================================================
%% ek.escript explain
%% =================================================================

escript_explain_plain_test() ->
    {0, Output} = run_ek_escript(["explain", "EK_CT_SPAWN_TIMEOUT"]),
    ?assert(string:find(Output, "EK_CT_SPAWN_TIMEOUT") =/= nomatch),
    ?assert(string:find(Output, "component: ct") =/= nomatch),
    ?assert(string:find(Output, "operator action:") =/= nomatch),
    ?assert(string:find(Output, "evidence fields you will see:") =/= nomatch).

escript_explain_accepts_code_without_prefix_test() ->
    {0, Output} = run_ek_escript(["explain", "CT_SPAWN_TIMEOUT"]),
    ?assert(string:find(Output, "EK_CT_SPAWN_TIMEOUT") =/= nomatch).

escript_explain_json_test() ->
    {0, Output} = run_ek_escript(["--format", "json", "explain", "EK_CT_SPAWN_TIMEOUT"]),
    Json = json:decode(list_to_binary(Output)),
    ?assertEqual(<<"EK_CT_SPAWN_TIMEOUT">>, maps:get(<<"code">>, Json)),
    ?assertEqual(<<"ct">>, maps:get(<<"component">>, Json)).

escript_explain_critical_includes_iron_rule_test() ->
    {0, Output} = run_ek_escript(["explain", "EK_AUDIT_CHAIN_BROKEN"]),
    ?assert(string:find(Output, "severity:  critical") =/= nomatch),
    ?assert(string:find(Output, "iron rule:") =/= nomatch).

escript_explain_list_test() ->
    {0, Output} = run_ek_escript(["explain", "--list"]),
    ?assert(string:find(Output, "EK_CT_SPAWN_TIMEOUT") =/= nomatch),
    ?assert(string:find(Output, "EK_AUDIT_CHAIN_BROKEN") =/= nomatch),
    ?assert(string:find(Output, "description") =/= nomatch).

escript_explain_component_filter_test() ->
    {0, Output} = run_ek_escript(["explain", "--component", "ct"]),
    ?assert(string:find(Output, "EK_CT_SPAWN_TIMEOUT") =/= nomatch),
    ?assertEqual(nomatch, string:find(Output, "EK_AUDIT_CHAIN_BROKEN")).

escript_explain_list_json_test() ->
    {0, Output} = run_ek_escript(["--format", "json", "explain", "--component", "audit"]),
    Rows = json:decode(list_to_binary(Output)),
    ?assert(is_list(Rows)),
    ?assert(lists:any(fun(#{<<"code">> := <<"EK_AUDIT_CHAIN_BROKEN">>}) -> true;
                         (_) -> false
                      end, Rows)),
    ?assert(lists:all(fun(#{<<"component">> := <<"audit">>}) -> true;
                         (_) -> false
                      end, Rows)).

escript_explain_unknown_code_fails_test() ->
    {Status, Output} = run_ek_escript(["explain", "DOES_NOT_EXIST"]),
    ?assertNotEqual(0, Status),
    ?assert(string:find(Output, "unknown error code") =/= nomatch).

escript_unknown_command_is_usage_error_test() ->
    {Status, Output} = run_ek_escript(["does-not-exist"]),
    ?assertEqual(2, Status),
    ?assert(string:find(Output, "unknown command") =/= nomatch).

escript_bad_quarantine_hash_is_usage_error_test() ->
    {Status, Output} = run_ek_escript(["quarantine", "add", "nothex"]),
    ?assertEqual(2, Status),
    ?assert(string:find(Output, "quarantine hash must be hex-encoded") =/= nomatch).

escript_down_without_args_is_usage_error_test() ->
    {Status, Output} = run_ek_escript(["down"]),
    ?assertEqual(2, Status),
    ?assert(string:find(Output, "down requires") =/= nomatch),
    ?assert(string:find(Output, "--all") =/= nomatch).

escript_down_all_uses_operator_api_test() ->
    Path = write_operator_api_mock(#{
        container_list => {ok, [#{name => <<"alpha">>},
                                #{name => <<"beta">>}]},
        container_stop => ok
    }),
    {Status, Output} = run_ek_escript(
        ["down", "--all"],
        [{"ERLKOENIG_EK_MOCK_OPERATOR_API", Path}]),
    ?assertEqual(0, Status),
    ?assert(string:find(Output, "stopped 2/2") =/= nomatch),
    ?assertEqual([{container_list, []},
                  {container_stop, [<<"alpha">>]},
                  {container_stop, [<<"beta">>]}],
                 read_operator_api_mock_calls(Path)).

escript_vol_destroy_without_yes_is_usage_error_test() ->
    {Status, Output} = run_ek_escript(["vol", "destroy", "ek_vol_test"]),
    ?assertEqual(2, Status),
    ?assert(string:find(Output, "--yes") =/= nomatch).

escript_vol_destroy_yes_uses_operator_api_test() ->
    Path = write_operator_api_mock(#{volume_destroy => ok}),
    {Status, Output} = run_ek_escript(
        ["vol", "destroy", "ek_vol_test", "--yes"],
        [{"ERLKOENIG_EK_MOCK_OPERATOR_API", Path}]),
    ?assertEqual(0, Status),
    ?assert(string:find(Output, "destroyed ek_vol_test") =/= nomatch),
    ?assertEqual([{volume_destroy, [<<"ek_vol_test">>]}],
                 read_operator_api_mock_calls(Path)).

escript_version_option_test() ->
    assert_cli_version(["--version"]).

escript_short_version_option_test() ->
    assert_cli_version(["-V"]).

escript_version_verb_test() ->
    assert_cli_version(["version"]).

escript_version_json_format_test() ->
    {Status, Output} = run_ek_escript(["--format", "json", "--version"]),
    ?assertEqual(0, Status),
    Decoded = json:decode(list_to_binary(Output)),
    ?assertMatch(#{<<"version">> := <<_/binary>>}, Decoded),
    ?assertMatch({match, _},
                 re:run(maps:get(<<"version">>, Decoded),
                        "^[0-9]+\\.[0-9]+\\.[0-9]+$")).

escript_down_all_partial_failure_single_message_test() ->
    Path = write_operator_api_mock(#{
        container_list => {ok, [#{name => <<"alpha">>},
                                #{name => <<"beta">>},
                                #{name => <<"gamma">>}]},
        container_stop => {error, #{code => 'EK_OPERATOR_INTERNAL',
                                    data => #{op => container_stop,
                                              raw => boom}}}
    }),
    {Status, Output} = run_ek_escript(
        ["down", "--all"],
        [{"ERLKOENIG_EK_MOCK_OPERATOR_API", Path}]),
    ?assertEqual(1, Status),
    %% Old behavior printed both "stopped 0/3" AND "failed for 3/3";
    %% the consolidated message must NOT contain "down: stopped".
    ?assertEqual(nomatch, string:find(Output, "down: stopped")),
    ?assert(string:find(Output, "stopped 0/3") =/= nomatch),
    ?assert(string:find(Output, "3 failed") =/= nomatch).

%% =================================================================
%% JSON Output Contract — see dist/ek.escript JSON Output Contract
%% block and docs/CLI.md "JSON Output Contract".
%% =================================================================

json_ct_list_normalizes_ip_tuple_and_state_test() ->
    Path = write_operator_api_mock(#{
        container_list => {ok, [
            #{name => <<"web">>, id => <<"id-1">>,
              state => running, restart_count => 2,
              zone => <<"dmz">>,
              net_info => #{ip => {10,10,0,2}, netmask => 24,
                            zone => <<"dmz">>}}
        ]}}),
    {0, Output} = run_ek_escript(
        ["--format", "json", "ct", "list"],
        [{"ERLKOENIG_EK_MOCK_OPERATOR_API", Path}]),
    [Row] = json:decode(list_to_binary(Output)),
    ?assertEqual(<<"web">>,    maps:get(<<"name">>, Row)),
    ?assertEqual(<<"running">>, maps:get(<<"state">>, Row)),
    ?assertEqual(<<"10.10.0.2">>, maps:get(<<"ip">>, Row)),
    ?assertEqual(<<"dmz">>, maps:get(<<"zone">>, Row)),
    ?assertEqual(2, maps:get(<<"restart_count">>, Row)).

json_ct_list_emits_null_for_missing_ip_test() ->
    Path = write_operator_api_mock(#{
        container_list => {ok, [
            #{name => <<"orphan">>, state => failed,
              restart_count => 0, zone => <<"dmz">>}
        ]}}),
    {0, Output} = run_ek_escript(
        ["--format", "json", "ct", "list"],
        [{"ERLKOENIG_EK_MOCK_OPERATOR_API", Path}]),
    [Row] = json:decode(list_to_binary(Output)),
    ?assertEqual(null, maps:get(<<"ip">>, Row)),
    ?assertEqual(<<"failed">>, maps:get(<<"state">>, Row)).

json_ct_inspect_full_shape_test() ->
    Info = #{
        id            => <<"id-42">>,
        name          => <<"web-0-nginx">>,
        binary        => <<"/opt/erlkoenig/rt/nginx">>,
        zone          => <<"dmz">>,
        state         => running,
        seccomp       => default,
        restart       => always,
        os_pid        => 12345,
        restart_count => 0,
        netns_path    => <<"/proc/12345/ns/net">>,
        socket_path   => <<"/run/erlkoenig/containers/id-42.sock">>,
        handshake     => true,
        args          => [<<"-p">>, <<"7777">>],
        ports         => [],
        caps          => [],
        volumes       => [
            #{uuid => <<"ek_vol_1">>,
              host => <<"/var/lib/erlkoenig/volumes/ek_vol_1">>,
              container => <<"/data">>,
              persist => <<"primary-data">>,
              read_only => false,
              lifecycle => persistent}
        ],
        net_info      => #{ip => {10,10,0,2}, netmask => 24,
                           zone => <<"dmz">>, ifname => <<"vm0">>},
        stats         => #{memory_bytes => 921600, cpu_usec => 2839,
                           pids_current => 3, memory_peak => 1404928},
        limits        => #{memory => 128000000, pids => 64},
        exit_info     => undefined,
        error         => undefined
    },
    Path = write_operator_api_mock(#{container_inspect => {ok, Info}}),
    {0, Output} = run_ek_escript(
        ["--format", "json", "ct", "inspect", "web-0-nginx"],
        [{"ERLKOENIG_EK_MOCK_OPERATOR_API", Path}]),
    Json = json:decode(list_to_binary(Output)),
    ?assertEqual(<<"running">>, maps:get(<<"state">>, Json)),
    ?assertEqual(<<"default">>, maps:get(<<"seccomp">>, Json)),
    ?assertEqual(<<"always">>,  maps:get(<<"restart">>, Json)),
    ?assertEqual(12345, maps:get(<<"os_pid">>, Json)),
    Net = maps:get(<<"net_info">>, Json),
    ?assertEqual(<<"10.10.0.2">>, maps:get(<<"ip">>, Net)),
    ?assertEqual(24,              maps:get(<<"netmask">>, Net)),
    ?assertEqual(<<"vm0">>,       maps:get(<<"ifname">>, Net)),
    Stats = maps:get(<<"stats">>, Json),
    ?assertEqual(921600, maps:get(<<"memory_bytes">>, Stats)),
    Args = maps:get(<<"args">>, Json),
    ?assertEqual([<<"-p">>, <<"7777">>], Args),
    [Vol] = maps:get(<<"volumes">>, Json),
    ?assertEqual(<<"ek_vol_1">>, maps:get(<<"uuid">>, Vol)),
    ?assertEqual(<<"/data">>, maps:get(<<"container">>, Vol)),
    ?assertEqual(<<"primary-data">>, maps:get(<<"persist">>, Vol)),
    ?assertEqual(false, maps:get(<<"read_only">>, Vol)),
    ?assertEqual(<<"persistent">>, maps:get(<<"lifecycle">>, Vol)),
    %% undefined → null
    ?assertEqual(null, maps:get(<<"exit_info">>, Json)),
    ?assertEqual(null, maps:get(<<"error">>, Json)),
    %% timeline is array of {step, status} objects (synthesized)
    Timeline = maps:get(<<"timeline">>, Json),
    ?assert(is_list(Timeline)),
    [?assert(maps:is_key(<<"step">>, Step) andalso
             maps:is_key(<<"status">>, Step)) || Step <- Timeline].

plain_ct_inspect_prints_complex_fields_test() ->
    Info = #{
        id      => <<"id-43">>,
        name    => <<"db-0-postgres">>,
        binary  => <<"/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server">>,
        zone    => <<"data">>,
        state   => failed,
        volumes => [#{host => <<"/var/lib/erlkoenig/volumes/v1">>,
                      container => <<"/var/lib/postgresql/data">>,
                      read_only => false}],
        error   => #{code => <<"EK_CT_SIGNATURE_REJECTED">>,
                     reason => signature_rejected}
    },
    Path = write_operator_api_mock(#{container_inspect => {ok, Info}}),
    {0, Output} = run_ek_escript(
        ["ct", "inspect", "db-0-postgres"],
        [{"ERLKOENIG_EK_MOCK_OPERATOR_API", Path}]),
    ?assertMatch({match, _}, re:run(Output, "volumes")),
    ?assertMatch({match, _}, re:run(Output, "EK_CT_SIGNATURE_REJECTED")).

json_pod_list_pid_as_string_test() ->
    Path = write_operator_api_mock(#{
        pod_list => {ok, [#{name => <<"web">>,
                            pid => <<"<0.99.0>">>,
                            children => 3}]}}),
    {0, Output} = run_ek_escript(
        ["--format", "json", "pod", "list"],
        [{"ERLKOENIG_EK_MOCK_OPERATOR_API", Path}]),
    [Row] = json:decode(list_to_binary(Output)),
    ?assertEqual(<<"web">>,       maps:get(<<"name">>, Row)),
    ?assertEqual(<<"<0.99.0>">>,  maps:get(<<"pid">>, Row)),
    ?assertEqual(3,               maps:get(<<"children">>, Row)).

pod_list_all_uses_all_operator_api_test() ->
    Path = write_operator_api_mock(#{
        pod_list_all => {ok, [#{name => <<"done">>,
                                pid => <<"<0.100.0>">>,
                                children => 0}]}}),
    {0, Output} = run_ek_escript(
        ["--format", "json", "pod", "list", "--all"],
        [{"ERLKOENIG_EK_MOCK_OPERATOR_API", Path}]),
    [Row] = json:decode(list_to_binary(Output)),
    ?assertEqual(<<"done">>, maps:get(<<"name">>, Row)),
    ?assertEqual(0, maps:get(<<"children">>, Row)),
    ?assertEqual([{pod_list_all, []}], read_operator_api_mock_calls(Path)).

json_vol_list_atom_lifecycle_to_string_test() ->
    Path = write_operator_api_mock(#{
        volume_list => {ok, [
            #{uuid => <<"u1">>, container => <<"pg">>,
              persist => <<"data">>, host_path => <<"/v/u1">>,
              lifecycle => persistent}
        ]}}),
    {0, Output} = run_ek_escript(
        ["--format", "json", "vol", "list"],
        [{"ERLKOENIG_EK_MOCK_OPERATOR_API", Path}]),
    [Row] = json:decode(list_to_binary(Output)),
    ?assertEqual(<<"persistent">>, maps:get(<<"lifecycle">>, Row)),
    %% quota_bytes always present (may be null)
    ?assertEqual(null, maps:get(<<"quota_bytes">>, Row)).

json_vol_inspect_quota_present_test() ->
    Path = write_operator_api_mock(#{
        volume_inspect => {ok,
            #{uuid => <<"u1">>, container => <<"pg">>,
              persist => <<"data">>, host_path => <<"/v/u1">>,
              lifecycle => persistent, quota_bytes => 1073741824}}}),
    {0, Output} = run_ek_escript(
        ["--format", "json", "vol", "inspect", "u1"],
        [{"ERLKOENIG_EK_MOCK_OPERATOR_API", Path}]),
    Json = json:decode(list_to_binary(Output)),
    ?assertEqual(1073741824, maps:get(<<"quota_bytes">>, Json)).

json_vol_orphans_array_shape_test() ->
    Path = write_operator_api_mock(#{
        volume_orphans => {ok, [<<"u1">>, <<"u2">>]}}),
    {0, Output} = run_ek_escript(
        ["--format", "json", "vol", "orphans"],
        [{"ERLKOENIG_EK_MOCK_OPERATOR_API", Path}]),
    Decoded = json:decode(list_to_binary(Output)),
    ?assertEqual([#{<<"uuid">> => <<"u1">>},
                  #{<<"uuid">> => <<"u2">>}], Decoded).

json_quarantine_list_crashloop_tuple_to_object_test() ->
    Path = write_operator_api_mock(#{
        quarantine_list => {ok, [
            #{hash => <<"deadbeef">>,
              reason => {crashloop, 5, 60000},
              since => 1777293296789},
            #{hash => <<"cafebabe">>,
              reason => manual,
              since => 1777293300000}
        ]}}),
    {0, Output} = run_ek_escript(
        ["--format", "json", "quarantine", "list"],
        [{"ERLKOENIG_EK_MOCK_OPERATOR_API", Path}]),
    [E1, E2] = json:decode(list_to_binary(Output)),
    ?assertEqual(<<"deadbeef">>, maps:get(<<"hash">>, E1)),
    R1 = maps:get(<<"reason">>, E1),
    ?assertEqual(<<"crashloop">>, maps:get(<<"kind">>, R1)),
    ?assertEqual(5, maps:get(<<"count">>, R1)),
    ?assertEqual(60000, maps:get(<<"window_ms">>, R1)),
    %% since: ISO + ms
    Iso = maps:get(<<"since">>, E1),
    ?assertMatch({match, _},
                 re:run(Iso, "^[0-9]{4}-[0-9]{2}-[0-9]{2}T")),
    ?assertEqual(1777293296789, maps:get(<<"since_ms">>, E1)),
    %% atom reason
    ?assertEqual(<<"manual">>, maps:get(<<"reason">>, E2)).

json_admission_snapshot_zone_map_test() ->
    Path = write_operator_api_mock(#{
        admission_snapshot => {ok,
            #{host_in_flight => 2, queued => 1,
              zone_in_flight => #{<<"dmz">> => 2}}}}),
    {0, Output} = run_ek_escript(
        ["--format", "json", "admission", "snapshot"],
        [{"ERLKOENIG_EK_MOCK_OPERATOR_API", Path}]),
    Json = json:decode(list_to_binary(Output)),
    ?assertEqual(2, maps:get(<<"host_in_flight">>, Json)),
    ?assertEqual(1, maps:get(<<"queued">>, Json)),
    Zones = maps:get(<<"zone_in_flight">>, Json),
    ?assertEqual(2, maps:get(<<"dmz">>, Zones)).

json_node_version_test() ->
    Path = write_rpc_mock(#{
        {application, get_key} => {ok, "9.9.9"}
    }),
    {0, Output} = run_ek_escript(
        ["--format", "json", "node", "version"],
        [{"ERLKOENIG_EK_MOCK_RPC", Path}]),
    Decoded = json:decode(list_to_binary(Output)),
    ?assertEqual(<<"9.9.9">>, maps:get(<<"version">>, Decoded)).

plain_node_version_test() ->
    Path = write_rpc_mock(#{
        {application, get_key} => {ok, "9.9.9"}
    }),
    {0, Output} = run_ek_escript(
        ["node", "version"],
        [{"ERLKOENIG_EK_MOCK_RPC", Path}]),
    ?assertMatch({match, _}, re:run(Output, "^9\\.9\\.9\n$")).

json_node_health_test() ->
    Path = write_operator_api_mock(#{
        node_health => {ok, #{uptime_ms => 123456, sup_children => 8}}}),
    {0, Output} = run_ek_escript(
        ["--format", "json", "node", "health"],
        [{"ERLKOENIG_EK_MOCK_OPERATOR_API", Path}]),
    Json = json:decode(list_to_binary(Output)),
    ?assertEqual(123456, maps:get(<<"uptime_ms">>, Json)),
    ?assertEqual(8, maps:get(<<"sup_children">>, Json)).

json_nft_counters_test() ->
    Path = write_operator_api_mock(#{
        nft_counters => {ok, [
            #{table => <<"erlkoenig_host">>,
              name => <<"egress">>,
              packets => 12,
              bytes => 960,
              total_packets => 1200,
              total_bytes => 96000,
              pps => 6.0,
              bps => 480.0,
              interval => 2000}
        ]}}),
    {0, Output} = run_ek_escript(
        ["--format", "json", "nft", "counters"],
        [{"ERLKOENIG_EK_MOCK_OPERATOR_API", Path}]),
    [Row] = json:decode(list_to_binary(Output)),
    ?assertEqual(<<"erlkoenig_host">>, maps:get(<<"table">>, Row)),
    ?assertEqual(<<"egress">>, maps:get(<<"name">>, Row)),
    ?assertEqual(12, maps:get(<<"packets">>, Row)),
    ?assertEqual(960, maps:get(<<"bytes">>, Row)),
    ?assertEqual(1200, maps:get(<<"total_packets">>, Row)),
    ?assertEqual(96000, maps:get(<<"total_bytes">>, Row)),
    ?assertEqual(6.0, maps:get(<<"pps">>, Row)),
    ?assertEqual(480.0, maps:get(<<"bps">>, Row)),
    ?assertEqual(2000, maps:get(<<"interval">>, Row)),
    ?assertEqual([{nft_counters, []}], read_operator_api_mock_calls(Path)).

firewall_status_table_uses_operator_api_test() ->
    Path = write_operator_api_mock(#{
        firewall_status => {ok, #{
            events => #{running => true, cursor => 12, buffered => 3},
            guard => #{active_actors => 1, active_bans => 0}
        }}}),
    {0, Output} = run_ek_escript(
        ["firewall", "status"],
        [{"ERLKOENIG_EK_MOCK_OPERATOR_API", Path}]),
    ?assert(string:find(Output, "events") =/= nomatch),
    ?assert(string:find(Output, "cursor") =/= nomatch),
    ?assert(string:find(Output, "guard") =/= nomatch),
    ?assertEqual([{firewall_status, []}], read_operator_api_mock_calls(Path)).

json_firewall_status_shape_test() ->
    Path = write_operator_api_mock(#{
        firewall_status => {ok, #{
            events => #{running => true, cursor => 12,
                        buffered => 3, groups => [nflog_events, counter_events]},
            guard => #{active_actors => 1, active_bans => 0}
        }}}),
    {0, Output} = run_ek_escript(
        ["--format", "json", "firewall", "status"],
        [{"ERLKOENIG_EK_MOCK_OPERATOR_API", Path}]),
    Json = json:decode(list_to_binary(Output)),
    Events = maps:get(<<"events">>, Json),
    ?assertEqual(true, maps:get(<<"running">>, Events)),
    ?assertEqual(12, maps:get(<<"cursor">>, Events)),
    ?assertEqual(3, maps:get(<<"buffered">>, Events)),
    Guard = maps:get(<<"guard">>, Json),
    ?assertEqual(1, maps:get(<<"active_actors">>, Guard)),
    ?assertEqual([{firewall_status, []}], read_operator_api_mock_calls(Path)).

firewall_events_table_uses_operator_api_test() ->
    Path = write_operator_api_mock(#{
        firewall_events => {ok, [
            #{seq => 7,
              ts_wall => 1778147168000,
              severity => notice,
              kind => scan_suspect,
              source => threat_actor,
              table => <<"erlkoenig_host">>,
              table_owner => host,
              src_ip => <<203,0,113,44>>,
              reason => distinct_ports_seen}
        ]}}),
    {0, Output} = run_ek_escript(
        ["firewall", "events", "--limit", "1"],
        [{"ERLKOENIG_EK_MOCK_OPERATOR_API", Path}]),
    ?assert(string:find(Output, "scan_suspect") =/= nomatch),
    ?assert(string:find(Output, "erlkoenig_host") =/= nomatch),
    ?assert(string:find(Output, "host") =/= nomatch),
    ?assert(string:find(Output, "203.0.113.44") =/= nomatch),
    ?assertEqual([{firewall_events, [1]}], read_operator_api_mock_calls(Path)).

json_firewall_events_normalizes_ip_and_evidence_test() ->
    Path = write_operator_api_mock(#{
        firewall_events => {ok, [
            #{seq => 8,
              id => <<"fw-test">>,
              ts_mono => 100,
              ts_wall => 1778147168000,
              severity => warning,
              kind => firewall_packet,
              source => nflog,
              src_ip => {203,0,113,44},
              dst_ip => {10,0,0,1},
              chain => <<"input">>,
              dst_port => 22,
              evidence => #{ports => [22, 443],
                            src_raw => <<203,0,113,44>>,
                            dst_raw => <<10,0,0,1>>},
              labels => [firewall, packet]}
        ]}}),
    {0, Output} = run_ek_escript(
        ["--format", "json", "firewall", "events"],
        [{"ERLKOENIG_EK_MOCK_OPERATOR_API", Path}]),
    [Row] = json:decode(list_to_binary(Output)),
    ?assertEqual(8, maps:get(<<"seq">>, Row)),
    ?assertEqual(<<"fw-test">>, maps:get(<<"id">>, Row)),
    ?assertEqual(<<"warning">>, maps:get(<<"severity">>, Row)),
    ?assertEqual(<<"firewall_packet">>, maps:get(<<"kind">>, Row)),
    ?assertEqual(<<"203.0.113.44">>, maps:get(<<"src_ip">>, Row)),
    ?assertEqual(<<"10.0.0.1">>, maps:get(<<"dst_ip">>, Row)),
    Evidence = maps:get(<<"evidence">>, Row),
    ?assertEqual([22, 443], maps:get(<<"ports">>, Evidence)),
    ?assertEqual(<<"203.0.113.44">>, maps:get(<<"src_raw">>, Evidence)),
    ?assertEqual(<<"10.0.0.1">>, maps:get(<<"dst_raw">>, Evidence)),
    ?assertEqual([{firewall_events, [50]}], read_operator_api_mock_calls(Path)).

firewall_events_bad_limit_is_usage_error_test() ->
    {Status, Output} = run_ek_escript(["firewall", "events", "--limit", "0"]),
    ?assertEqual(2, Status),
    ?assert(string:find(Output, "--limit must be a positive integer") =/= nomatch).

escript_doctor_json_uses_catalog_codes_test() ->
    {1, Output} = run_ek_escript(
        ["--format", "json", "doctor"],
        [{"ERLKOENIG_PROTOCOL_VECTORS", "/tmp/erlkoenig_missing_vectors"}]),
    ?assert(string:find(Output, "doctor: ") =/= nomatch),
    ?assert(string:find(Output, "blocking issue") =/= nomatch),
    Rows = json:decode(unicode:characters_to_binary(first_json_line(Output))),
    ?assert(is_list(Rows)),
    Protocol = lists:filter(
        fun(#{<<"check">> := <<"protocol_vectors">>}) -> true;
           (_) -> false
        end, Rows),
    ?assertMatch([_], Protocol),
    [Row] = Protocol,
    ?assertEqual(<<"warn">>, maps:get(<<"status">>, Row)),
    ?assertEqual(<<"EK_HOST_PROTOCOL_VECTORS_MISSING">>, maps:get(<<"code">>, Row)),
    ?assert(maps:is_key(<<"action">>, Row)),
    ?assert(maps:is_key(<<"evidence">>, Row)).

escript_doctor_flags_weak_cookie_permissions_test() ->
    Cookie = filename:join(
        ["/tmp", "ek_doctor_cookie_"
                 ++ integer_to_list(erlang:unique_integer([positive]))]),
    ok = file:write_file(Cookie, <<"ERLKOENIG_TEST_COOKIE\n">>),
    ok = file:change_mode(Cookie, 8#0644),
    {1, Output} = run_ek_escript(
        ["--cookie-file", Cookie, "--format", "json", "doctor"], []),
    Rows = json:decode(unicode:characters_to_binary(first_json_line(Output))),
    Row = doctor_row(<<"cookie_permissions">>, Rows),
    ?assertEqual(<<"fail">>, maps:get(<<"status">>, Row)),
    ?assertEqual(<<"EK_HOST_COOKIE_PERMISSIONS_WEAK">>, maps:get(<<"code">>, Row)),
    Evidence = maps:get(<<"evidence">>, Row),
    ?assertEqual(<<"0644">>, maps:get(<<"mode">>, Evidence)),
    ?assertEqual(true, maps:get(<<"world_readable">>, Evidence)).

%% =================================================================
%% IO capture helpers
%% =================================================================

run_ek_escript(Args) ->
    run_ek_escript(Args, []).

run_ek_escript(Args, Env) ->
    Escript = os:find_executable("escript"),
    ?assert(is_list(Escript)),
    Script = filename:absname("dist/ek.escript"),
    Port = open_port({spawn_executable, Escript},
                     [binary, exit_status, stderr_to_stdout, use_stdio,
                      {env, Env},
                      {args, [Script | Args]}]),
    collect_port(Port, []).

write_operator_api_mock(Responses) ->
    Path = filename:join(
        ["/tmp", "ek_operator_api_mock_"
                 ++ integer_to_list(erlang:unique_integer([positive]))
                 ++ ".term"]),
    State = #{responses => Responses, calls => []},
    ok = file:write_file(Path, io_lib:format("~p.~n", [State])),
    Path.

write_rpc_mock(Responses) ->
    Path = filename:join(
        ["/tmp", "ek_rpc_mock_"
                 ++ integer_to_list(erlang:unique_integer([positive]))
                 ++ ".term"]),
    State = #{responses => Responses, calls => []},
    ok = file:write_file(Path, io_lib:format("~p.~n", [State])),
    Path.

doctor_row(Check, Rows) ->
    Matches = [Row || #{<<"check">> := Found} = Row <- Rows,
                      Found =:= Check],
    ?assertMatch([_], Matches),
    [Row] = Matches,
    Row.

read_operator_api_mock_calls(Path) ->
    {ok, [State]} = file:consult(Path),
    maps:get(calls, State).

assert_cli_version(Args) ->
    {0, Output} = run_ek_escript(Args),
    ?assertMatch({match, _}, re:run(Output, "^ek [0-9]+\\.[0-9]+\\.[0-9]+\\n$")).

first_json_line(Output) ->
    Lines = string:split(Output, "\n", all),
    case [Line || Line <- Lines, is_json_line(Line)] of
        [Line | _] -> Line;
        [] -> error({no_json_line, Output})
    end.

is_json_line([]) ->
    false;
is_json_line([${ | _]) ->
    true;
is_json_line([$[ | _]) ->
    true;
is_json_line(_) ->
    false.

collect_port(Port, Acc) ->
    receive
        {Port, {data, Data}} ->
            collect_port(Port, [Data | Acc]);
        {Port, {exit_status, Status}} ->
            {Status, unicode:characters_to_list(lists:reverse(Acc))}
    after 5000 ->
        exit({ek_escript_timeout, Port})
    end.

io_capture_get(Pid) ->
    Ref = make_ref(),
    Pid ! {get, self(), Ref},
    receive
        {Ref, Data} -> Data
    after 2000 -> ""
    end.

capture_print_event(Event) ->
    OldGL = group_leader(),
    CaptPid = spawn_link(fun() -> io_server_loop([]) end),
    group_leader(CaptPid, self()),
    ek:print_event(Event),
    group_leader(OldGL, self()),
    io_capture_get(CaptPid).

io_server_loop(Acc) ->
    receive
        {io_request, From, ReplyAs, Request} ->
            {Reply, NewAcc} = io_handle_request(Request, Acc),
            From ! {io_reply, ReplyAs, Reply},
            io_server_loop(NewAcc);
        {get, Caller, Ref} ->
            Caller ! {Ref, unicode:characters_to_list(lists:reverse(Acc))}
    end.

io_handle_request({put_chars, _Encoding, Chars}, Acc) ->
    {ok, [unicode:characters_to_binary(Chars) | Acc]};
io_handle_request({put_chars, _Encoding, M, F, A}, Acc) ->
    Chars = apply(M, F, A),
    {ok, [unicode:characters_to_binary(Chars) | Acc]};
io_handle_request({put_chars, Chars}, Acc) ->
    {ok, [unicode:characters_to_binary(Chars) | Acc]};
io_handle_request(_Other, Acc) ->
    {ok, Acc}.

%% =================================================================
%% admission_denial — text + JSON output, ETS hot path
%% =================================================================

admission_denial_test_() ->
    {foreach,
     fun denial_setup/0,
     fun denial_teardown/1,
     [fun t_admission_denial_no_match_text/1,
      fun t_admission_denial_no_match_json_default/1,
      fun t_admission_denial_text_round_trip/1,
      fun t_admission_denial_default_format_is_json/1,
      fun t_admission_denial_lookup_by_name/1,
      fun t_admission_denial_all_lists_multiple/1,
      fun t_admission_denial_text_handles_binary_limit_keys/1,
      fun t_admission_denial_text_capture_is_ascii_safe/1]}.

denial_setup() ->
    {ok, Pid} = erlkoenig_denial_log:start_link(),
    Pid.

denial_teardown(Pid) ->
    catch gen_server:stop(Pid),
    ok.

denial_sync() -> _ = sys:get_state(erlkoenig_denial_log), ok.

denial_record(Id, Name, Reason) ->
    erlkoenig_denial_log:record_denial(#{
        container_id => Id,
        container_name => Name,
        ts_ms => 1_700_000_000_000,
        zone => zone_a,
        reason => Reason,
        limits => #{memory => 200, pids => 10}
    }),
    denial_sync().

capture_admission(Args) ->
    OldGL = group_leader(),
    CaptPid = spawn_link(fun() -> io_server_loop([]) end),
    group_leader(CaptPid, self()),
    apply(ek, admission_denial, Args),
    group_leader(OldGL, self()),
    io_capture_get(CaptPid).

t_admission_denial_no_match_text(_) ->
    ?_test(begin
        Output = capture_admission([<<"missing">>, #{format => text}]),
        ?assert(string:find(Output, "No admission denials found") =/= nomatch),
        ?assert(string:find(Output, "missing") =/= nomatch)
    end).

t_admission_denial_no_match_json_default(_) ->
    ?_test(begin
        %% No format opt → JSON (the contracted default for the pipe).
        Output = capture_admission([<<"missing">>]),
        ?assertEqual([], json:decode(iolist_to_binary(string:trim(Output))))
    end).

t_admission_denial_text_round_trip(_) ->
    ?_test(begin
        denial_record(<<"c1">>, <<"api">>,
                      #{reason => insufficient_memory, kind => memory,
                        ceiling => 1000, allocated => 800, committed => 100}),
        Output = capture_admission([<<"c1">>, #{format => text}]),
        ?assert(string:find(Output, "c1") =/= nomatch),
        ?assert(string:find(Output, "api") =/= nomatch),
        ?assert(string:find(Output, "insufficient_memory") =/= nomatch),
        ?assert(string:find(Output, "Ceiling") =/= nomatch),
        ?assert(string:find(Output, "Allocated") =/= nomatch)
    end).

t_admission_denial_default_format_is_json(_) ->
    ?_test(begin
        denial_record(<<"c1">>, <<"api">>,
                      #{reason => insufficient_memory, kind => memory,
                        ceiling => 1000, allocated => 800}),
        %% The contracted default — `ek:admission_denial(Name)`
        %% must produce a JSON object suitable for piping to
        %% `mix erlkoenig.explain admission`.
        Output = capture_admission([<<"c1">>]),
        Decoded = json:decode(iolist_to_binary(string:trim(Output))),
        ?assert(is_map(Decoded)),
        ?assertEqual(<<"ct">>, maps:get(<<"type">>, Decoded)),
        ?assertEqual(<<"resource_admission_denied">>,
                     maps:get(<<"reason">>, Decoded)),
        ?assertEqual(<<"EK_CT_RESOURCE_ADMISSION_DENIED">>,
                     maps:get(<<"code">>, Decoded)),
        ?assertEqual(<<"c1">>, maps:get(<<"container">>, Decoded)),
        ?assertEqual(1_700_000_000_000, maps:get(<<"ts_ms">>, Decoded)),
        Data = maps:get(<<"data">>, Decoded),
        ?assert(is_map(Data)),
        ?assert(maps:is_key(<<"reason">>, Data)),
        ?assert(maps:is_key(<<"limits">>, Data))
    end).

t_admission_denial_lookup_by_name(_) ->
    ?_test(begin
        denial_record(<<"abc-123-def">>, <<"api">>,
                      #{reason => insufficient_memory}),
        %% Operator typed the friendly name, not the generated id.
        Output = capture_admission([<<"api">>, #{format => text}]),
        ?assert(string:find(Output, "abc-123-def") =/= nomatch),
        ?assert(string:find(Output, "api") =/= nomatch)
    end).

t_admission_denial_all_lists_multiple(_) ->
    ?_test(begin
        denial_record(<<"c1">>, <<"api">>,
                      #{reason => insufficient_memory}),
        denial_record(<<"c1">>, <<"api">>,
                      #{reason => insufficient_pids}),
        Output = capture_admission([<<"c1">>, #{format => text, all => true}]),
        ?assert(string:find(Output, "2 denial(s)") =/= nomatch),
        ?assert(string:find(Output, "insufficient_memory") =/= nomatch),
        ?assert(string:find(Output, "insufficient_pids") =/= nomatch)
    end).

%% Reproduces the audit-fallback case: limits arrive as a map keyed
%% by binaries (json:decode default) rather than atoms. The text
%% renderer must not crash on `atom_to_list/1`.
t_admission_denial_text_handles_binary_limit_keys(_) ->
    ?_test(begin
        erlkoenig_denial_log:record_denial(#{
            container_id => <<"c1">>,
            container_name => <<"api">>,
            ts_ms => 1_700_000_000_000,
            zone => <<"zone_a">>,
            reason => #{<<"reason">> => <<"insufficient_memory">>},
            limits => #{<<"memory">> => 200, <<"pids">> => 10}
        }),
        denial_sync(),
        %% Should render without crashing on atom_to_list/binary.
        Output = capture_admission([<<"c1">>, #{format => text}]),
        ?assert(string:find(Output, "memory = 200") =/= nomatch),
        ?assert(string:find(Output, "pids = 10") =/= nomatch)
    end).

t_admission_denial_text_capture_is_ascii_safe(_) ->
    ?_test(begin
        denial_record(<<"c1">>, <<"api">>,
                      #{reason => insufficient_memory, kind => memory}),
        Output = ek:capture(fun() ->
            ek:admission_denial(<<"c1">>, #{format => text})
        end),
        ?assert(string:find(Output, "c1") =/= nomatch),
        ?assert(string:find(Output, "insufficient_memory") =/= nomatch)
    end).

%% =================================================================
%% admission_denial — full audit-fallback round trip
%%
%% Exercises the producer/consumer contract end to end:
%%   ct.erl-shape audit:log
%%     → erlkoenig_audit gen_server (writes to disk)
%%       → erlkoenig_audit:query/1 (parses lines)
%%         → ek's audit_to_denial/1
%%           → ek's denial_to_emit_event/1
%%             → erlkoenig_error:to_map/1
%% This is the path that was broken before this fix: audit flattens
%% `details' onto top level, so a reader looking inside a nested
%% `<<"details">>' map got back nothing. With the fix, every field
%% should make it through.
%% =================================================================

audit_roundtrip_test_() ->
    {foreach,
     fun audit_setup/0,
     fun audit_teardown/1,
     [fun t_audit_roundtrip_full_evidence/1,
      fun t_audit_roundtrip_name_lookup/1,
      fun t_audit_roundtrip_text_reason_with_binary_keys/1,
      fun t_audit_roundtrip_not_hidden_by_global_limit/1]}.

audit_setup() ->
    TmpDir = "/tmp/ek_audit_roundtrip_"
             ++ integer_to_list(erlang:unique_integer([positive])),
    ok = filelib:ensure_dir(TmpDir ++ "/x"),
    AuditFile = filename:join(TmpDir, "audit.jsonl"),
    application:set_env(erlkoenig, audit_path, AuditFile),
    {ok, AuditPid} = erlkoenig_audit:start_link(),
    {ok, RingPid} = erlkoenig_denial_log:start_link(),
    {AuditPid, RingPid, TmpDir}.

audit_teardown({AuditPid, RingPid, TmpDir}) ->
    catch gen_server:stop(AuditPid),
    catch gen_server:stop(RingPid),
    application:unset_env(erlkoenig, audit_path),
    _ = file:del_dir_r(TmpDir),
    ok.

audit_flush() -> _ = sys:get_state(erlkoenig_audit), ok.

t_audit_roundtrip_full_evidence(_) ->
    ?_test(begin
        %% Mimics ct.erl exactly — same map shape goes into the audit.
        Reason = #{reason => insufficient_memory,
                   required => 4_294_967_296,
                   available => 2_147_483_648,
                   evidence => #{kind => memory,
                                 ceiling => 8_589_934_592,
                                 allocated => 5_368_709_120,
                                 committed => 1_073_741_824}},
        erlkoenig_audit:log(#{type => resource_admission_denied,
                              subject => <<"abc-123">>,
                              result => denied,
                              details => #{zone => zone_a,
                                           reason => Reason,
                                           limits => #{memory => 4_294_967_296,
                                                       pids => 512},
                                           container_name => <<"api">>}}),
        audit_flush(),
        %% Hot ring is empty — only the audit-fallback can serve this.
        Output = capture_admission([<<"abc-123">>]),
        Decoded = json:decode(iolist_to_binary(string:trim(Output))),
        ?assertEqual(<<"ct">>, maps:get(<<"type">>, Decoded)),
        ?assertEqual(<<"resource_admission_denied">>,
                     maps:get(<<"reason">>, Decoded)),
        ?assertEqual(<<"abc-123">>, maps:get(<<"container">>, Decoded)),
        Data = maps:get(<<"data">>, Decoded),
        %% These four assertions would all have failed against the
        %% pre-fix `audit_to_denial' that read from a nested
        %% `<<"details">>' key.
        ?assertEqual(<<"zone_a">>, maps:get(<<"zone">>, Data)),
        DataReason = maps:get(<<"reason">>, Data),
        ?assert(is_map(DataReason)),
        ?assertEqual(<<"insufficient_memory">>,
                     maps:get(<<"reason">>, DataReason)),
        ?assertEqual(4_294_967_296,
                     maps:get(<<"required">>, DataReason)),
        DataLimits = maps:get(<<"limits">>, Data),
        ?assertEqual(4_294_967_296, maps:get(<<"memory">>, DataLimits)),
        ?assertEqual(512, maps:get(<<"pids">>, DataLimits))
    end).

t_audit_roundtrip_name_lookup(_) ->
    ?_test(begin
        erlkoenig_audit:log(#{type => resource_admission_denied,
                              subject => <<"abc-123">>,
                              result => denied,
                              details => #{zone => zone_a,
                                           reason =>
                                               #{reason => insufficient_memory},
                                           limits => #{memory => 200},
                                           container_name => <<"api">>}}),
        audit_flush(),
        %% Operator typed the friendly name. Audit-fallback must
        %% match container_name (top-level after the flatten), not
        %% just subject. Without the name-aware filter this returns
        %% an empty `[]' and the JSON output is the no-match list.
        Output = capture_admission([<<"api">>]),
        Decoded = json:decode(iolist_to_binary(string:trim(Output))),
        ?assert(is_map(Decoded)),
        ?assertEqual(<<"abc-123">>, maps:get(<<"container">>, Decoded))
    end).

t_audit_roundtrip_text_reason_with_binary_keys(_) ->
    ?_test(begin
        erlkoenig_audit:log(#{type => resource_admission_denied,
                              subject => <<"abc-123">>,
                              result => denied,
                              details => #{zone => zone_a,
                                           reason =>
                                               #{reason => insufficient_memory,
                                                 kind => memory,
                                                 ceiling => 1000,
                                                 allocated => 800,
                                                 committed => 100},
                                           limits => #{memory => 200},
                                           container_name => <<"api">>}}),
        audit_flush(),
        %% Audit JSON decode returns binary keys inside the reason map.
        %% The text quick-look must still show the reason and fields.
        Output = capture_admission([<<"abc-123">>, #{format => text}]),
        ?assert(string:find(Output, "insufficient_memory") =/= nomatch),
        ?assert(string:find(Output, "Ceiling") =/= nomatch),
        ?assert(string:find(Output, "Allocated") =/= nomatch),
        ?assert(string:find(Output, "Committed") =/= nomatch)
    end).

t_audit_roundtrip_not_hidden_by_global_limit(_) ->
    ?_test(begin
        [erlkoenig_audit:log(#{type => resource_admission_denied,
                               subject => <<"noise-", (integer_to_binary(N))/binary>>,
                               result => denied,
                               details => #{container_name => <<"noise">>,
                                            reason =>
                                                #{reason => insufficient_memory},
                                            limits => #{memory => 1}}})
         || N <- lists:seq(1, 1005)],
        erlkoenig_audit:log(#{type => resource_admission_denied,
                              subject => <<"abc-123">>,
                              result => denied,
                              details => #{zone => zone_a,
                                           reason =>
                                               #{reason => insufficient_pids},
                                           limits => #{pids => 512},
                                           container_name => <<"api">>}}),
        audit_flush(),
        %% This must still find the newest target denial even though
        %% more than 1000 unrelated denials precede it in the audit.
        Output = capture_admission([<<"abc-123">>]),
        Decoded = json:decode(iolist_to_binary(string:trim(Output))),
        ?assert(is_map(Decoded)),
        ?assertEqual(<<"abc-123">>, maps:get(<<"container">>, Decoded)),
        DataReason = maps:get(<<"reason">>, maps:get(<<"data">>, Decoded)),
        ?assertEqual(<<"insufficient_pids">>,
                     maps:get(<<"reason">>, DataReason))
    end).
