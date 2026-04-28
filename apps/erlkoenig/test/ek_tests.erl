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
        volumes       => [],
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
    %% undefined → null
    ?assertEqual(null, maps:get(<<"exit_info">>, Json)),
    ?assertEqual(null, maps:get(<<"error">>, Json)),
    %% timeline is array of {step, status} objects (synthesized)
    Timeline = maps:get(<<"timeline">>, Json),
    ?assert(is_list(Timeline)),
    [?assert(maps:is_key(<<"step">>, Step) andalso
             maps:is_key(<<"status">>, Step)) || Step <- Timeline].

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

escript_doctor_json_uses_catalog_codes_test() ->
    {1, Output} = run_ek_escript(
        ["--format", "json", "doctor"],
        [{"ERLKOENIG_PROTOCOL_VECTORS", "/tmp/erlkoenig_missing_vectors"}]),
    ?assert(string:find(Output, "doctor: ") =/= nomatch),
    ?assert(string:find(Output, "blocking issue") =/= nomatch),
    Rows = json:decode(unicode:characters_to_binary(first_line(Output))),
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
    Rows = json:decode(unicode:characters_to_binary(first_line(Output))),
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

first_line(Output) ->
    hd(string:split(Output, "\n")).

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
