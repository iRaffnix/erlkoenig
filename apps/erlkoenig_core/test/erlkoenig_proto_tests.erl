%%%-------------------------------------------------------------------
%%% @doc Unit tests for erlkoenig_proto (wire protocol codec).
%%%
%%% Tests encode/decode roundtrips for all reply types, command
%%% structure validation, and error handling for malformed input.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_proto_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%% =================================================================
%% Reply decode tests
%% =================================================================

decode_reply_ok_test() ->
    Bin = <<16#01, 0:16/big>>,
    ?assertEqual({ok, reply_ok, #{data => <<>>}}, erlkoenig_proto:decode(Bin)).

decode_reply_ok_with_data_test() ->
    Data = <<"hello">>,
    Bin = <<16#01, 5:16/big, Data/binary>>,
    ?assertEqual({ok, reply_ok, #{data => Data}}, erlkoenig_proto:decode(Bin)).

decode_reply_error_test() ->
    Msg = <<"ENOENT">>,
    Bin = <<16#02, (- 2):32/big-signed, 6:16/big, Msg/binary>>,
    ?assertEqual({ok, reply_error, #{code => -2, message => Msg}},
                 erlkoenig_proto:decode(Bin)).

decode_reply_container_pid_test() ->
    Ns = <<"/proc/42/ns/net">>,
    Bin = <<16#03, 42:32/big, (byte_size(Ns)):16/big, Ns/binary>>,
    ?assertEqual({ok, reply_container_pid,
                  #{child_pid => 42, netns_path => Ns}},
                 erlkoenig_proto:decode(Bin)).

decode_reply_ready_test() ->
    ?assertEqual({ok, reply_ready, #{}}, erlkoenig_proto:decode(<<16#04>>)).

decode_reply_exited_test() ->
    Bin = <<16#05, 0:32/big-signed, 0:8>>,
    ?assertEqual({ok, reply_exited, #{exit_code => 0, term_signal => 0}},
                 erlkoenig_proto:decode(Bin)).

decode_reply_exited_signal_test() ->
    %% Process killed by SIGSEGV (signal 11), exit code = 128+11
    Bin = <<16#05, 139:32/big-signed, 11:8>>,
    ?assertEqual({ok, reply_exited, #{exit_code => 139, term_signal => 11}},
                 erlkoenig_proto:decode(Bin)).

decode_reply_status_test() ->
    Bin = <<16#06, 1:8, 1234:32/big, 5000:64/big>>,
    ?assertEqual({ok, reply_status,
                  #{state => 1, child_pid => 1234, uptime_ms => 5000}},
                 erlkoenig_proto:decode(Bin)).

decode_reply_stdout_test() ->
    Data = <<"Hello, world!\n">>,
    Bin = <<16#07, Data/binary>>,
    ?assertEqual({ok, reply_stdout, #{data => Data}},
                 erlkoenig_proto:decode(Bin)).

decode_reply_stderr_test() ->
    Data = <<"error: something\n">>,
    Bin = <<16#08, Data/binary>>,
    ?assertEqual({ok, reply_stderr, #{data => Data}},
                 erlkoenig_proto:decode(Bin)).

%% =================================================================
%% Error handling tests
%% =================================================================

decode_empty_test() ->
    ?assertEqual({error, empty_message}, erlkoenig_proto:decode(<<>>)).

decode_unknown_tag_test() ->
    ?assertEqual({error, {unknown_tag, 16#FF}}, erlkoenig_proto:decode(<<16#FF>>)).

decode_malformed_reply_ok_test() ->
    %% reply_ok with truncated length
    ?assertEqual({error, {malformed, reply_ok}}, erlkoenig_proto:decode(<<16#01, 0>>)).

decode_malformed_reply_error_test() ->
    %% reply_error with truncated payload
    ?assertEqual({error, {malformed, reply_error}}, erlkoenig_proto:decode(<<16#02, 0, 0>>)).

decode_malformed_reply_exited_test() ->
    %% reply_exited with only 4 bytes instead of 5
    ?assertEqual({error, {malformed, reply_exited}},
                 erlkoenig_proto:decode(<<16#05, 0:32/big>>)).

decode_malformed_container_pid_test() ->
    %% reply_container_pid with truncated ns path
    ?assertEqual({error, {malformed, reply_container_pid}},
                 erlkoenig_proto:decode(<<16#03, 42:32/big, 100:16/big, "short">>)).

%% =================================================================
%% Encode structure tests
%% =================================================================

encode_cmd_spawn_tag_test() ->
    Cmd = erlkoenig_proto:encode_cmd_spawn(<<"/bin/test">>, [], [], 0, 0, 0),
    ?assertEqual(16#10, binary:first(Cmd)).

encode_cmd_spawn_with_args_test() ->
    Cmd = erlkoenig_proto:encode_cmd_spawn(
            <<"/bin/echo">>, [<<"-n">>, <<"hello">>],
            [{<<"HOME">>, <<"/tmp">>}], 1000, 1000, 0),
    ?assert(is_binary(Cmd)),
    ?assert(byte_size(Cmd) > 10).

encode_cmd_spawn_all_opts_test() ->
    Cmd = erlkoenig_proto:encode_cmd_spawn(
            <<"/app">>, [], [], 0, 0, 1, 64, 16#FFFFFFFFFFFFFFFF),
    ?assertEqual(16#10, binary:first(Cmd)),
    ?assert(byte_size(Cmd) > 20).

encode_cmd_go_test() ->
    ?assertEqual(<<16#11>>, erlkoenig_proto:encode_cmd_go()).

encode_cmd_kill_test() ->
    ?assertEqual(<<16#12, 9>>, erlkoenig_proto:encode_cmd_kill(9)).

encode_cmd_kill_sigterm_test() ->
    ?assertEqual(<<16#12, 15>>, erlkoenig_proto:encode_cmd_kill(15)).

encode_cmd_net_setup_test() ->
    Cmd = erlkoenig_proto:encode_cmd_net_setup(
            <<"eth0">>, {10, 0, 0, 2}, 24, {10, 0, 0, 1}),
    ?assertEqual(16#15, binary:first(Cmd)),
    %% Tag(1) + IfNameLen(2) + "eth0"(4) + IP(4) + Prefix(1) + GW(4) = 16
    ?assertEqual(16, byte_size(Cmd)).

encode_cmd_write_file_test() ->
    Cmd = erlkoenig_proto:encode_cmd_write_file(
            <<"/etc/hosts">>, 8#644, <<"127.0.0.1 localhost\n">>),
    ?assertEqual(16#16, binary:first(Cmd)).

encode_cmd_query_status_test() ->
    ?assertEqual(<<16#14>>, erlkoenig_proto:encode_cmd_query_status()).

%% =================================================================
%% tag_name tests
%% =================================================================

tag_name_known_test_() ->
    [?_assertEqual(reply_ok, erlkoenig_proto:tag_name(16#01)),
     ?_assertEqual(reply_error, erlkoenig_proto:tag_name(16#02)),
     ?_assertEqual(reply_container_pid, erlkoenig_proto:tag_name(16#03)),
     ?_assertEqual(reply_exited, erlkoenig_proto:tag_name(16#05)),
     ?_assertEqual(reply_stdout, erlkoenig_proto:tag_name(16#07)),
     ?_assertEqual(reply_stderr, erlkoenig_proto:tag_name(16#08)),
     ?_assertEqual(cmd_spawn, erlkoenig_proto:tag_name(16#10)),
     ?_assertEqual(cmd_go, erlkoenig_proto:tag_name(16#11)),
     ?_assertEqual(cmd_kill, erlkoenig_proto:tag_name(16#12)),
     ?_assertEqual(cmd_net_setup, erlkoenig_proto:tag_name(16#15)),
     ?_assertEqual(cmd_write_file, erlkoenig_proto:tag_name(16#16))].

tag_name_unknown_test() ->
    ?assertEqual(unknown, erlkoenig_proto:tag_name(16#FF)).

%% =================================================================
%% Volume encoding tests
%% =================================================================

encode_volumes_empty_test() ->
    ?assertEqual(<<0>>, erlkoenig_proto:encode_volumes([])).

encode_volumes_single_test() ->
    Src = <<"/var/lib/erlkoenig/volumes/app/db">>,
    Dst = <<"/data/db">>,
    Volumes = [#{host => Src, container => Dst, opts => 0}],
    Expected = <<1:8,
                 (byte_size(Src)):16/big, Src/binary,
                 (byte_size(Dst)):16/big, Dst/binary,
                 0:32/big>>,
    ?assertEqual(Expected, erlkoenig_proto:encode_volumes(Volumes)).

encode_volumes_readonly_test() ->
    Src = <<"/var/lib/erlkoenig/volumes/app/config">>,
    Dst = <<"/etc/config">>,
    Volumes = [#{host => Src, container => Dst, opts => 16#01}],
    Bin = erlkoenig_proto:encode_volumes(Volumes),
    %% Check the opts field is 0x01 (last 4 bytes)
    OptsOffset = byte_size(Bin) - 4,
    <<_:OptsOffset/binary, Opts:32/big>> = Bin,
    ?assertEqual(16#01, Opts).

encode_volumes_max_test() ->
    Vols = [#{host => <<"/src">>, container => <<"/dst">>, opts => 0}
            || _ <- lists:seq(1, 16)],
    Bin = erlkoenig_proto:encode_volumes(Vols),
    <<NumVol:8, _/binary>> = Bin,
    ?assertEqual(16, NumVol).

volume_opts_readonly_test() ->
    ?assertEqual(16#01, erlkoenig_proto:volume_opts(#{read_only => true})).

volume_opts_default_test() ->
    ?assertEqual(0, erlkoenig_proto:volume_opts(#{read_only => false})).

volume_opts_empty_test() ->
    ?assertEqual(0, erlkoenig_proto:volume_opts(#{})).

encode_cmd_spawn_with_volumes_test() ->
    Volumes = [#{host => <<"/h">>, container => <<"/c">>, opts => 0}],
    Cmd = erlkoenig_proto:encode_cmd_spawn(
            <<"/app">>, [], [], 0, 0, 0, 0, 0, 0, 0, Volumes),
    ?assertEqual(16#10, binary:first(Cmd)),
    ?assert(byte_size(Cmd) > 20).
