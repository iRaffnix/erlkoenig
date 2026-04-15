%%%-------------------------------------------------------------------
%%% @doc Unit tests for erlkoenig_proto (wire protocol codec).
%%%
%%% Tests encode/decode roundtrips, TLV encoding, and error handling.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_proto_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

%% =================================================================
%% Reply decode tests (C -> Erlang)
%%
%% Replies from the C runtime are: Tag:8 | Version:8 | Payload
%% The decoder accepts both with and without version byte.
%% =================================================================

decode_reply_ok_test() ->
    %% Tag + Version + empty
    ?assertMatch({ok, reply_ok, _}, erlkoenig_proto:decode(<<16#01, 1>>)).

decode_reply_ok_legacy_test() ->
    %% Legacy: Tag + Payload (no version)
    ?assertMatch({ok, reply_ok, _}, erlkoenig_proto:decode(<<16#01, 0, 0:16/big>>)).

decode_reply_error_test() ->
    Msg = <<"ENOENT">>,
    %% Tag + Version + TLV(type=1, errno) + TLV(type=2, message)
    Bin = <<16#02, 1,
            1:16/big, 4:16/big, (-2):32/big-signed,
            2:16/big, (byte_size(Msg)):16/big, Msg/binary>>,
    ?assertMatch({ok, reply_error, #{code := -2, message := Msg}},
                 erlkoenig_proto:decode(Bin)).

decode_reply_container_pid_test() ->
    Ns = <<"/proc/42/ns/net">>,
    %% Tag + Version + TLV(type=1, pid) + TLV(type=2, netns)
    Bin = <<16#03, 1,
            1:16/big, 4:16/big, 42:32/big,
            2:16/big, (byte_size(Ns)):16/big, Ns/binary>>,
    ?assertMatch({ok, reply_container_pid, #{child_pid := 42, netns_path := Ns}},
                 erlkoenig_proto:decode(Bin)).

decode_reply_ready_test() ->
    ?assertEqual({ok, reply_ready, #{}}, erlkoenig_proto:decode(<<16#04, 1>>)).

decode_reply_exited_test() ->
    %% Tag + Version + TLV(type=1, exit_code) + TLV(type=2, signal)
    Bin = <<16#05, 1,
            1:16/big, 4:16/big, 0:32/big-signed,
            2:16/big, 1:16/big, 0:8>>,
    ?assertEqual({ok, reply_exited, #{exit_code => 0, term_signal => 0}},
                 erlkoenig_proto:decode(Bin)).

decode_reply_exited_signal_test() ->
    Bin = <<16#05, 1,
            1:16/big, 4:16/big, 139:32/big-signed,
            2:16/big, 1:16/big, 11:8>>,
    ?assertEqual({ok, reply_exited, #{exit_code => 139, term_signal => 11}},
                 erlkoenig_proto:decode(Bin)).

decode_reply_status_test() ->
    Bin = <<16#06, 1, 1:8, 1234:32/big, 5000:64/big>>,
    ?assertEqual({ok, reply_status,
                  #{state => 1, child_pid => 1234, uptime_ms => 5000}},
                 erlkoenig_proto:decode(Bin)).

%% stdout/stderr are streaming frames: <<Tag:8, Data/binary>> — NO version
%% byte, because the C runtime sends them raw (see erlkoenig_rt.c::forward_output).
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
    ?assertMatch({error, {unknown_tag, 16#FF}}, erlkoenig_proto:decode(<<16#FF, 1>>)).

%% =================================================================
%% Encode structure tests (TLV format)
%% =================================================================

encode_cmd_spawn_tag_test() ->
    Cmd = erlkoenig_proto:encode_cmd_spawn(<<"/bin/test">>, [], [], 0, 0, 0),
    %% Tag:8 + Version:8 + TLV attrs
    <<Tag, _Ver, _/binary>> = Cmd,
    ?assertEqual(16#10, Tag).

encode_cmd_spawn_version_test() ->
    Cmd = erlkoenig_proto:encode_cmd_spawn(#{path => <<"/app">>}),
    <<_Tag, Ver, _/binary>> = Cmd,
    ?assertEqual(1, Ver).

encode_cmd_spawn_with_image_path_test() ->
    Cmd = erlkoenig_proto:encode_cmd_spawn(#{
        path => <<"/app">>,
        image_path => <<"/tmp/test.erofs">>
    }),
    %% Image path attr (type 15) should be present
    ?assert(binary:match(Cmd, <<"/tmp/test.erofs">>) =/= nomatch).

encode_cmd_spawn_with_args_test() ->
    Cmd = erlkoenig_proto:encode_cmd_spawn(
            <<"/bin/echo">>, [<<"-n">>, <<"hello">>],
            [{<<"HOME">>, <<"/tmp">>}], 1000, 1000, 0),
    ?assert(is_binary(Cmd)),
    %% Args and env should be in the TLV payload
    ?assert(binary:match(Cmd, <<"-n">>) =/= nomatch),
    ?assert(binary:match(Cmd, <<"hello">>) =/= nomatch),
    ?assert(binary:match(Cmd, <<"HOME">>) =/= nomatch).

encode_cmd_spawn_map_test() ->
    Cmd = erlkoenig_proto:encode_cmd_spawn(#{
        path => <<"/app">>,
        uid => 1000,
        gid => 1000,
        args => [<<"--port">>, <<"8080">>],
        env => [{<<"HOME">>, <<"/tmp">>}],
        image_path => <<"/data/app.erofs">>,
        seccomp => default
    }),
    <<16#10, 1, _Attrs/binary>> = Cmd,
    ?assert(binary:match(Cmd, <<"/app">>) =/= nomatch),
    ?assert(binary:match(Cmd, <<"/data/app.erofs">>) =/= nomatch),
    ?assert(binary:match(Cmd, <<"--port">>) =/= nomatch).

encode_cmd_go_test() ->
    Cmd = erlkoenig_proto:encode_cmd_go(),
    ?assertEqual(<<16#11, 1>>, Cmd).

encode_cmd_kill_test() ->
    Cmd = erlkoenig_proto:encode_cmd_kill(9),
    <<Tag, _Ver, _Attrs/binary>> = Cmd,
    ?assertEqual(16#12, Tag).

encode_cmd_kill_sigterm_test() ->
    Cmd = erlkoenig_proto:encode_cmd_kill(15),
    <<16#12, 1, _/binary>> = Cmd,
    ok.

encode_cmd_net_setup_test() ->
    Cmd = erlkoenig_proto:encode_cmd_net_setup(
            <<"eth0">>, {10, 0, 0, 2}, 24, {10, 0, 0, 1}),
    <<Tag, _Ver, _Attrs/binary>> = Cmd,
    ?assertEqual(16#15, Tag),
    ?assert(binary:match(Cmd, <<"eth0">>) =/= nomatch).

encode_cmd_write_file_test() ->
    Cmd = erlkoenig_proto:encode_cmd_write_file(
            <<"/etc/hosts">>, 8#644, <<"127.0.0.1 localhost\n">>),
    <<Tag, _Ver, _/binary>> = Cmd,
    ?assertEqual(16#16, Tag).

encode_cmd_query_status_test() ->
    ?assertEqual(<<16#14, 1>>, erlkoenig_proto:encode_cmd_query_status()).

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
%% Volume helpers tests
%% =================================================================

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
    <<16#10, 1, _/binary>> = Cmd,
    ?assert(binary:match(Cmd, <<"/h">>) =/= nomatch),
    ?assert(binary:match(Cmd, <<"/c">>) =/= nomatch).

%% -----------------------------------------------------------------
%% Extended volume wire format
%%
%% The value of one EK_ATTR_VOLUME TLV is:
%%   host\0 container\0 flags:u32 clear:u32 prop:u8 rec:u8 dlen:u16 data
%% -----------------------------------------------------------------

-define(MS_RDONLY,  16#00000001).
-define(MS_NOSUID,  16#00000002).
-define(MS_NODEV,   16#00000004).
-define(MS_NOEXEC,  16#00000008).
-define(MS_RELATIME, 16#00200000).
-define(EK_PROP_NONE,    0).
-define(EK_PROP_PRIVATE, 1).
-define(EK_PROP_SLAVE,   2).

%% Decode the TLV *value* of an EK_ATTR_VOLUME back into a map.
%% Mirrors the wire format above; used only by tests to assert on
%% encoder output without depending on the full TLV decoder.
decode_volume_value(Bin) ->
    [Host, Rest0]       = binary:split(Bin, <<0>>),
    [Cont, Rest1]       = binary:split(Rest0, <<0>>),
    <<Flags:32/big, Clear:32/big, Prop:8, Rec:8,
      DLen:16/big, Data:DLen/binary>> = Rest1,
    #{host => Host, container => Cont,
      flags => Flags, clear => Clear,
      propagation => Prop, recursive => Rec, data => Data}.

%% Extract the bytes of the first EK_ATTR_VOLUME TLV from a spawn cmd.
first_volume_value(Cmd) ->
    <<_Tag, _Ver, Payload/binary>> = Cmd,
    find_volume(Payload).

find_volume(<<Type:16/big, Len:16/big, Val:Len/binary, Rest/binary>>) ->
    case Type of
        11 -> Val;  %% EK_ATTR_VOLUME
        _  -> find_volume(Rest)
    end;
find_volume(_) ->
    error(no_volume_tlv).

resolve_volume_opts_string_test() ->
    %% String-based opts: flags populated, data empty.
    Opts = erlkoenig_proto:resolve_volume(
             #{host => <<"/h">>, container => <<"/c">>,
               opts => <<"ro,nosuid,nodev,noexec">>}),
    Want = ?MS_RDONLY bor ?MS_NOSUID bor ?MS_NODEV bor ?MS_NOEXEC,
    ?assertEqual(Want, maps:get(flags, Opts)),
    ?assertEqual(<<>>, maps:get(data, Opts)).

resolve_volume_opts_with_data_test() ->
    Opts = erlkoenig_proto:resolve_volume(
             #{host => <<"/h">>, container => <<"/c">>,
               opts => <<"nosuid,size=64m,mode=0755">>}),
    ?assertEqual(?MS_NOSUID, maps:get(flags, Opts)),
    ?assertEqual(<<"size=64m,mode=0755">>, maps:get(data, Opts)).

resolve_volume_opts_propagation_test() ->
    Opts = erlkoenig_proto:resolve_volume(
             #{host => <<"/h">>, container => <<"/c">>,
               opts => <<"rslave">>}),
    ?assertEqual(slave, maps:get(propagation, Opts)),
    ?assertEqual(true,  maps:get(recursive, Opts)).

resolve_volume_legacy_read_only_test() ->
    %% No opts string — legacy boolean still works.
    Opts = erlkoenig_proto:resolve_volume(
             #{host => <<"/h">>, container => <<"/c">>, read_only => true}),
    ?assertEqual(?MS_RDONLY, maps:get(flags, Opts)).

resolve_volume_legacy_u32_test() ->
    %% Legacy callers pass `opts: integer()` with the ro bit set.
    Opts = erlkoenig_proto:resolve_volume(
             #{host => <<"/h">>, container => <<"/c">>, opts => 16#01}),
    ?assertEqual(?MS_RDONLY, maps:get(flags, Opts)).

resolve_volume_opts_wins_over_read_only_test() ->
    %% Both set: opts string is canonical, read_only is ignored.
    Opts = erlkoenig_proto:resolve_volume(
             #{host => <<"/h">>, container => <<"/c">>,
               opts => <<"rw">>, read_only => true}),
    ?assertEqual(0, maps:get(flags, Opts) band ?MS_RDONLY).

resolve_volume_invalid_opts_raises_test() ->
    ?assertError({invalid_mount_opts, {unknown_flag, <<"nosudi">>}, _},
                 erlkoenig_proto:resolve_volume(
                   #{host => <<"/h">>, container => <<"/c">>,
                     opts => <<"nosudi">>})).

resolve_volume_default_test() ->
    Opts = erlkoenig_proto:resolve_volume(
             #{host => <<"/h">>, container => <<"/c">>}),
    ?assertEqual(0, maps:get(flags, Opts)),
    ?assertEqual(none, maps:get(propagation, Opts)),
    ?assertEqual(<<>>, maps:get(data, Opts)).

encode_volume_tlv_shape_test() ->
    %% End-to-end: string opts survive through the wire shape.
    Bin = erlkoenig_proto:encode_volume_tlv(
            #{host => <<"/srv/data">>, container => <<"/data">>,
              opts => <<"ro,nosuid">>}),
    V = decode_volume_value(Bin),
    ?assertEqual(<<"/srv/data">>, maps:get(host, V)),
    ?assertEqual(<<"/data">>, maps:get(container, V)),
    ?assertEqual(?MS_RDONLY bor ?MS_NOSUID, maps:get(flags, V)),
    ?assertEqual(?EK_PROP_NONE, maps:get(propagation, V)),
    ?assertEqual(0, maps:get(recursive, V)),
    ?assertEqual(<<>>, maps:get(data, V)).

encode_volume_tlv_with_data_test() ->
    Bin = erlkoenig_proto:encode_volume_tlv(
            #{host => <<"tmpfs">>, container => <<"/tmp">>,
              opts => <<"nosuid,size=64m">>}),
    V = decode_volume_value(Bin),
    ?assertEqual(?MS_NOSUID, maps:get(flags, V)),
    ?assertEqual(<<"size=64m">>, maps:get(data, V)).

encode_volume_tlv_propagation_test() ->
    Bin = erlkoenig_proto:encode_volume_tlv(
            #{host => <<"/a">>, container => <<"/b">>,
              opts => <<"rslave">>}),
    V = decode_volume_value(Bin),
    ?assertEqual(?EK_PROP_SLAVE, maps:get(propagation, V)),
    ?assertEqual(1, maps:get(recursive, V)).

encode_volume_tlv_legacy_boolean_test() ->
    Bin = erlkoenig_proto:encode_volume_tlv(
            #{host => <<"/a">>, container => <<"/b">>, read_only => true}),
    V = decode_volume_value(Bin),
    ?assertEqual(?MS_RDONLY, maps:get(flags, V)),
    ?assertEqual(<<>>, maps:get(data, V)).

encode_volume_tlv_legacy_u32_zero_test() ->
    %% opts => 0 from the 11-arg legacy API — should produce a clean
    %% default (no flags, no data).
    Bin = erlkoenig_proto:encode_volume_tlv(
            #{host => <<"/a">>, container => <<"/b">>, opts => 0}),
    V = decode_volume_value(Bin),
    ?assertEqual(0, maps:get(flags, V)),
    ?assertEqual(<<>>, maps:get(data, V)).

encode_cmd_spawn_volume_struct_test() ->
    %% The wire format inside a full CMD_SPAWN matches the struct.
    Cmd = erlkoenig_proto:encode_cmd_spawn(#{
        path => <<"/app">>,
        volumes => [#{host => <<"/srv">>, container => <<"/srv">>,
                      opts => <<"ro,nosuid,relatime">>}]
    }),
    V = decode_volume_value(first_volume_value(Cmd)),
    Want = ?MS_RDONLY bor ?MS_NOSUID bor ?MS_RELATIME,
    ?assertEqual(Want, maps:get(flags, V)).

%% =================================================================
%% Handshake tests
%% =================================================================

handshake_version_test() ->
    ?assertEqual(1, erlkoenig_proto:protocol_version()).

handshake_encode_test() ->
    H = erlkoenig_proto:encode_handshake(),
    ?assertEqual(<<1>>, H).

handshake_check_v1_test() ->
    ?assertEqual(ok, erlkoenig_proto:check_handshake_reply(<<1>>)).

handshake_check_v2_test() ->
    ?assertEqual(ok, erlkoenig_proto:check_handshake_reply(<<2, 0:256>>)).

handshake_check_bad_test() ->
    ?assertMatch({error, _}, erlkoenig_proto:check_handshake_reply(<<99>>)).
