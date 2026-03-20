-module(erlkoenig_ctl_proto_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

roundtrip_test_() ->
    Cmds = [spawn, stop, ps, inspect, audit, status],
    [{atom_to_list(C), fun() ->
        ReqId = rand:uniform(16#FFFFFFFF),
        Payload = <<"test payload">>,
        Encoded = erlkoenig_ctl_proto:encode_request(ReqId, C, Payload),
        {ok, {ReqId2, Cmd, Pay}} = erlkoenig_ctl_proto:decode_request(Encoded),
        ?assertEqual(ReqId, ReqId2),
        ?assertEqual(C, Cmd),
        ?assertEqual(Payload, Pay)
    end} || C <- Cmds].

response_ok_test() ->
    Resp = erlkoenig_ctl_proto:encode_response(42, ok, <<"data">>),
    {ok, {42, ok, <<"data">>}} = erlkoenig_ctl_proto:decode_response(Resp).

response_error_test() ->
    Resp = erlkoenig_ctl_proto:encode_response(99, error, <<"bad">>),
    {ok, {99, error, <<"bad">>}} = erlkoenig_ctl_proto:decode_response(Resp).

unknown_command_test() ->
    Bad = <<1:32/big, 16#FF:8, "payload">>,
    ?assertEqual({error, {unknown_command, 16#FF}},
                 erlkoenig_ctl_proto:decode_request(Bad)).

invalid_request_test() ->
    ?assertEqual({error, invalid_request},
                 erlkoenig_ctl_proto:decode_request(<<1, 2>>)).

str_roundtrip_test() ->
    Bin = <<"hello world">>,
    Encoded = erlkoenig_ctl_proto:encode_str(Bin),
    {Bin, <<>>} = erlkoenig_ctl_proto:decode_str(Encoded).

str_with_rest_test() ->
    Bin = <<"foo">>,
    Rest = <<"remaining">>,
    Encoded = <<(erlkoenig_ctl_proto:encode_str(Bin))/binary, Rest/binary>>,
    {Bin, Rest} = erlkoenig_ctl_proto:decode_str(Encoded).
