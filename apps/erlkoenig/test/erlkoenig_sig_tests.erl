-module(erlkoenig_sig_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

fixture(Name) ->
    {ok, Cwd} = file:get_cwd(),
    Dir = filename:join([Cwd, "apps", "erlkoenig", "test", "fixtures"]),
    ensure_fixtures(Dir),
    filename:join(Dir, Name).

ensure_fixtures(Dir) ->
    case filelib:is_regular(filename:join(Dir, "root-ca.pem")) of
        true -> ok;
        false -> os:cmd("bash " ++ filename:join(Dir, "generate.sh"))
    end.

test_binary() ->
    Path = "/tmp/erlkoenig_sig_test_binary_" ++
           integer_to_list(erlang:unique_integer([positive])),
    ok = file:write_file(Path, <<"#!/bin/true\nstatic test binary\n">>),
    Path.

%% --- Sign + Verify roundtrip ---

roundtrip_test() ->
    BinPath = test_binary(),
    SigPath = BinPath ++ ".sig",
    try
        {ok, SigData} = erlkoenig_sig:sign(
            BinPath,
            fixture("signing.pem"),
            fixture("signing.key"),
            #{git_sha => <<"abcdef0123456789abcdef0123456789abcdef01">>}
        ),
        ok = file:write_file(SigPath, SigData),

        {ok, Meta} = erlkoenig_sig:verify(BinPath, SigPath),
        ?assertEqual(<<"test-pipeline">>, maps:get(signer_cn, Meta)),
        ?assertNotEqual(<<>>, maps:get(sha256, Meta)),
        ?assertNotEqual(<<"0000000000000000000000000000000000000000">>, maps:get(git_sha, Meta)),
        ?assert(is_integer(maps:get(timestamp, Meta))),
        ?assert(length(maps:get(chain, Meta)) >= 1)
    after
        file:delete(BinPath),
        file:delete(SigPath)
    end.

roundtrip_no_git_sha_test() ->
    BinPath = test_binary(),
    SigPath = BinPath ++ ".sig",
    try
        {ok, SigData} = erlkoenig_sig:sign(
            BinPath,
            fixture("signing.pem"),
            fixture("signing.key"),
            #{}
        ),
        ok = file:write_file(SigPath, SigData),

        {ok, Meta} = erlkoenig_sig:verify(BinPath, SigPath),
        %% Git SHA should be all zeros (hex)
        ?assertEqual(<<"0000000000000000000000000000000000000000">>, maps:get(git_sha, Meta))
    after
        file:delete(BinPath),
        file:delete(SigPath)
    end.

%% --- Tamper detection ---

tampered_binary_test() ->
    BinPath = test_binary(),
    SigPath = BinPath ++ ".sig",
    try
        {ok, SigData} = erlkoenig_sig:sign(
            BinPath, fixture("signing.pem"), fixture("signing.key"), #{}),
        ok = file:write_file(SigPath, SigData),

        %% Tamper with the binary
        ok = file:write_file(BinPath, <<"tampered content">>),

        ?assertMatch({error, {sha256_mismatch, _}},
                     erlkoenig_sig:verify(BinPath, SigPath))
    after
        file:delete(BinPath),
        file:delete(SigPath)
    end.

tampered_signature_test() ->
    BinPath = test_binary(),
    SigPath = BinPath ++ ".sig",
    try
        {ok, SigData} = erlkoenig_sig:sign(
            BinPath, fixture("signing.pem"), fixture("signing.key"), #{}),
        %% Flip a byte near the start (inside the signature block, not the cert)
        SigBin = iolist_to_binary(SigData),
        Pos = 80,  %% inside the base64 signature payload
        <<Pre:Pos/binary, Byte:8, Post/binary>> = SigBin,
        Tampered = <<Pre/binary, (Byte bxor 16#FF):8, Post/binary>>,
        ok = file:write_file(SigPath, Tampered),

        Result = erlkoenig_sig:verify(BinPath, SigPath),
        ?assertMatch({error, _}, Result)
    after
        file:delete(BinPath),
        file:delete(SigPath)
    end.

%% --- Error cases ---

missing_sig_file_test() ->
    BinPath = test_binary(),
    try
        ?assertEqual({error, sig_not_found},
                     erlkoenig_sig:verify(BinPath, "/nonexistent.sig"))
    after
        file:delete(BinPath)
    end.

missing_binary_test() ->
    ?assertMatch({error, {read_failed, _, enoent}},
                 erlkoenig_sig:verify("/nonexistent_binary", "/nonexistent.sig")).

%% --- Payload encoding ---

payload_roundtrip_test() ->
    SHA256 = crypto:hash(sha256, <<"test">>),
    GitSHA = <<1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20>>,
    Input = #{sha256 => SHA256, git_sha => GitSHA,
              timestamp => 1710500000, signer_cn => <<"my-pipeline">>},
    Encoded = erlkoenig_sig:encode_payload(Input),
    {ok, Decoded} = erlkoenig_sig:decode_payload(Encoded),
    ?assertEqual(SHA256, maps:get(sha256, Decoded)),
    ?assertEqual(GitSHA, maps:get(git_sha, Decoded)),
    ?assertEqual(1710500000, maps:get(timestamp, Decoded)),
    ?assertEqual(<<"my-pipeline">>, maps:get(signer_cn, Decoded)).

payload_invalid_version_test() ->
    %% Version 99
    Bad = <<99:8, 1:8, 0:(32*8), 0:(20*8), 0:64, 0:16>>,
    ?assertMatch({error, {unsupported_version, 99}},
                 erlkoenig_sig:decode_payload(Bad)).

%% --- Chain in .sig file ---

chain_included_test() ->
    BinPath = test_binary(),
    SigPath = BinPath ++ ".sig",
    try
        %% Build a cert chain file: signing + sub-ca
        {ok, SigningPem} = file:read_file(fixture("signing.pem")),
        {ok, SubCaPem} = file:read_file(fixture("sub-ca.pem")),
        ChainFile = BinPath ++ ".chain.pem",
        ok = file:write_file(ChainFile, [SigningPem, SubCaPem]),

        {ok, SigData} = erlkoenig_sig:sign(
            BinPath, ChainFile, fixture("signing.key"), #{}),
        ok = file:write_file(SigPath, SigData),

        {ok, Meta} = erlkoenig_sig:verify(BinPath, SigPath),
        %% Should have 2 certs in chain (signing + sub-ca)
        ?assertEqual(2, length(maps:get(chain, Meta)))
    after
        file:delete(BinPath),
        file:delete(SigPath),
        file:delete(BinPath ++ ".chain.pem")
    end.
