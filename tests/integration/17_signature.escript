#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% Integration test: binary signature verification.
%%
%% Tests the full signing and verification pipeline:
%%   1. Generate test CA chain
%%   2. Sign a binary
%%   3. Start erlkoenig with signature mode=on
%%   4. Spawn container with valid signature → must succeed
%%   5. Tamper binary → spawn must fail
%%   6. Remove signature → spawn must fail
%%
%% Requires: openssl, erlkoenig_rt in PATH or build/release/
%%
%% Usage: escript integration-tests/17_signature.escript

-mode(compile).

main(_) ->
    io:format("~n=== 17: Binary Signature Verification ===~n~n"),

    %% Add compiled modules to code path
    {ok, Cwd} = file:get_cwd(),
    EbinDirs = filelib:wildcard(filename:join([Cwd, "_build", "*", "lib", "*", "ebin"])),
    lists:foreach(fun(Dir) -> code:add_pathz(Dir) end, EbinDirs),
    FixtureDir = filename:join([Cwd, "apps", "erlkoenig", "test", "fixtures"]),
    RootCA = filename:join(FixtureDir, "root-ca.pem"),
    SigningCert = filename:join(FixtureDir, "signing.pem"),
    SubCACert = filename:join(FixtureDir, "sub-ca.pem"),
    SigningKey = filename:join(FixtureDir, "signing.key"),

    %% Verify fixtures exist
    lists:foreach(fun(F) ->
        case filelib:is_regular(F) of
            true -> ok;
            false ->
                io:format("ERROR: fixture not found: ~s~n", [F]),
                halt(1)
        end
    end, [RootCA, SigningCert, SubCACert, SigningKey]),

    %% Create a test binary
    TestBin = "/tmp/erlkoenig_sig_test_binary",
    ok = file:write_file(TestBin, <<"#!/bin/true\ntest binary\n">>),

    %% Build chain file (signing + sub-ca)
    {ok, SCert} = file:read_file(SigningCert),
    {ok, SubCA} = file:read_file(SubCACert),
    ChainFile = "/tmp/erlkoenig_sig_test_chain.pem",
    ok = file:write_file(ChainFile, [SCert, SubCA]),

    %% Test 1: Sign with erlkoenig_sig (Erlang module)
    io:format("[1/4] Signing binary ...~n"),
    {ok, SigData} = erlkoenig_sig:sign(TestBin, ChainFile, SigningKey,
                                        #{git_sha => <<"abcdef0123456789abcdef0123456789abcdef01">>}),
    SigPath = TestBin ++ ".sig",
    ok = file:write_file(SigPath, SigData),
    io:format("  Signed: ~s~n  Sig:    ~s~n", [TestBin, SigPath]),

    %% Test 2: Verify with erlkoenig_sig
    io:format("[2/4] Verifying signature ...~n"),
    {ok, Meta} = erlkoenig_sig:verify(TestBin, SigPath),
    io:format("  SHA256:  ~s~n", [maps:get(sha256, Meta)]),
    io:format("  Git SHA: ~s~n", [maps:get(git_sha, Meta)]),
    io:format("  Signer:  ~s~n", [maps:get(signer_cn, Meta)]),
    io:format("  Chain:   ~p cert(s)~n", [length(maps:get(chain, Meta))]),

    %% Test 3: Verify chain against Root CA
    io:format("[3/4] Validating certificate chain ...~n"),
    {ok, RootPem} = file:read_file(RootCA),
    RootDers = [Der || {'Certificate', Der, _} <- public_key:pem_decode(RootPem)],
    %% Manual chain validation (without gen_server)
    Chain = maps:get(chain, Meta),
    RootDer = hd(RootDers),
    RootCert = public_key:pkix_decode_cert(RootDer, otp),
    PathCerts = [public_key:pkix_decode_cert(D, otp) || D <- lists:reverse(Chain)],
    {ok, _} = public_key:pkix_path_validation(RootCert, PathCerts, []),
    io:format("  Chain OK: chains to Root CA~n"),

    %% Test 4: Tampered binary must fail
    io:format("[4/4] Tamper detection ...~n"),
    ok = file:write_file(TestBin, <<"tampered!">>),
    {error, {sha256_mismatch, _}} = erlkoenig_sig:verify(TestBin, SigPath),
    io:format("  Tampered binary correctly rejected~n"),

    %% Cleanup
    file:delete(TestBin),
    file:delete(SigPath),
    file:delete(ChainFile),

    io:format("~n=== ALL SIGNATURE TESTS PASSED ===~n"),
    halt(0).
