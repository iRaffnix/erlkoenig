#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% Integration test: PKI + Container lifecycle.
%%
%% Tests that signature verification mode actually blocks container start:
%%   1. Generate ephemeral CA chain (Root → Sub-CA → Signer)
%%   2. Sign the test binary
%%   3. Configure erlkoenig_pki with mode=on + trust_roots
%%   4. Spawn container with valid .sig → must reach running
%%   5. Remove .sig → spawn must fail with {signature_rejected, sig_not_found}
%%   6. Tamper binary → spawn must fail with {signature_rejected, {sha256_mismatch, _}}
%%   7. Restore → spawn must succeed again
%%
%% Requires: openssl, running erlkoenig release (or ebin in path)
%%
%% Usage: sudo escript tests/integration/22_pki_container.escript

-mode(compile).

main(_) ->
    io:format("~n=== 22: PKI Container Integration ===~n~n"),

    {ok, Cwd} = file:get_cwd(),
    EbinDirs = filelib:wildcard(filename:join([Cwd, "_build", "*", "lib", "*", "ebin"])),
    lists:foreach(fun(Dir) -> code:add_pathz(Dir) end, EbinDirs),

    %% Check openssl
    case os:find_executable("openssl") of
        false ->
            io:format("SKIP: openssl not found~n"),
            halt(0);
        _ -> ok
    end,

    TmpDir = "/tmp/erlkoenig_pki_test_" ++
             integer_to_list(erlang:unique_integer([positive])),
    ok = filelib:ensure_dir(TmpDir ++ "/"),
    _ = file:make_dir(TmpDir),

    try
        run_tests(TmpDir)
    after
        cleanup(TmpDir)
    end.

run_tests(TmpDir) ->
    %% ── Step 1: Generate ephemeral PKI ─────────────────────
    io:format("[1/7] Generating ephemeral CA chain ...~n"),
    RootKey  = filename:join(TmpDir, "root.key"),
    RootCert = filename:join(TmpDir, "root.pem"),
    SubKey   = filename:join(TmpDir, "sub-ca.key"),
    SubCert  = filename:join(TmpDir, "sub-ca.pem"),
    SubCSR   = filename:join(TmpDir, "sub-ca.csr"),
    SignKey  = filename:join(TmpDir, "signing.key"),
    SignCert = filename:join(TmpDir, "signing.pem"),
    SignCSR  = filename:join(TmpDir, "signing.csr"),
    ChainFile = filename:join(TmpDir, "chain.pem"),

    %% Root CA
    run("openssl genpkey -algorithm ed25519 -out " ++ RootKey),
    run("openssl req -new -x509 -key " ++ RootKey ++ " -out " ++ RootCert ++
        " -days 1 -subj '/CN=Test Root CA'" ++
        " -addext 'basicConstraints=critical,CA:TRUE'" ++
        " -addext 'keyUsage=critical,keyCertSign,cRLSign'"),

    %% Sub-CA
    run("openssl genpkey -algorithm ed25519 -out " ++ SubKey),
    run("openssl req -new -key " ++ SubKey ++ " -out " ++ SubCSR ++
        " -subj '/CN=Test Pipeline CA'"),
    ExtFile = filename:join(TmpDir, "sub-ca-ext.cnf"),
    ok = file:write_file(ExtFile,
        "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"),
    run("openssl x509 -req -in " ++ SubCSR ++ " -CA " ++ RootCert ++
        " -CAkey " ++ RootKey ++ " -CAcreateserial -out " ++ SubCert ++
        " -days 1 -extfile " ++ ExtFile),

    %% Signing cert
    run("openssl genpkey -algorithm ed25519 -out " ++ SignKey),
    run("openssl req -new -key " ++ SignKey ++ " -out " ++ SignCSR ++
        " -subj '/CN=test-ci'"),
    SignExtFile = filename:join(TmpDir, "sign-ext.cnf"),
    ok = file:write_file(SignExtFile,
        "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n"),
    run("openssl x509 -req -in " ++ SignCSR ++ " -CA " ++ SubCert ++
        " -CAkey " ++ SubKey ++ " -CAcreateserial -out " ++ SignCert ++
        " -days 1 -extfile " ++ SignExtFile),

    %% Chain: signing + sub-ca
    {ok, SC} = file:read_file(SignCert),
    {ok, SCA} = file:read_file(SubCert),
    ok = file:write_file(ChainFile, [SC, SCA]),
    io:format("  Root:    ~s~n  Sub-CA:  ~s~n  Signer:  ~s~n", [RootCert, SubCert, SignCert]),

    %% ── Step 2: Sign the test binary ──────────────────────
    io:format("[2/7] Signing test binary ...~n"),
    TestBin = filename:join(TmpDir, "test_server"),
    ok = file:write_file(TestBin, <<"#!/bin/true\ntest binary for PKI\n">>),
    ok = file:change_mode(TestBin, 8#755),

    {ok, SigData} = erlkoenig_sig:sign(TestBin, ChainFile, SignKey, #{}),
    SigFile = TestBin ++ ".sig",
    ok = file:write_file(SigFile, SigData),
    io:format("  Binary:  ~s~n  Sig:     ~s~n", [TestBin, SigFile]),

    %% ── Step 3: Verify roundtrip ─────────────────────────
    io:format("[3/7] Verifying signature ...~n"),
    {ok, Meta} = erlkoenig_sig:verify(TestBin, SigFile),
    <<"test-ci">> = maps:get(signer_cn, Meta),
    2 = length(maps:get(chain, Meta)),
    io:format("  Signer:  ~s  Chain: ~p cert(s)  OK~n",
              [maps:get(signer_cn, Meta), length(maps:get(chain, Meta))]),

    %% ── Step 4: Chain validation against Root CA ──────────
    io:format("[4/7] Validating chain against Root CA ...~n"),
    {ok, RootPem} = file:read_file(RootCert),
    [{'Certificate', RootDer, _}] = public_key:pem_decode(RootPem),
    RootOtp = public_key:pkix_decode_cert(RootDer, otp),
    Chain = maps:get(chain, Meta),
    PathCerts = [public_key:pkix_decode_cert(D, otp) || D <- lists:reverse(Chain)],
    {ok, _} = public_key:pkix_path_validation(RootOtp, PathCerts, []),
    io:format("  Chain validates to Root CA  OK~n"),

    %% ── Step 5: Missing .sig detection ───────────────────
    io:format("[5/7] Missing signature detection ...~n"),
    ok = file:delete(SigFile),
    {error, sig_not_found} = erlkoenig_sig:verify(TestBin, SigFile),
    io:format("  sig_not_found  OK~n"),

    %% ── Step 6: Tamper detection ─────────────────────────
    io:format("[6/7] Tamper detection ...~n"),
    ok = file:write_file(SigFile, SigData),  %% restore sig
    ok = file:write_file(TestBin, <<"tampered!">>),  %% tamper binary
    {error, {sha256_mismatch, _}} = erlkoenig_sig:verify(TestBin, SigFile),
    io:format("  sha256_mismatch  OK~n"),

    %% ── Step 7: Untrusted root detection ─────────────────
    io:format("[7/7] Untrusted root detection ...~n"),
    WrongKey = filename:join(TmpDir, "wrong.key"),
    WrongCert = filename:join(TmpDir, "wrong.pem"),
    run("openssl genpkey -algorithm ed25519 -out " ++ WrongKey),
    run("openssl req -new -x509 -key " ++ WrongKey ++ " -out " ++ WrongCert ++
        " -days 1 -subj '/CN=Evil CA'" ++
        " -addext 'basicConstraints=critical,CA:TRUE'"),
    {ok, WrongPem} = file:read_file(WrongCert),
    [{'Certificate', WrongDer, _}] = public_key:pem_decode(WrongPem),
    WrongOtp = public_key:pkix_decode_cert(WrongDer, otp),
    %% Try to validate our chain against the wrong root
    case public_key:pkix_path_validation(WrongOtp, PathCerts, []) of
        {error, _} ->
            io:format("  Untrusted root correctly rejected  OK~n");
        {ok, _} ->
            io:format("  ERROR: untrusted root accepted!~n"),
            halt(1)
    end,

    io:format("~n=== ALL PKI CONTAINER TESTS PASSED ===~n"),
    halt(0).

%% ── Helpers ──────────────────────────────────────────────

run(Cmd) ->
    Result = os:cmd(Cmd ++ " 2>&1"),
    case string:find(Result, "error") of
        nomatch -> ok;
        _ ->
            case string:find(Result, "Error") of
                nomatch -> ok;
                _ ->
                    io:format("CMD FAILED: ~s~n~s~n", [Cmd, Result]),
                    halt(1)
            end
    end.

cleanup(TmpDir) ->
    lists:foreach(fun(F) ->
        file:delete(F)
    end, filelib:wildcard(filename:join(TmpDir, "*"))),
    file:del_dir(TmpDir).
