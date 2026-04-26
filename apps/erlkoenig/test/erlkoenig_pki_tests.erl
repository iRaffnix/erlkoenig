-module(erlkoenig_pki_tests).

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

read_cert(Name) ->
    {ok, PemBin} = file:read_file(fixture(Name)),
    [{'Certificate', Der, _}] = public_key:pem_decode(PemBin),
    Der.

setup() ->
    application:set_env(erlkoenig, signature, #{
        mode => on,
        trust_roots => [fixture("root-ca.pem")],
        min_chain_depth => 2
    }),
    %% audit must be running for pki init
    AuditPath = "/tmp/erlkoenig_pki_test_" ++
                integer_to_list(erlang:unique_integer([positive])) ++ "/audit.jsonl",
    application:set_env(erlkoenig, audit_path, AuditPath),
    {ok, AuditPid} = erlkoenig_audit:start_link(),
    {ok, PkiPid} = erlkoenig_pki:start_link(),
    {PkiPid, AuditPid, AuditPath}.

cleanup({PkiPid, AuditPid, AuditPath}) ->
    gen_server:stop(PkiPid),
    gen_server:stop(AuditPid),
    file:delete(AuditPath),
    file:del_dir(filename:dirname(AuditPath)),
    application:unset_env(erlkoenig, signature),
    application:unset_env(erlkoenig, audit_path).

%% --- Tests ---

valid_chain_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun({_, _, _}) ->
         [fun() ->
              Signing = read_cert("signing.pem"),
              SubCA = read_cert("sub-ca.pem"),
              %% Chain: [leaf, intermediate] — root is in trust store
              ?assertEqual(ok, erlkoenig_pki:verify_chain([Signing, SubCA]))
          end]
     end}.

direct_signing_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun({_, _, _}) ->
         [fun() ->
              %% Sub-CA directly signed by root (depth 2: root + sub-ca)
              SubCA = read_cert("sub-ca.pem"),
              ?assertEqual(ok, erlkoenig_pki:verify_chain([SubCA]))
          end]
     end}.

untrusted_root_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun({_, _, _}) ->
         [fun() ->
              WrongSigning = read_cert("wrong-signing.pem"),
              WrongCA = read_cert("wrong-ca.pem"),
              ?assertEqual({error, untrusted_root},
                           erlkoenig_pki:verify_chain([WrongSigning, WrongCA]))
          end]
     end}.

chain_too_short_test_() ->
    {"chain too short with min_depth=3",
     {setup,
      fun() ->
          application:set_env(erlkoenig, signature, #{
              mode => on,
              trust_roots => [fixture("root-ca.pem")],
              min_chain_depth => 3
          }),
          AuditPath = "/tmp/erlkoenig_pki_depth_" ++
                      integer_to_list(erlang:unique_integer([positive])) ++ "/audit.jsonl",
          application:set_env(erlkoenig, audit_path, AuditPath),
          {ok, AuditPid} = erlkoenig_audit:start_link(),
          {ok, PkiPid} = erlkoenig_pki:start_link(),
          {PkiPid, AuditPid, AuditPath}
      end,
      fun cleanup/1,
      fun({_, _, _}) ->
          [fun() ->
               %% Only 1 cert in chain + root = depth 2, but min is 3
               SubCA = read_cert("sub-ca.pem"),
               ?assertEqual({error, chain_too_short},
                            erlkoenig_pki:verify_chain([SubCA]))
           end]
      end}}.

mode_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun({_, _, _}) ->
         [fun() ->
              ?assertEqual(on, erlkoenig_pki:mode())
          end]
     end}.

reload_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun({_, _, _}) ->
         [fun() ->
              ?assertEqual(ok, erlkoenig_pki:reload())
          end]
     end}.

%% --- Node cert hash — strict-mode semantics ---
%%
%% Regression guard for Muster 3 bug: `load_node_cert_hash` used to
%% return the PEM's SHA-256 even when the chain was invalid in `on`
%% mode, with a comment saying "handshake runs anyway". That diverged
%% from sig-verify semantics (which rejects in `on` mode) and meant
%% downstream callers reading `node_cert_hash/0` as a "valid cert
%% present" indicator got misleading data. Fix: `on` + invalid chain
%% → <<0:256>>, same as file-not-found.

node_cert_invalid_chain_strict_returns_zero_test_() ->
    {"strict mode + invalid chain → node_cert_hash is zero",
     {setup,
      fun() -> setup_with_node_cert(on, "wrong-signing.pem") end,
      fun cleanup_with_node_cert/1,
      fun({_, _, _, _}) ->
          [fun() ->
               %% wrong-signing.pem chains to wrong-ca.pem (not our
               %% trust root). In on mode that must disable identity.
               ?assertEqual(<<0:256>>, erlkoenig_pki:node_cert_hash())
           end]
      end}}.

node_cert_valid_chain_strict_returns_hash_test_() ->
    {"strict mode + valid chain (leaf+intermediate) → node_cert_hash is set",
     {setup,
      fun() ->
          %% Build a combined PEM (leaf + intermediate) so the chain
          %% anchors to the trusted root. signing.pem alone doesn't
          %% pass pkix_path_validation because sub-ca.pem is missing.
          ChainPath = write_combined_pem(["signing.pem", "sub-ca.pem"]),
          setup_with_node_cert_abs(on, ChainPath)
      end,
      fun cleanup_with_node_cert/1,
      fun({_, _, _, _}) ->
          [fun() ->
               Hash = erlkoenig_pki:node_cert_hash(),
               ?assertEqual(32, byte_size(Hash)),
               ?assertNotEqual(<<0:256>>, Hash)
           end]
      end}}.

node_cert_invalid_chain_warn_returns_hash_test_() ->
    {"warn mode + invalid chain → node_cert_hash still returned (permissive)",
     {setup,
      fun() -> setup_with_node_cert(warn, "wrong-signing.pem") end,
      fun cleanup_with_node_cert/1,
      fun({_, _, _, _}) ->
          [fun() ->
               Hash = erlkoenig_pki:node_cert_hash(),
               ?assertEqual(32, byte_size(Hash)),
               ?assertNotEqual(<<0:256>>, Hash)
           end]
      end}}.

%% Helpers for the three tests above — same shape as setup/0 but
%% with node_cert config wired in BEFORE start_link so init picks it up.
setup_with_node_cert(Mode, CertName) ->
    application:set_env(erlkoenig, signature, #{
        mode => Mode,
        trust_roots => [fixture("root-ca.pem")],
        min_chain_depth => 2
    }),
    application:set_env(erlkoenig, node_cert, #{
        cert_path => fixture(CertName)
    }),
    AuditPath = "/tmp/erlkoenig_pki_node_cert_test_" ++
                integer_to_list(erlang:unique_integer([positive])) ++
                "/audit.jsonl",
    application:set_env(erlkoenig, audit_path, AuditPath),
    {ok, AuditPid} = erlkoenig_audit:start_link(),
    {ok, PkiPid} = erlkoenig_pki:start_link(),
    {PkiPid, AuditPid, AuditPath, CertName}.

cleanup_with_node_cert({PkiPid, AuditPid, AuditPath, CertPath}) ->
    gen_server:stop(PkiPid),
    gen_server:stop(AuditPid),
    file:delete(AuditPath),
    file:del_dir(filename:dirname(AuditPath)),
    %% Only delete the combined-chain file if it's one we wrote
    %% (absolute /tmp path, not a fixture).
    case CertPath of
        "/tmp/erlkoenig_pki_chain_" ++ _ -> file:delete(CertPath);
        _ -> ok
    end,
    application:unset_env(erlkoenig, signature),
    application:unset_env(erlkoenig, node_cert),
    application:unset_env(erlkoenig, audit_path).

%% Build a temporary PEM file concatenating the given fixture certs.
%% Returns the absolute path. Caller is responsible for deletion.
write_combined_pem(FixtureNames) ->
    Combined = iolist_to_binary(
                 [begin
                      {ok, B} = file:read_file(fixture(N)),
                      B
                  end || N <- FixtureNames]),
    Path = "/tmp/erlkoenig_pki_chain_" ++
           integer_to_list(erlang:unique_integer([positive])) ++ ".pem",
    ok = file:write_file(Path, Combined),
    Path.

%% Variant of setup_with_node_cert/2 that takes an already-resolved
%% absolute cert path (so tests can build chain files dynamically).
setup_with_node_cert_abs(Mode, AbsCertPath) ->
    application:set_env(erlkoenig, signature, #{
        mode => Mode,
        trust_roots => [fixture("root-ca.pem")],
        min_chain_depth => 2
    }),
    application:set_env(erlkoenig, node_cert, #{
        cert_path => AbsCertPath
    }),
    AuditPath = "/tmp/erlkoenig_pki_node_cert_test_" ++
                integer_to_list(erlang:unique_integer([positive])) ++
                "/audit.jsonl",
    application:set_env(erlkoenig, audit_path, AuditPath),
    {ok, AuditPid} = erlkoenig_audit:start_link(),
    {ok, PkiPid} = erlkoenig_pki:start_link(),
    {PkiPid, AuditPid, AuditPath, AbsCertPath}.
