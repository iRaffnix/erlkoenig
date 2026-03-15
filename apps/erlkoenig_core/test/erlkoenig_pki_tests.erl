-module(erlkoenig_pki_tests).

-include_lib("eunit/include/eunit.hrl").

fixture(Name) ->
    {ok, Cwd} = file:get_cwd(),
    filename:join([Cwd, "apps", "erlkoenig_core", "test", "fixtures", Name]).

read_cert(Name) ->
    {ok, PemBin} = file:read_file(fixture(Name)),
    [{'Certificate', Der, _}] = public_key:pem_decode(PemBin),
    Der.

setup() ->
    application:set_env(erlkoenig_core, signature, #{
        mode => on,
        trust_roots => [fixture("root-ca.pem")],
        min_chain_depth => 2
    }),
    %% audit must be running for pki init
    AuditPath = "/tmp/erlkoenig_pki_test_" ++
                integer_to_list(erlang:unique_integer([positive])) ++ "/audit.jsonl",
    application:set_env(erlkoenig_core, audit_path, AuditPath),
    {ok, AuditPid} = erlkoenig_audit:start_link(),
    {ok, PkiPid} = erlkoenig_pki:start_link(),
    {PkiPid, AuditPid, AuditPath}.

cleanup({PkiPid, AuditPid, AuditPath}) ->
    gen_server:stop(PkiPid),
    gen_server:stop(AuditPid),
    file:delete(AuditPath),
    file:del_dir(filename:dirname(AuditPath)),
    application:unset_env(erlkoenig_core, signature),
    application:unset_env(erlkoenig_core, audit_path).

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
          application:set_env(erlkoenig_core, signature, #{
              mode => on,
              trust_roots => [fixture("root-ca.pem")],
              min_chain_depth => 3
          }),
          AuditPath = "/tmp/erlkoenig_pki_depth_" ++
                      integer_to_list(erlang:unique_integer([positive])) ++ "/audit.jsonl",
          application:set_env(erlkoenig_core, audit_path, AuditPath),
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
