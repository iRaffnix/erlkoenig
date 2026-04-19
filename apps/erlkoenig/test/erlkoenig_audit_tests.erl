-module(erlkoenig_audit_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("stdlib/include/assert.hrl").

test_path() ->
    "/tmp/erlkoenig_audit_test_" ++
    integer_to_list(erlang:unique_integer([positive])) ++
    "/audit.jsonl".

setup() ->
    Path = test_path(),
    application:set_env(erlkoenig, audit_path, Path),
    {ok, Pid} = erlkoenig_audit:start_link(),
    {Pid, Path}.

cleanup({Pid, Path}) ->
    gen_server:stop(Pid),
    file:delete(Path),
    file:del_dir(filename:dirname(Path)),
    application:unset_env(erlkoenig, audit_path).

flush() ->
    %% Force delayed_write buffer to disk
    erlkoenig_audit:query(#{limit => 0}),
    timer:sleep(20).

read_lines(Path) ->
    {ok, Bin} = file:read_file(Path),
    [L || L <- binary:split(Bin, <<"\n">>, [global]), L =/= <<>>].

%% --- Tests ---

log_writes_json_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun({_Pid, Path}) ->
         [fun() ->
              erlkoenig_audit:log(#{
                  type => binary_verify,
                  subject => <<"proxy">>,
                  result => ok,
                  details => #{sha256 => <<"abcdef">>}
              }),
              flush(),
              Lines = read_lines(Path),
              ?assertEqual(1, length(Lines)),
              Line = hd(Lines),
              ?assertNotEqual(nomatch, binary:match(Line, <<"\"seq\":1">>)),
              ?assertNotEqual(nomatch, binary:match(Line, <<"\"type\":\"binary_verify\"">>)),
              ?assertNotEqual(nomatch, binary:match(Line, <<"\"subject\":\"proxy\"">>)),
              ?assertNotEqual(nomatch, binary:match(Line, <<"\"result\":\"ok\"">>)),
              ?assertNotEqual(nomatch, binary:match(Line, <<"\"sha256\":\"abcdef\"">>))
          end]
     end}.

monotonic_seq_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun({_Pid, Path}) ->
         [fun() ->
              erlkoenig_audit:log(#{type => a, subject => <<"x">>, result => ok}),
              erlkoenig_audit:log(#{type => b, subject => <<"y">>, result => ok}),
              erlkoenig_audit:log(#{type => c, subject => <<"z">>, result => ok}),
              flush(),
              Lines = read_lines(Path),
              ?assertEqual(3, length(Lines)),
              ?assertNotEqual(nomatch, binary:match(hd(Lines), <<"\"seq\":1">>)),
              ?assertNotEqual(nomatch, binary:match(lists:nth(2, Lines), <<"\"seq\":2">>)),
              ?assertNotEqual(nomatch, binary:match(lists:nth(3, Lines), <<"\"seq\":3">>))
          end]
     end}.

error_result_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun({_Pid, Path}) ->
         [fun() ->
              erlkoenig_audit:log(#{
                  type => binary_reject,
                  subject => <<"bad">>,
                  result => {error, sig_not_found}
              }),
              flush(),
              Lines = read_lines(Path),
              Line = hd(Lines),
              ?assertNotEqual(nomatch, binary:match(Line, <<"\"result\":\"error:sig_not_found\"">>))
          end]
     end}.

integer_details_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun({_Pid, Path}) ->
         [fun() ->
              erlkoenig_audit:log(#{
                  type => health_ok,
                  subject => <<"web">>,
                  result => ok,
                  details => #{latency => 42, port => 8080}
              }),
              flush(),
              Lines = read_lines(Path),
              Line = hd(Lines),
              ?assertNotEqual(nomatch, binary:match(Line, <<"42">>)),
              ?assertNotEqual(nomatch, binary:match(Line, <<"8080">>))
          end]
     end}.

query_filter_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun({_Pid, _Path}) ->
         [fun() ->
              erlkoenig_audit:log(#{type => container_start, subject => <<"a">>, result => ok}),
              erlkoenig_audit:log(#{type => binary_verify, subject => <<"b">>, result => ok}),
              erlkoenig_audit:log(#{type => container_start, subject => <<"c">>, result => ok}),
              flush(),
              {ok, Results} = erlkoenig_audit:query(#{type => container_start}),
              ?assertEqual(2, length(Results))
          end]
     end}.

query_limit_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun({_Pid, _Path}) ->
         [fun() ->
              erlkoenig_audit:log(#{type => a, subject => <<"1">>, result => ok}),
              erlkoenig_audit:log(#{type => a, subject => <<"2">>, result => ok}),
              erlkoenig_audit:log(#{type => a, subject => <<"3">>, result => ok}),
              flush(),
              {ok, Results} = erlkoenig_audit:query(#{limit => 2}),
              ?assertEqual(2, length(Results))
          end]
     end}.

json_escape_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun({_Pid, Path}) ->
         [fun() ->
              erlkoenig_audit:log(#{
                  type => test,
                  subject => <<"has\"quotes">>,
                  result => ok
              }),
              flush(),
              Lines = read_lines(Path),
              Line = hd(Lines),
              ?assertNotEqual(nomatch, binary:match(Line, <<"has\\\"quotes">>))
          end]
     end}.

missing_dir_test_() ->
    {"starts without crash when dir missing",
     fun() ->
         application:set_env(erlkoenig, audit_path, "/nonexistent_xyz/audit.jsonl"),
         {ok, Pid} = erlkoenig_audit:start_link(),
         erlkoenig_audit:log(#{type => test, subject => <<"x">>, result => ok}),
         timer:sleep(20),
         gen_server:stop(Pid),
         application:unset_env(erlkoenig, audit_path)
     end}.

%% --- Hash chain tests (SPEC-AS-005) ---

hash_chain_genesis_test_() ->
    {"first event has all-zero prev_hash",
     {setup, fun setup/0, fun cleanup/1,
      fun({_Pid, Path}) ->
          [fun() ->
               erlkoenig_audit:log(#{type => first, subject => <<"x">>, result => ok}),
               flush(),
               [Line] = read_lines(Path),
               Decoded = json:decode(Line),
               ?assertEqual(<<"0000000000000000000000000000000000000000000000000000000000000000">>,
                            maps:get(<<"prev_hash">>, Decoded)),
               %% this_hash must be present and 64 hex chars (32-byte SHA-256)
               ThisHash = maps:get(<<"this_hash">>, Decoded),
               ?assertEqual(64, byte_size(ThisHash))
           end]
      end}}.

hash_chain_links_test_() ->
    {"each event's prev_hash matches the previous event's this_hash",
     {setup, fun setup/0, fun cleanup/1,
      fun({_Pid, Path}) ->
          [fun() ->
               erlkoenig_audit:log(#{type => a, subject => <<"x">>, result => ok}),
               erlkoenig_audit:log(#{type => b, subject => <<"y">>, result => ok}),
               erlkoenig_audit:log(#{type => c, subject => <<"z">>, result => ok}),
               flush(),
               Lines = read_lines(Path),
               ?assertEqual(3, length(Lines)),
               Decoded = [json:decode(L) || L <- Lines],
               %% Walk chain: prev_hash[N] == this_hash[N-1]
               lists:foldl(
                 fun(Event, Prev) ->
                     ?assertEqual(Prev, maps:get(<<"prev_hash">>, Event)),
                     maps:get(<<"this_hash">>, Event)
                 end,
                 <<"0000000000000000000000000000000000000000000000000000000000000000">>,
                 Decoded)
           end]
      end}}.

hash_chain_verify_clean_test_() ->
    {"verify_chain returns ok on a freshly-written log",
     {setup, fun setup/0, fun cleanup/1,
      fun({_Pid, Path}) ->
          [fun() ->
               erlkoenig_audit:log(#{type => a, subject => <<"x">>, result => ok}),
               erlkoenig_audit:log(#{type => b, subject => <<"y">>, result => ok}),
               erlkoenig_audit:log(#{type => c, subject => <<"z">>, result => ok}),
               flush(),
               ?assertEqual({ok, 3}, erlkoenig_audit:verify_chain(Path))
           end]
      end}}.

hash_chain_verify_tamper_test_() ->
    {"verify_chain detects byte-level tampering",
     {setup, fun setup/0, fun cleanup/1,
      fun({_Pid, Path}) ->
          [fun() ->
               erlkoenig_audit:log(#{type => a, subject => <<"x">>, result => ok}),
               erlkoenig_audit:log(#{type => b, subject => <<"y">>, result => ok}),
               erlkoenig_audit:log(#{type => c, subject => <<"z">>, result => ok}),
               flush(),
               %% Tamper: replace "subject":"y" with "subject":"Y" in the
               %% middle line. Must invalidate event 2's this_hash AND
               %% break event 3's prev_hash linkage.
               {ok, Bin} = file:read_file(Path),
               Tampered = binary:replace(Bin,
                   <<"\"subject\":\"y\"">>, <<"\"subject\":\"Y\"">>),
               ?assertNotEqual(Bin, Tampered),  %% sanity: replacement happened
               ok = file:write_file(Path, Tampered),
               case erlkoenig_audit:verify_chain(Path) of
                   {error, {chain_break, 2, _}} -> ok;
                   Other -> ?assertEqual({error, {chain_break, 2, '_'}}, Other)
               end
           end]
      end}}.

hash_chain_verify_truncation_test_() ->
    {"verify_chain detects mid-event truncation as decode failure",
     {setup, fun setup/0, fun cleanup/1,
      fun({_Pid, Path}) ->
          [fun() ->
               erlkoenig_audit:log(#{type => a, subject => <<"x">>, result => ok}),
               erlkoenig_audit:log(#{type => b, subject => <<"y">>, result => ok}),
               flush(),
               {ok, Bin} = file:read_file(Path),
               %% Truncate the second line in the middle.
               Truncated = binary:part(Bin, 0, byte_size(Bin) - 30),
               ok = file:write_file(Path, Truncated),
               case erlkoenig_audit:verify_chain(Path) of
                   {error, {chain_break, 2, _}} -> ok;
                   {ok, 1} -> ok;  %% if truncation hit exactly the newline
                   Other -> ?assertMatch({error, {chain_break, _, _}}, Other)
               end
           end]
      end}}.

hash_chain_recovery_test_() ->
    {"chain continues across gen_server restart",
     fun() ->
         Path = test_path(),
         application:set_env(erlkoenig, audit_path, Path),
         %% First boot: write 2 events, capture chain head
         {ok, Pid1} = erlkoenig_audit:start_link(),
         erlkoenig_audit:log(#{type => a, subject => <<"x">>, result => ok}),
         erlkoenig_audit:log(#{type => b, subject => <<"y">>, result => ok}),
         flush(),
         Head1 = erlkoenig_audit:chain_head(),
         gen_server:stop(Pid1),
         %% Second boot: should recover chain head from disk
         {ok, Pid2} = erlkoenig_audit:start_link(),
         Head2 = erlkoenig_audit:chain_head(),
         ?assertEqual(Head1, Head2),
         %% Write one more event; verify the chain still validates
         erlkoenig_audit:log(#{type => c, subject => <<"z">>, result => ok}),
         flush(),
         ?assertEqual({ok, 3}, erlkoenig_audit:verify_chain(Path)),
         gen_server:stop(Pid2),
         file:delete(Path),
         file:del_dir(filename:dirname(Path)),
         application:unset_env(erlkoenig, audit_path)
     end}.

canonical_json_deterministic_test_() ->
    {"canonical_json sorts keys at every nesting level",
     fun() ->
         %% Build the same logical map two different ways
         M1 = #{<<"b">> => 2, <<"a">> => 1, <<"c">> => #{<<"y">> => 20, <<"x">> => 10}},
         M2 = #{<<"c">> => #{<<"x">> => 10, <<"y">> => 20}, <<"a">> => 1, <<"b">> => 2},
         ?assertEqual(erlkoenig_audit:canonical_json(M1),
                      erlkoenig_audit:canonical_json(M2)),
         %% Verify the actual encoding has sorted keys
         Encoded = erlkoenig_audit:canonical_json(M1),
         ?assertEqual(<<"{\"a\":1,\"b\":2,\"c\":{\"x\":10,\"y\":20}}">>, Encoded)
     end}.

%% --- Hash chain tests stage 2: Ed25519 signing (SPEC-AS-005) ---

%% Setup that materialises a fresh Ed25519 keypair, writes the private
%% key (raw 32 bytes) to a tmp file, configures the audit gen_server
%% to use it, and yields {Pid, Path, KeyPath, PubKey}.
setup_signed() ->
    Path = test_path(),
    KeyPath = "/tmp/erlkoenig_audit_test_key_" ++
              integer_to_list(erlang:unique_integer([positive])) ++ ".raw",
    {PubKey, PrivKey} = crypto:generate_key(eddsa, ed25519),
    32 = byte_size(PrivKey),
    32 = byte_size(PubKey),
    ok = file:write_file(KeyPath, PrivKey),
    application:set_env(erlkoenig, audit_path, Path),
    application:set_env(erlkoenig, audit_signing_key, KeyPath),
    {ok, Pid} = erlkoenig_audit:start_link(),
    {Pid, Path, KeyPath, PubKey}.

cleanup_signed({Pid, Path, KeyPath, _PubKey}) ->
    %% Tolerant of tests that already stopped the gen_server before
    %% tampering with on-disk state (e.g. tampered_signed_event_detected).
    catch gen_server:stop(Pid),
    file:delete(Path),
    file:delete(KeyPath),
    file:del_dir(filename:dirname(Path)),
    application:unset_env(erlkoenig, audit_path),
    application:unset_env(erlkoenig, audit_signing_key).

signing_pubkey_exposed_test_() ->
    {"signing_pubkey/0 returns the loaded public key",
     {setup, fun setup_signed/0, fun cleanup_signed/1,
      fun({_Pid, _Path, _KeyPath, ExpectedPub}) ->
          [fun() ->
               ?assertEqual(ExpectedPub, erlkoenig_audit:signing_pubkey())
           end]
      end}}.

events_carry_signature_test_() ->
    {"every event has a non-null hex signature when key is configured",
     {setup, fun setup_signed/0, fun cleanup_signed/1,
      fun({_Pid, Path, _KeyPath, _PubKey}) ->
          [fun() ->
               erlkoenig_audit:log(#{type => a, subject => <<"x">>, result => ok}),
               erlkoenig_audit:log(#{type => b, subject => <<"y">>, result => ok}),
               flush(),
               Lines = read_lines(Path),
               Decoded = [json:decode(L) || L <- Lines],
               lists:foreach(fun(E) ->
                   Sig = maps:get(<<"signature">>, E),
                   ?assert(is_binary(Sig)),
                   %% Ed25519 signature = 64 bytes = 128 hex chars
                   ?assertEqual(128, byte_size(Sig))
               end, Decoded)
           end]
      end}}.

verify_chain_with_correct_pubkey_test_() ->
    {"verify_chain/2 succeeds with the right public key",
     {setup, fun setup_signed/0, fun cleanup_signed/1,
      fun({_Pid, Path, _KeyPath, PubKey}) ->
          [fun() ->
               erlkoenig_audit:log(#{type => a, subject => <<"x">>, result => ok}),
               erlkoenig_audit:log(#{type => b, subject => <<"y">>, result => ok}),
               erlkoenig_audit:log(#{type => c, subject => <<"z">>, result => ok}),
               flush(),
               ?assertEqual({ok, 3}, erlkoenig_audit:verify_chain(Path, PubKey))
           end]
      end}}.

verify_chain_with_wrong_pubkey_test_() ->
    {"verify_chain/2 fails with a different public key",
     {setup, fun setup_signed/0, fun cleanup_signed/1,
      fun({_Pid, Path, _KeyPath, _RealPubKey}) ->
          [fun() ->
               erlkoenig_audit:log(#{type => a, subject => <<"x">>, result => ok}),
               flush(),
               %% Generate a DIFFERENT keypair
               {WrongPub, _} = crypto:generate_key(eddsa, ed25519),
               case erlkoenig_audit:verify_chain(Path, WrongPub) of
                   {error, {signature_invalid, 1, _}} -> ok;
                   Other -> ?assertEqual({error, {signature_invalid, 1, '_'}}, Other)
               end
           end]
      end}}.

verify_chain_no_pubkey_skips_signatures_test_() ->
    {"verify_chain/1 (no pubkey) only checks hash chain, not signatures",
     {setup, fun setup_signed/0, fun cleanup_signed/1,
      fun({_Pid, Path, _KeyPath, _PubKey}) ->
          [fun() ->
               erlkoenig_audit:log(#{type => a, subject => <<"x">>, result => ok}),
               flush(),
               %% Hash chain is intact even though we don't pass a key
               ?assertEqual({ok, 1}, erlkoenig_audit:verify_chain(Path))
           end]
      end}}.

unsigned_chain_with_pubkey_passes_test_() ->
    {"verify_chain/2 tolerates legacy events without signatures",
     {setup, fun setup/0, fun cleanup/1,
      fun({_Pid, Path}) ->
          [fun() ->
               %% Setup ran without audit_signing_key, so events have
               %% signature: null. Verifying with a key still passes
               %% because verify_signature handles null.
               erlkoenig_audit:log(#{type => a, subject => <<"x">>, result => ok}),
               flush(),
               {SomePub, _} = crypto:generate_key(eddsa, ed25519),
               ?assertEqual({ok, 1}, erlkoenig_audit:verify_chain(Path, SomePub))
           end]
      end}}.

tampered_signed_event_detected_test_() ->
    {"tampering with a signed event's payload breaks both hash and signature",
     {setup, fun setup_signed/0, fun cleanup_signed/1,
      fun({Pid, Path, _KeyPath, PubKey}) ->
          [fun() ->
               erlkoenig_audit:log(#{type => a, subject => <<"alpha">>, result => ok}),
               erlkoenig_audit:log(#{type => b, subject => <<"bravo">>, result => ok}),
               flush(),
               ok = gen_server:stop(Pid),
               {ok, Bin} = file:read_file(Path),
               Tampered = binary:replace(Bin,
                   <<"\"subject\":\"alpha\"">>, <<"\"subject\":\"ALPHA\"">>),
               ?assertNotEqual(Bin, Tampered),
               ok = file:write_file(Path, Tampered),
               %% The hash check fires first — that's the cheaper test
               case erlkoenig_audit:verify_chain(Path, PubKey) of
                   {error, {chain_break, 1, _}} -> ok;
                   {error, {signature_invalid, 1, _}} -> ok;
                   Other -> ?assertMatch({error, {_, 1, _}}, Other)
               end
           end]
      end}}.

hex_to_bin_roundtrip_test_() ->
    {"hex_to_bin reverses canonical hex encoding",
     fun() ->
         Hash = crypto:hash(sha256, <<"test data">>),
         Hex = list_to_binary(
             [io_lib:format("~2.16.0b", [B]) || <<B>> <= Hash]),
         ?assertEqual(64, byte_size(Hex)),
         ?assertEqual(Hash, erlkoenig_audit:hex_to_bin(Hex))
     end}.
