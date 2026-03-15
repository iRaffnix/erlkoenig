-module(erlkoenig_audit_tests).

-include_lib("eunit/include/eunit.hrl").

test_path() ->
    "/tmp/erlkoenig_audit_test_" ++
    integer_to_list(erlang:unique_integer([positive])) ++
    "/audit.jsonl".

setup() ->
    Path = test_path(),
    application:set_env(erlkoenig_core, audit_path, Path),
    {ok, Pid} = erlkoenig_audit:start_link(),
    {Pid, Path}.

cleanup({Pid, Path}) ->
    gen_server:stop(Pid),
    file:delete(Path),
    file:del_dir(filename:dirname(Path)),
    application:unset_env(erlkoenig_core, audit_path).

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
         application:set_env(erlkoenig_core, audit_path, "/nonexistent_xyz/audit.jsonl"),
         {ok, Pid} = erlkoenig_audit:start_link(),
         erlkoenig_audit:log(#{type => test, subject => <<"x">>, result => ok}),
         timer:sleep(20),
         gen_server:stop(Pid),
         application:unset_env(erlkoenig_core, audit_path)
     end}.
