%%%-------------------------------------------------------------------
%%% @doc Tests for `erlkoenig_journal_local`.
%%%
%%% Walking-skeleton coverage: socket setup, line framing, JSON
%%% decoding, fan-out to `erlkoenig_audit`, multi-client behaviour,
%%% and tolerant handling of malformed input.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_journal_local_tests).

-include_lib("eunit/include/eunit.hrl").

%% ============================================================
%% Helpers
%% ============================================================

unique_tag() ->
    integer_to_list(os:system_time(microsecond)) ++ "_" ++
    integer_to_list(erlang:unique_integer([positive])).

setup() ->
    Tag = unique_tag(),
    Dir = "/tmp/erlkoenig_journal_test_" ++ Tag,
    SockPath = Dir ++ "/journal.sock",
    AuditPath = Dir ++ "/audit.jsonl",
    ok = filelib:ensure_dir(SockPath),
    application:set_env(erlkoenig, audit_path, AuditPath),
    application:set_env(erlkoenig, journal_local_path, SockPath),
    {ok, AuditPid} = erlkoenig_audit:start_link(),
    {ok, JournalPid} = erlkoenig_journal_local:start_link(),
    {AuditPid, JournalPid, SockPath, AuditPath, Dir}.

cleanup({AuditPid, JournalPid, _Sock, _Audit, Dir}) ->
    catch erlkoenig_journal_local:stop(),
    catch gen_server:stop(JournalPid),
    catch gen_server:stop(AuditPid),
    %% Wipe the whole sandbox dir.
    {ok, Files} = file:list_dir(Dir),
    lists:foreach(fun(F) -> file:delete(filename:join(Dir, F)) end, Files),
    file:del_dir(Dir),
    application:unset_env(erlkoenig, audit_path),
    application:unset_env(erlkoenig, journal_local_path).

connect(SockPath) ->
    {ok, Sock} = gen_tcp:connect({local, SockPath}, 0,
                                 [binary, {packet, line}, {active, false}],
                                 2000),
    Sock.

send_entry(Sock, Entry) when is_map(Entry) ->
    Line = iolist_to_binary([json:encode(Entry), <<"\n">>]),
    ok = gen_tcp:send(Sock, Line).

flush_audit() ->
    %% A synchronous call to the audit gen_server flushes any
    %% pending casts in front of it. The journal-side fan-out is
    %% gen_event-style cast, so we also poll the audit file.
    _ = erlkoenig_audit:query(#{limit => 0}),
    timer:sleep(40).

wait_for_event_count(Path, Expected, TimeoutMs) ->
    wait_for_event_count(Path, Expected, TimeoutMs,
                         erlang:monotonic_time(millisecond)).
wait_for_event_count(Path, Expected, TimeoutMs, Start) ->
    flush_audit(),
    Lines = case file:read_file(Path) of
        {ok, B} -> [L || L <- binary:split(B, <<"\n">>, [global]), L =/= <<>>];
        _       -> []
    end,
    case length(Lines) >= Expected of
        true -> Lines;
        false ->
            case erlang:monotonic_time(millisecond) - Start >= TimeoutMs of
                true  -> Lines;
                false ->
                    timer:sleep(20),
                    wait_for_event_count(Path, Expected, TimeoutMs, Start)
            end
    end.

%% ============================================================
%% Tests
%% ============================================================

socket_file_created_test_() ->
    {"start_link creates the listening socket file at the configured path",
     {setup, fun setup/0, fun cleanup/1,
      fun({_AuditPid, _JournalPid, SockPath, _Audit, _Dir}) ->
          [fun() ->
               ?assert(socket_file_exists(SockPath)),
               ?assertEqual(SockPath, erlkoenig_journal_local:socket_path())
           end]
      end}}.

%% A Unix socket node has type `other` in file_info; filelib:is_file
%% returns false for sockets, so we check via read_file_info directly.
socket_file_exists(Path) ->
    case file:read_file_info(Path) of
        {ok, _} -> true;
        _       -> false
    end.

single_entry_lands_in_audit_test_() ->
    {"a JSON line written to the socket becomes one audit event",
     {setup, fun setup/0, fun cleanup/1,
      fun({_AuditPid, _JournalPid, SockPath, AuditPath, _Dir}) ->
          [fun() ->
               Sock = connect(SockPath),
               send_entry(Sock, #{<<"subject">> => <<"my-app">>,
                                  <<"level">>   => <<"info">>,
                                  <<"msg">>     => <<"hello">>,
                                  <<"fields">>  => #{<<"k">> => <<"v">>}}),
               gen_tcp:close(Sock),
               Lines = wait_for_event_count(AuditPath, 1, 1000),
               ?assertEqual(1, length(Lines)),
               Event = json:decode(hd(Lines)),
               ?assertEqual(<<"journal">>, maps:get(<<"type">>, Event)),
               ?assertEqual(<<"my-app">>, maps:get(<<"subject">>, Event)),
               ?assertEqual(<<"info">>,
                            maps:get(<<"level">>, Event)),
               ?assertEqual(<<"hello">>, maps:get(<<"msg">>, Event)),
               ?assertEqual(#{<<"k">> => <<"v">>},
                            maps:get(<<"fields">>, Event))
           end]
      end}}.

multiple_entries_one_connection_test_() ->
    {"three JSON lines on one connection produce three chained events",
     {setup, fun setup/0, fun cleanup/1,
      fun({_AuditPid, _JournalPid, SockPath, AuditPath, _Dir}) ->
          [fun() ->
               Sock = connect(SockPath),
               send_entry(Sock, #{<<"subject">> => <<"a">>, <<"msg">> => <<"1">>}),
               send_entry(Sock, #{<<"subject">> => <<"a">>, <<"msg">> => <<"2">>}),
               send_entry(Sock, #{<<"subject">> => <<"a">>, <<"msg">> => <<"3">>}),
               gen_tcp:close(Sock),
               Lines = wait_for_event_count(AuditPath, 3, 1500),
               ?assertEqual(3, length(Lines)),
               %% Hash chain across the three events must validate.
               ?assertEqual({ok, 3},
                            erlkoenig_audit:verify_chain(AuditPath))
           end]
      end}}.

concurrent_clients_test_() ->
    {"two simultaneous clients can stream without interfering",
     {setup, fun setup/0, fun cleanup/1,
      fun({_AuditPid, _JournalPid, SockPath, AuditPath, _Dir}) ->
          [fun() ->
               Self = self(),
               Spawn = fun(Subject, Count) ->
                   spawn(fun() ->
                       Sock = connect(SockPath),
                       lists:foreach(fun(I) ->
                           send_entry(Sock,
                               #{<<"subject">> => Subject,
                                 <<"msg">> => integer_to_binary(I)})
                       end, lists:seq(1, Count)),
                       gen_tcp:close(Sock),
                       Self ! {done, Subject}
                   end)
               end,
               Spawn(<<"alice">>, 5),
               Spawn(<<"bob">>,   5),
               receive {done, <<"alice">>} -> ok after 2000 -> error(timeout) end,
               receive {done, <<"bob">>}   -> ok after 2000 -> error(timeout) end,
               Lines = wait_for_event_count(AuditPath, 10, 2000),
               ?assertEqual(10, length(Lines)),
               ?assertEqual({ok, 10},
                            erlkoenig_audit:verify_chain(AuditPath))
           end]
      end}}.

malformed_json_does_not_crash_test_() ->
    {"a bad line is dropped; subsequent good lines still land",
     {setup, fun setup/0, fun cleanup/1,
      fun({_AuditPid, _JournalPid, SockPath, AuditPath, _Dir}) ->
          [fun() ->
               Sock = connect(SockPath),
               %% Garbage line, no JSON.
               ok = gen_tcp:send(Sock, <<"this is not json\n">>),
               %% Then a legit one — must still arrive.
               send_entry(Sock, #{<<"subject">> => <<"after-garbage">>,
                                  <<"msg">>     => <<"ok">>}),
               gen_tcp:close(Sock),
               Lines = wait_for_event_count(AuditPath, 1, 1000),
               ?assertEqual(1, length(Lines)),
               Event = json:decode(hd(Lines)),
               ?assertEqual(<<"after-garbage">>,
                            maps:get(<<"subject">>, Event))
           end]
      end}}.

defaults_filled_when_fields_missing_test_() ->
    {"missing subject/level/msg/fields get safe defaults",
     {setup, fun setup/0, fun cleanup/1,
      fun({_AuditPid, _JournalPid, SockPath, AuditPath, _Dir}) ->
          [fun() ->
               Sock = connect(SockPath),
               %% Empty object — every optional field absent.
               send_entry(Sock, #{}),
               gen_tcp:close(Sock),
               Lines = wait_for_event_count(AuditPath, 1, 1000),
               Event = json:decode(hd(Lines)),
               ?assertEqual(<<"unknown">>, maps:get(<<"subject">>, Event)),
               ?assertEqual(<<"info">>,
                            maps:get(<<"level">>, Event)),
               ?assertEqual(<<>>, maps:get(<<"msg">>, Event)),
               ?assertEqual(#{}, maps:get(<<"fields">>, Event))
           end]
      end}}.

stop_removes_socket_file_test_() ->
    {"clean shutdown removes the socket file from disk",
     fun() ->
         Tag = unique_tag(),
         Dir = "/tmp/erlkoenig_journal_test_" ++ Tag,
         SockPath = Dir ++ "/journal.sock",
         AuditPath = Dir ++ "/audit.jsonl",
         ok = filelib:ensure_dir(SockPath),
         application:set_env(erlkoenig, audit_path, AuditPath),
         application:set_env(erlkoenig, journal_local_path, SockPath),
         {ok, AuditPid} = erlkoenig_audit:start_link(),
         {ok, _} = erlkoenig_journal_local:start_link(),
         ?assert(socket_file_exists(SockPath)),
         erlkoenig_journal_local:stop(),
         %% give terminate a tick
         timer:sleep(20),
         ?assertNot(socket_file_exists(SockPath)),
         gen_server:stop(AuditPid),
         file:delete(AuditPath),
         file:del_dir(Dir),
         application:unset_env(erlkoenig, audit_path),
         application:unset_env(erlkoenig, journal_local_path)
     end}.
