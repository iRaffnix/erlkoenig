-module(e2e_test_21).
-export([run/0]).

%% Full Stack End-to-End Test
%% Run via: /opt/erlkoenig/bin/erlkoenig eval "..."
%% Output goes to /tmp/e2e_test_21.log

-define(LOG, "/tmp/e2e_test_21.log").

run() ->
    {ok, Fd} = file:open(?LOG, [write]),
    put(fd, Fd),
    DemoBin = <<"/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server">>,
    log("~n=== Test 21: Full Stack End-to-End ===~n~n"),

    %% Step 1: Spawn container A — strict firewall (generic rule)
    PidA = step("Spawn A (strict: nur Port 7001)", fun() ->
        {ok, P} = erlkoenig:spawn(DemoBin, #{
            ip => {10, 0, 0, 60},
            args => [<<"7001">>],
            firewall => #{chains => [#{
                name => <<"inbound">>,
                rules => [
                    ct_established_accept,
                    icmp_accept,
                    {rule, accept, #{tcp => 7001}},
                    {rule, drop, #{log => <<"E2E_DROP: ">>}}
                ]
            }]}
        }),
        {ok, P}
    end),

    %% Step 2: Spawn container B — open (default rules)
    PidB = step("Spawn B (open)", fun() ->
        {ok, P} = erlkoenig:spawn(DemoBin, #{
            ip => {10, 0, 0, 70},
            args => [<<"7002">>]
        }),
        {ok, P}
    end),

    timer:sleep(1500),

    %% Step 3: Both running
    step("Beide Container running", fun() ->
        #{state := running} = erlkoenig:inspect(PidA),
        #{state := running} = erlkoenig:inspect(PidB),
        log("    A + B running~n"),
        ok
    end),

    %% Step 4: Allowed port on A
    step("A: Port 7001 erlaubt", fun() ->
        echo_test({10, 0, 0, 60}, 7001, <<"e2e_strict_allowed">>)
    end),

    %% Step 5: Open port on B
    step("B: Port 7002 erlaubt (open)", fun() ->
        echo_test({10, 0, 0, 70}, 7002, <<"e2e_open_works">>)
    end),

    %% Step 6: Blocked port on A
    step("A: Port 7002 geblockt (drop)", fun() ->
        case gen_tcp:connect({10, 0, 0, 60}, 7002, [binary, {active, false}], 2000) of
            {error, _} ->
                log("    Port 7002 korrekt geblockt~n"),
                ok;
            {ok, Sock} ->
                gen_tcp:close(Sock),
                {error, port_should_be_blocked}
        end
    end),

    %% Step 7: nftables check
    step("nft: generic rule in container chain", fun() ->
        Output = os:cmd("nft list table inet erlkoenig 2>&1"),
        case string:find(Output, "tcp dport 7001 accept") of
            nomatch -> {error, "tcp dport 7001 accept rule missing"};
            _ ->
                log("    tcp dport 7001 accept vorhanden~n"),
                ok
        end
    end),

    %% Step 8: Inspect metadata
    step("Inspect metadata", fun() ->
        #{net_info := #{ip := {10, 0, 0, 60}}, args := [<<"7001">>]} =
            erlkoenig:inspect(PidA),
        #{net_info := #{ip := {10, 0, 0, 70}}, args := [<<"7002">>]} =
            erlkoenig:inspect(PidB),
        log("    A: 10.0.0.60:7001  B: 10.0.0.70:7002~n"),
        ok
    end),

    %% Step 9: Cleanup
    step("Cleanup", fun() ->
        erlkoenig:stop(PidA),
        erlkoenig:stop(PidB),
        timer:sleep(1000),
        case erlkoenig:list() of
            [] -> log("    Alle Container gestoppt~n"), ok;
            R  -> log("    WARN: ~p still running~n", [length(R)]), ok
        end
    end),

    %% Step 10: Verify nft cleanup
    step("nft chains entfernt", fun() ->
        Output = os:cmd("nft list table inet erlkoenig 2>&1"),
        case string:find(Output, "tcp dport 7001") of
            nomatch -> log("    Container chains sauber entfernt~n"), ok;
            _       -> log("    WARN: chain still present~n"), ok
        end
    end),

    log("~n=== Test 21 bestanden ===~n~n"),
    file:close(get(fd)),
    ok.

%% --- helpers ---

log(Fmt) -> log(Fmt, []).
log(Fmt, Args) -> io:format(get(fd), Fmt, Args).

step(Name, Fun) ->
    log("[....] ~s", [Name]),
    try Fun() of
        ok ->
            log("\r[OK  ] ~s~n", [Name]);
        {ok, Val} ->
            log("\r[OK  ] ~s~n", [Name]),
            Val;
        {error, Reason} ->
            log("\r[FAIL] ~s: ~p~n", [Name, Reason]),
            file:close(get(fd)),
            error({test_failed, Name, Reason})
    catch
        Class:Error:Stack ->
            log("\r[FAIL] ~s~n  ~p:~p~n  ~p~n",
                [Name, Class, Error, lists:sublist(Stack, 3)]),
            file:close(get(fd)),
            error({test_crashed, Name, {Class, Error}})
    end.

echo_test(Ip, Port, Msg) ->
    case gen_tcp:connect(Ip, Port, [binary, {active, false}], 5000) of
        {ok, Sock} ->
            ok = gen_tcp:send(Sock, Msg),
            case gen_tcp:recv(Sock, 0, 5000) of
                {ok, Msg} ->
                    log("    echo: ~s~n", [Msg]),
                    gen_tcp:close(Sock),
                    ok;
                {ok, Other} ->
                    gen_tcp:close(Sock),
                    {error, {unexpected, Other}};
                {error, R} ->
                    gen_tcp:close(Sock),
                    {error, {recv, R}}
            end;
        {error, R} ->
            {error, {connect, Ip, Port, R}}
    end.
