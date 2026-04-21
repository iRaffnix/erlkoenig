#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 28: DNS egress allowlist (SPEC-AS-009, L7 DNS half).
%%
%% Verifies end-to-end, through the real UDP path, that:
%%
%%   1. A name NOT in a registered allowlist is answered with an
%%      immediate authoritative NXDOMAIN generated locally by
%%      erlkoenig_dns_filter. "Authoritative" means AA=1 — that's
%%      how we distinguish our filter's NXDOMAIN from any upstream
%%      NXDOMAIN (where AA=0).
%%   2. Wildcard patterns (`*.wild.example`) match sub-labels but
%%      NOT the bare parent domain.
%%   3. An allowed name does NOT get the filter's NXDOMAIN — the
%%      query is passed through to upstream.
%%   4. The deny lands in the audit chain with the right fields.
%%   5. unregister/1 puts the source IP back into pass-through mode.
%%
%% The default-zone DNS's bind IP depends on host topology (loopback
%% vs. an IPVLAN gateway IP like 10.0.0.1). We discover it at runtime
%% via `sys:get_state/1` on the DNS gen_server and drive the client
%% socket from the same IP so SrcIp on the wire matches what we
%% register the allowlist against. Works on both bare default-zone
%% (127.0.0.1) and zones with a gateway IP already assigned.
%%
%% Test runs as root (needs to bind UDP/53 via the runtime).
-mode(compile).

%% Flag masks: see RFC 1035 §4.1.1.
-define(AA_MASK,        16#0400).
-define(RCODE_MASK,     16#000F).
-define(RCODE_NXDOMAIN, 3).

%% erlkoenig_dns state tuple layout — position 2 is the UDP socket.
%% We don't redefine the record here so we won't silently break if
%% the module's record name or field order ever diverges; tuple
%% access with an explicit size assertion gives us a loud failure
%% on mismatch.

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 28: DNS egress allowlist ===~n~n"),

    case string:trim(os:cmd("id -u")) of
        "0" -> ok;
        _   -> io:format("ERROR: must run as root~n"), halt(1)
    end,

    Tag = integer_to_list(os:system_time(microsecond)),
    AuditPath = "/tmp/erlkoenig_audit_test_28_" ++ Tag ++ ".jsonl",

    application:load(erlkoenig),
    application:set_env(erlkoenig, audit_path, AuditPath),
    test_helper:boot(),
    logger:set_primary_config(level, error),

    DnsPid = erlkoenig_zone:dns(default),
    true = is_pid(DnsPid),

    %% Discover where the DNS actually listens — and the effective
    %% SrcIp it will see for a socket bound on the same address.
    {DnsIp, 53} = dns_sockname(DnsPid),
    io:format("    default-zone DNS listens on ~p~n", [DnsIp]),

    SrcIp = DnsIp,

    Sock = test_helper:step(
      "open UDP client bound on the DNS's own IP",
      fun() ->
          {ok, S} = gen_udp:open(0,
              [binary, {ip, SrcIp}, {active, false}, {reuseaddr, true}]),
          {ok, S}
      end),

    test_helper:step(
      "register allowlist for the client's SrcIp: [allowed.example, *.wild.example]",
      fun() ->
          erlkoenig_dns_filter:register_allowlist(SrcIp,
              [<<"allowed.example">>, <<"*.wild.example">>])
      end),

    test_helper:step(
      "denied name (evil.example) gets authoritative NXDOMAIN from filter",
      fun() ->
          assert_filter_nxdomain(Sock, DnsIp, 1, <<"evil.example">>)
      end),

    test_helper:step(
      "wildcard root (wild.example) gets NXDOMAIN (needs a label prefix)",
      fun() ->
          assert_filter_nxdomain(Sock, DnsIp, 2, <<"wild.example">>)
      end),

    test_helper:step(
      "neighbouring domain (evilwild.example) gets NXDOMAIN",
      fun() ->
          assert_filter_nxdomain(Sock, DnsIp, 3, <<"evilwild.example">>)
      end),

    test_helper:step(
      "allowed exact (allowed.example) is NOT filter-NXDOMAIN",
      fun() ->
          assert_passthrough(Sock, DnsIp, 4, <<"allowed.example">>)
      end),

    test_helper:step(
      "allowed wildcard (foo.wild.example) is NOT filter-NXDOMAIN",
      fun() ->
          assert_passthrough(Sock, DnsIp, 5, <<"foo.wild.example">>)
      end),

    test_helper:step(
      "allowed deeper wildcard (a.b.wild.example) is NOT filter-NXDOMAIN",
      fun() ->
          assert_passthrough(Sock, DnsIp, 6, <<"a.b.wild.example">>)
      end),

    test_helper:step(
      "audit chain captured evil.example deny",
      fun() ->
          timer:sleep(300),
          {ok, Bin} = file:read_file(AuditPath),
          case binary:match(Bin, <<"\"query\":\"evil.example\"">>) of
              nomatch ->
                  {error, {no_deny_in_audit, byte_size(Bin)}};
              _ ->
                  case binary:match(Bin, <<"\"type\":\"dns_filter\"">>) of
                      nomatch -> {error, no_dns_filter_type};
                      _       -> ok
                  end
          end
      end),

    test_helper:step(
      "unregister: evil.example is NOT filter-NXDOMAIN anymore",
      fun() ->
          ok = erlkoenig_dns_filter:unregister(SrcIp),
          assert_passthrough(Sock, DnsIp, 7, <<"evil.example">>)
      end),

    _ = gen_udp:close(Sock),
    io:format("~n    audit log kept at: ~s~n", [AuditPath]),
    io:format("~n=== Test 28 passed ===~n~n"),
    halt(0).

%% =================================================================
%% Discovery helpers
%% =================================================================

%% Pull the DNS gen_server's bound {IP, Port} via sys:get_state.
%% Fragile across releases — used here only because the test needs
%% to know where to send without a public API for it.
dns_sockname(Pid) ->
    State = sys:get_state(Pid),
    %% Tuple shape: {state, Socket, Tab, Upstream, Domain, TTL, Pending}
    state = element(1, State),
    7     = tuple_size(State) - 0,    %% sanity: 7 fields incl. tag
    Socket = element(2, State),
    case inet:sockname(Socket) of
        {ok, IpPort} -> IpPort;
        Other        -> error({sockname_failed, Other})
    end.

%% =================================================================
%% Assertions
%% =================================================================

assert_filter_nxdomain(Sock, DnsIp, Id, Name) ->
    Q = build_query(Id, Name, 1),
    ok = gen_udp:send(Sock, DnsIp, 53, Q),
    case gen_udp:recv(Sock, 0, 800) of
        {ok, {_, _, <<_ReplyId:16, Flags:16, _/binary>>}} ->
            Aa    = (Flags band ?AA_MASK)    =/= 0,
            RCode = (Flags band ?RCODE_MASK),
            case {Aa, RCode} of
                {true, ?RCODE_NXDOMAIN} -> ok;
                Other -> {error, {not_filter_nxdomain, Other, Flags}}
            end;
        {error, timeout} ->
            {error, filter_did_not_reply}
    end.

assert_passthrough(Sock, DnsIp, Id, Name) ->
    Q = build_query(Id, Name, 1),
    ok = gen_udp:send(Sock, DnsIp, 53, Q),
    case gen_udp:recv(Sock, 0, 800) of
        {error, timeout} ->
            ok;
        {ok, {_, _, <<_ReplyId:16, Flags:16, _/binary>>}} ->
            Aa    = (Flags band ?AA_MASK)    =/= 0,
            RCode = (Flags band ?RCODE_MASK),
            case {Aa, RCode} of
                {true, ?RCODE_NXDOMAIN} ->
                    {error, {unexpected_filter_nxdomain, Flags}};
                _ -> ok
            end
    end.

%% =================================================================
%% DNS wire helpers
%% =================================================================

build_query(Id, Name, QType) ->
    EncName = encode_dns_name(Name),
    Hdr = <<Id:16, 16#0100:16, 1:16, 0:16, 0:16, 0:16>>,
    <<Hdr/binary, EncName/binary, QType:16, 1:16>>.

encode_dns_name(Name) when is_binary(Name) ->
    Labels = binary:split(Name, <<".">>, [global]),
    encode_labels(Labels).

encode_labels([]) ->
    <<0>>;
encode_labels([<<>> | Rest]) ->
    encode_labels(Rest);
encode_labels([L | Rest]) ->
    Sz = byte_size(L),
    <<Sz, L/binary, (encode_labels(Rest))/binary>>.
