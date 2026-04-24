%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%

-module(erlkoenig_proto_golden_tests).
-moduledoc """
Golden-vector regression harness for the BEAM <-> C runtime wire
protocol.

Pulls `.bin` frames (the exact bytes an `erlkoenig_rt::send_reply_*`
path would write) and the matching `.expected.term` files from an
external vector tree — the architecture repo at
`erlkoenigin/specs/protocol/vectors/v1/`.

The tree path is injected via the `ERLKOENIG_PROTOCOL_VECTORS` env
variable (per SPEC-PROTO-001 + ADR-0021). When unset the test
generator returns an empty list and logs a skip notice. CI jobs that
touch the wire protocol MUST set the variable.

Spike scope (SPEC-PROTO-001 Phase B): only the two drifts that
motivated the spec — REPLY_STATUS TLV decode and the adjacent
handshake-reconnect invariant. Broader coverage arrives with
SPEC-RT-006 once libekproto's emit tooling lands.
""".

-include_lib("eunit/include/eunit.hrl").

%% =================================================================
%% Reply vectors — decode .bin, assert matches .expected.term
%% =================================================================

replies_golden_test_() ->
    case os:getenv("ERLKOENIG_PROTOCOL_VECTORS") of
        false ->
            io:format(user,
                      "[skip] ERLKOENIG_PROTOCOL_VECTORS not set — "
                      "golden reply tests skipped. Point it at "
                      "erlkoenigin/specs/protocol/vectors to enable.~n",
                      []),
            [];
        Dir ->
            [
                {"reply_status_alive",
                 ?_test(golden_reply(Dir, "replies/reply_status_alive"))},
                {"reply_status_stopped",
                 ?_test(golden_reply(Dir, "replies/reply_status_stopped"))}
            ]
    end.

golden_reply(Dir, Stem) ->
    BinPath      = filename:join(Dir, Stem ++ ".bin"),
    ExpectedPath = filename:join(Dir, Stem ++ ".expected.term"),
    {ok, Bytes}    = file:read_file(BinPath),
    {ok, [Expected]} = file:consult(ExpectedPath),
    %% The decoded shape must EXACTLY match the committed term.
    %% Any drift — new field, different default, wrong type — trips here.
    ?assertEqual(Expected, erlkoenig_proto:decode(Bytes)).
