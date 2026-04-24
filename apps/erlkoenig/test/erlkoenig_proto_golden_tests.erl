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

Reads `.bin` frames (the exact bytes an `erlkoenig_rt::send_reply_*`
path would write) and the matching `.expected.term` files from the
in-tree vector directory at
`apps/erlkoenig/test/protocol_vectors/v1/`.

The path is derived from the compiled test module's own location
(`code:which/1`) so the tests work identically under `rebar3 eunit`,
under an unpacked release, or when the repo is relocated.
`ERLKOENIG_PROTOCOL_VECTORS` is respected as an override for ad-hoc
testing against an alternative vector tree.

Spec reference: SPEC-PROTO-001 (vectors) + ADR-0021 (wire contract).
The in-tree vectors were vendored from erlkoenigin/specs/protocol/
vectors/v1/ — the spec repo remains the design-time source, the
code repo carries the runtime-consumed copies.
""".

-include_lib("eunit/include/eunit.hrl").

%% =================================================================
%% Reply vectors — decode .bin, assert matches .expected.term
%% =================================================================

replies_golden_test_() ->
    Dir = vectors_dir(),
    [
        {"reply_status_alive",
         ?_test(golden_reply(Dir, "replies/reply_status_alive"))},
        {"reply_status_stopped",
         ?_test(golden_reply(Dir, "replies/reply_status_stopped"))}
    ].

%% Resolution order:
%%   1. ERLKOENIG_PROTOCOL_VECTORS env — explicit override
%%   2. Next to the test module's .beam file — rebar3 copies the
%%      `test/` tree into _build/test/lib/erlkoenig/test/, so
%%      `<beam-dir>/protocol_vectors/v1` is the in-tree path.
vectors_dir() ->
    case os:getenv("ERLKOENIG_PROTOCOL_VECTORS") of
        false ->
            BeamPath = code:which(?MODULE),
            filename:join(filename:dirname(BeamPath),
                          "protocol_vectors/v1");
        Override ->
            Override
    end.

golden_reply(Dir, Stem) ->
    BinPath      = filename:join(Dir, Stem ++ ".bin"),
    ExpectedPath = filename:join(Dir, Stem ++ ".expected.term"),
    {ok, Bytes}    = file:read_file(BinPath),
    {ok, [Expected]} = file:consult(ExpectedPath),
    %% The decoded shape must EXACTLY match the committed term.
    %% Any drift — new field, different default, wrong type — trips here.
    ?assertEqual(Expected, erlkoenig_proto:decode(Bytes)).
