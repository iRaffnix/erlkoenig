#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 37: `ek quarantine add/remove` round-trip via CLI.
%%
%% Regression test for the hex double-encoding bug (2026-04-17):
%%   dispatch(["quarantine", "remove", Hash], ...) -> q_remove(O, list_to_binary(Hash))
%% passed the ASCII bytes of the hex string as the hash, instead of
%% the decoded 32-byte SHA-256. Lookups never matched, remove was
%% a silent no-op.
%%
%% Fix: decode_hash/1 helper validates + decodes before calling the
%% quarantine gen_server.
%%
%% This test exercises the actual `ek` CLI via os:cmd to catch any
%% regression in the escript dispatch/decode path.
-mode(compile).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 37: ek quarantine CLI round-trip ===~n~n"),

    %% Runs in-process — requires running erlkoenig daemon OR
    %% test_helper:boot which starts the app.
    test_helper:boot(),
    logger:set_primary_config(level, warning),

    %% We use a synthetic 32-byte hash (never a real binary hash)
    %% so the test is independent of what's on disk.
    HashHex = <<"deadbeef0001020304050607080900"
                "01020304050607080900010203040506">>,
    HashBin = binary:decode_hex(HashHex),
    32 = byte_size(HashBin),

    EkBin = find_ek(),

    %% Clean slate
    _ = erlkoenig_quarantine:unquarantine(HashBin),

    test_helper:step("ek quarantine add <hex>", fun() ->
        Cmd = EkBin ++ " quarantine add " ++ binary_to_list(HashHex),
        Out = os:cmd(Cmd),
        case string:find(Out, "quarantined") of
            nomatch -> error({add_failed, Out});
            _ -> ok
        end
    end),

    test_helper:step("gen_server sees the hash bytes (not hex)", fun() ->
        List = erlkoenig_quarantine:list(),
        case [H || {H, _} <- List, H =:= HashBin] of
            [_] -> ok;
            [] -> error({not_stored_as_bytes,
                         {expected_hash, HashBin},
                         {in_list, [H || {H, _} <- List]}})
        end
    end),

    test_helper:step("ek quarantine list displays 64 hex chars", fun() ->
        Out = os:cmd(EkBin ++ " quarantine list"),
        ExpectedUp = string:uppercase(binary_to_list(HashHex)),
        case string:find(Out, ExpectedUp) of
            nomatch -> error({hex_not_in_list_output, Out});
            _ -> ok
        end
    end),

    test_helper:step("ek quarantine remove <hex>", fun() ->
        Cmd = EkBin ++ " quarantine remove " ++ binary_to_list(HashHex),
        Out = os:cmd(Cmd),
        case string:find(Out, "unquarantined") of
            nomatch -> error({remove_failed, Out});
            _ -> ok
        end
    end),

    test_helper:step("gen_server no longer has the hash", fun() ->
        List = erlkoenig_quarantine:list(),
        case [H || {H, _} <- List, H =:= HashBin] of
            [] -> ok;
            _ -> error({still_present, HashBin})
        end
    end),

    test_helper:step("remove non-hex input is rejected", fun() ->
        Out = os:cmd(EkBin ++ " quarantine remove notahexstring 2>&1"),
        case string:find(Out, "hex") of
            nomatch -> error({no_validation, Out});
            _ -> ok
        end
    end),

    io:format("~n=== Test 37 passed ===~n"),
    halt(0).

find_ek() ->
    Candidates = [
        "/opt/erlkoenig/release/bin/ek",
        "/opt/erlkoenig/bin/ek",
        "./dist/ek"
    ],
    case [P || P <- Candidates, filelib:is_regular(P)] of
        [P | _] -> P;
        [] -> error(ek_binary_not_found)
    end.
