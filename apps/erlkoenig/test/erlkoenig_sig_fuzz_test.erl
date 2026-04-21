%%%-------------------------------------------------------------------
%%% @doc PKI signature parser fuzz.
%%%
%%% `erlkoenig_sig` parses signature files that the operator ships
%%% alongside container binaries.  A crash here during
%%% `maybe_verify_signature` aborts container spawn with a
%%% confusing error — and if the crash happens server-side on
%%% routine config reload, it's a DoS.
%%%
%%% Hot spots (read first):
%%%   - `parse_sig_file/1` line 284: `<<Payload:PayloadLen/binary,
%%%     Signature/binary>> = Rest` — lying PayloadLen (attacker
%%%     controls first 4 bytes after base64 decode) → badmatch.
%%%   - `parse_git_sha/1`: 40-byte non-hex input crashes via
%%%     `binary_to_integer` badarg.
%%%   - `decode_payload/1`: looks tight, but fuzz anyway.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_sig_fuzz_test).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(nowarn_unused_function).

decode_payload_arbitrary_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_decode_payload_arbitrary_safe(),
                 [{numtests, 1000}, {to_file, user}, noshrink])
    end}.

parse_sig_file_arbitrary_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_parse_sig_file_arbitrary_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

parse_sig_file_lying_len_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_parse_sig_file_lying_len_safe(),
                 [{numtests, 200}, {to_file, user}])
    end}.

parse_git_sha_arbitrary_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_parse_git_sha_arbitrary_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

prop_decode_payload_arbitrary_safe() ->
    ?FORALL(Bin, proper_types:binary(),
        run_safely(fun() -> erlkoenig_sig:decode_payload(Bin) end, Bin)).

prop_parse_sig_file_arbitrary_safe() ->
    ?FORALL(Bin, proper_types:binary(),
        run_safely(fun() -> erlkoenig_sig:parse_sig_file(Bin) end, Bin)).

%% Targeted: build a valid PEM wrapper + base64 of `<<LyingLen:32, "A">>`.
%% PayloadLen = 0xFFFFFFFF, Rest = 1 byte. The pattern-match at line
%% 284 MUST not crash.
prop_parse_sig_file_lying_len_safe() ->
    ?FORALL({LyingLen, TailBytes},
            {proper_types:choose(5, 1000),
             proper_types:choose(0, 20)},
        begin
            Tail = binary:copy(<<"A">>, TailBytes),
            Inner = <<LyingLen:32/big, Tail/binary>>,
            B64 = base64:encode(Inner),
            Pem = iolist_to_binary([
                <<"-----BEGIN ERLKOENIG SIGNATURE-----\n">>,
                B64, <<"\n">>,
                <<"-----END ERLKOENIG SIGNATURE-----\n">>
            ]),
            run_safely(fun() ->
                erlkoenig_sig:parse_sig_file(Pem)
            end, {lying_len, LyingLen, TailBytes})
        end).

prop_parse_git_sha_arbitrary_safe() ->
    ?FORALL(Bin, proper_types:binary(),
        run_safely(fun() -> erlkoenig_sig:parse_git_sha(Bin) end, Bin)).

run_safely(F, Label) ->
    Self = self(),
    Pid = spawn(fun() ->
        R = try F() of
                V -> {ok, V}
            catch
                C:E:_ -> {crash, C, E}
            end,
        Self ! {self(), R}
    end),
    receive
        {Pid, {ok, _}} -> true;
        {Pid, {crash, C, E}} ->
            io:format(user, "CRASH ~p:~p on ~p~n", [C, E, Label]),
            false
    after 2000 ->
        exit(Pid, kill),
        io:format(user, "TIMEOUT on ~p~n", [Label]),
        false
    end.
