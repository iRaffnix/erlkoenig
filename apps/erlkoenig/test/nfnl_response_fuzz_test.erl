%%%-------------------------------------------------------------------
%%% @doc Netlink response parser fuzz.
%%%
%%% `nfnl_response:parse/1` and `parse_with_seq/1` walk a binary
%%% containing one or more netlink response messages.  They read
%%% a `Len:32` length field, then slice that many bytes off.
%%% A lying Len field (Len > remaining) crashes with badmatch.
%%% Since kernel responses are attacker-adjacent (conntrack events,
%%% nflog, whatever else a userspace peer can inject), this is a
%%% DoS target.
%%% @end
%%%-------------------------------------------------------------------

-module(nfnl_response_fuzz_test).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(nowarn_unused_function).

parse_arbitrary_safe_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_parse_arbitrary_safe(),
                 [{numtests, 1000}, {to_file, user}, noshrink])
    end}.

parse_lying_length_safe_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_parse_lying_length_safe(),
                 [{numtests, 500}, {to_file, user}])
    end}.

parse_with_seq_arbitrary_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_parse_with_seq_arbitrary_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

parse_multi_message_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_parse_multi_ack(),
                 [{numtests, 200}, {to_file, user}])
    end}.

%% -------------------------------------------------------------------

prop_parse_arbitrary_safe() ->
    ?FORALL(Bin, proper_types:binary(),
        run_safely(fun() -> nfnl_response:parse(Bin) end, Bin)).

prop_parse_with_seq_arbitrary_safe() ->
    ?FORALL(Bin, proper_types:binary(),
        run_safely(fun() -> nfnl_response:parse_with_seq(Bin) end, Bin)).

%% A 4-byte Len field at the start of a binary that's shorter than
%% Len.  Classic "Len Field Attack".  Must return a list, not
%% crash.
prop_parse_lying_length_safe() ->
    ?FORALL({LyingLen, TailBytes},
            {proper_types:choose(20, 1000),
             proper_types:choose(0, 50)},
        begin
            %% Build a well-looking header but too-short total
            Tail = binary:copy(<<"A">>, TailBytes),
            Bin = <<LyingLen:32/little,
                    2:16/little,     %% NLMSG_ERROR
                    0:16/little,     %% flags
                    1:32/little,     %% seq
                    1234:32/little,  %% pid
                    (-22):32/signed-little,  %% errno EINVAL
                    Tail/binary>>,
            run_safely(fun() -> nfnl_response:parse(Bin) end, Bin)
        end).

%% Multi-message: two concatenated NLMSG_ERROR ACKs.  The parser
%% should return two results.
prop_parse_multi_ack() ->
    ?FORALL({Seq1, Seq2, E1, E2},
            {seq_gen(), seq_gen(), errno_gen(), errno_gen()},
        begin
            M1 = make_error_msg(Seq1, E1),
            M2 = make_error_msg(Seq2, E2),
            Bin = <<M1/binary, M2/binary>>,
            case nfnl_response:parse_with_seq(Bin) of
                [{Seq1, R1}, {Seq2, R2}] ->
                    check_result(R1, E1) andalso check_result(R2, E2);
                Other ->
                    io:format(user, "multi-ACK parse wrong: ~p~n", [Other]),
                    false
            end
        end).

%% -------------------------------------------------------------------

run_safely(F, Bin) ->
    Self = self(),
    Pid = spawn(fun() ->
        R = try F() of
                V when is_list(V) -> ok_list;
                Other -> {unexpected, Other}
            catch
                C:E:_ -> {crash, C, E}
            end,
        Self ! {self(), R}
    end),
    receive
        {Pid, ok_list} -> true;
        {Pid, {unexpected, V}} ->
            io:format(user, "unexpected return: ~p on ~p~n", [V, Bin]),
            false;
        {Pid, {crash, C, E}} ->
            io:format(user, "CRASH ~p:~p on ~p~n", [C, E, Bin]),
            false
    after 2000 ->
        exit(Pid, kill),
        io:format(user, "parse hung on ~p~n", [Bin]),
        false
    end.

make_error_msg(Seq, Errno) ->
    Len = 20,
    <<Len:32/little, 2:16/little, 0:16/little,
      Seq:32/little, 0:32/little,
      Errno:32/signed-little>>.

check_result(ok, 0) -> true;
check_result({error, {N, _Name}}, N) -> true;
check_result(_, _) -> false.

seq_gen() -> proper_types:choose(1, 16#ffffffff).
errno_gen() -> proper_types:oneof([0, -1, -2, -13, -16, -17, -22, -28, -99]).
