-module(nfnl_server_tests).
-include_lib("eunit/include/eunit.hrl").

%% --- next_seq ---

next_seq_basic_test() ->
    ?assertEqual(1, nfnl_server:next_seq(0)),
    ?assertEqual(101, nfnl_server:next_seq(100)).

next_seq_wraparound_test() ->
    ?assertEqual(0, nfnl_server:next_seq(16#FFFFFFFF)),
    ?assertEqual(16#FFFFFFFF, nfnl_server:next_seq(16#FFFFFFFE)).

%% --- process_acks ---

process_acks_all_ok_test() ->
    Expected = #{1 => true, 2 => true},
    {Remaining, Result} = nfnl_server:process_acks(
        [{1, ok}, {2, ok}], Expected, ok),
    ?assertEqual(#{}, Remaining),
    ?assertEqual(ok, Result).

process_acks_first_error_kept_test() ->
    Expected = #{1 => true, 2 => true, 3 => true},
    {Remaining, Result} = nfnl_server:process_acks(
        [{1, ok}, {2, {error, {-2, enoent}}}, {3, ok}], Expected, ok),
    ?assertEqual(#{}, Remaining),
    ?assertEqual({error, {-2, enoent}}, Result).

process_acks_second_error_ignored_test() ->
    Expected = #{1 => true, 2 => true},
    {Remaining, Result} = nfnl_server:process_acks(
        [{1, {error, {-2, enoent}}}, {2, {error, {-17, eexist}}}], Expected, ok),
    ?assertEqual(#{}, Remaining),
    ?assertEqual({error, {-2, enoent}}, Result).

process_acks_stale_seq_discarded_test() ->
    Expected = #{1 => true, 2 => true},
    {Remaining, Result} = nfnl_server:process_acks(
        [{1, ok}, {99, ok}, {2, ok}], Expected, ok),
    ?assertEqual(#{}, Remaining),
    ?assertEqual(ok, Result).

process_acks_partial_test() ->
    Expected = #{1 => true, 2 => true, 3 => true},
    {Remaining, Result} = nfnl_server:process_acks(
        [{1, ok}, {3, ok}], Expected, ok),
    ?assertEqual(#{2 => true}, Remaining),
    ?assertEqual(ok, Result).

process_acks_empty_input_test() ->
    Expected = #{1 => true},
    {Remaining, Result} = nfnl_server:process_acks([], Expected, ok),
    ?assertEqual(#{1 => true}, Remaining),
    ?assertEqual(ok, Result).

process_acks_preserves_existing_error_test() ->
    Expected = #{1 => true},
    {Remaining, Result} = nfnl_server:process_acks(
        [{1, ok}], Expected, {error, previous}),
    ?assertEqual(#{}, Remaining),
    ?assertEqual({error, previous}, Result).
