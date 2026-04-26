-module(nfnl_server_tests).
-include_lib("eunit/include/eunit.hrl").
-include("erlkoenig_error_test.hrl").

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
    ?assertErrorCode('EK_NFT_BATCH_REJECTED', Result),
    {error, #{data := Data}} = Result,
    ?assertMatch(#{errno := -2, errno_name := enoent, seq := 2}, Data).

process_acks_second_error_ignored_test() ->
    Expected = #{1 => true, 2 => true},
    {Remaining, Result} = nfnl_server:process_acks(
        [{1, {error, {-2, enoent}}}, {2, {error, {-17, eexist}}}], Expected, ok),
    ?assertEqual(#{}, Remaining),
    ?assertErrorCode('EK_NFT_BATCH_REJECTED', Result),
    {error, #{data := Data}} = Result,
    ?assertMatch(#{errno := -2, errno_name := enoent, seq := 1}, Data).

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

%% --- query wrappers ---

wrap_query_error_ok_passthrough_test() ->
    ?assertEqual(
        {ok, #{packets => 1, bytes => 2}},
        nfnl_server:wrap_query_error(
            counter_query_failed,
            {ok, #{packets => 1, bytes => 2}},
            #{})).

wrap_query_error_counter_code_test() ->
    Result = nfnl_server:wrap_query_error(
        counter_query_failed,
        {error, invalid_response},
        #{family => 1, table => <<"fw">>, name => <<"ssh">>, seq => 42}),
    ?assertErrorCode('EK_NFT_COUNTER_QUERY_FAILED', Result),
    {error, #{data := Data}} = Result,
    ?assertMatch(#{reason := invalid_response, seq := 42}, Data).

wrap_query_error_set_elems_code_test() ->
    Result = nfnl_server:wrap_query_error(
        list_set_elems_failed,
        {error, timeout},
        #{family => 1, table => <<"fw">>, set => <<"block">>, seq => 43}),
    ?assertErrorCode('EK_NFT_LIST_SET_ELEMS_FAILED', Result).

wrap_query_error_chains_code_test() ->
    Result = nfnl_server:wrap_query_error(
        list_chains_failed,
        {error, enoent},
        #{family => 1, table => <<"fw">>, seq => 44}),
    ?assertErrorCode('EK_NFT_LIST_CHAINS_FAILED', Result).

wrap_query_error_ruleset_code_test() ->
    Result = nfnl_server:wrap_query_error(
        ruleset_query_failed,
        {error, invalid_response},
        #{family => 1, seq => 45}),
    ?assertErrorCode('EK_NFT_RULESET_QUERY_FAILED', Result).

%% --- Unified Seq: verify exports exist ---

unified_seq_nft_object_exports_test() ->
    %% Ensure module is loaded before checking exports
    _ = code:ensure_loaded(nft_object),
    ?assert(erlang:function_exported(nft_object, get_counter, 5)),
    ?assert(erlang:function_exported(nft_object, get_counter_reset, 5)),
    ?assert(erlang:function_exported(nft_object, get_all_counters, 4)),
    ?assert(erlang:function_exported(nft_object, get_counter, 4)),
    ?assert(erlang:function_exported(nft_object, get_counter_reset, 4)),
    ?assert(erlang:function_exported(nft_object, get_all_counters, 3)).

unified_seq_nft_query_exports_test() ->
    _ = code:ensure_loaded(nft_query),
    ?assert(erlang:function_exported(nft_query, list_tables, 3)),
    ?assert(erlang:function_exported(nft_query, list_chains, 4)),
    ?assert(erlang:function_exported(nft_query, list_rules, 4)),
    ?assert(erlang:function_exported(nft_query, get_ruleset, 3)),
    ?assert(erlang:function_exported(nft_query, list_set_elems, 5)),
    ?assert(erlang:function_exported(nft_query, list_tables, 2)),
    ?assert(erlang:function_exported(nft_query, list_chains, 3)),
    ?assert(erlang:function_exported(nft_query, list_set_elems, 4)).
