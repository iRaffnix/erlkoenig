%%%-------------------------------------------------------------------
%%% @doc EUnit regression guards for nft_set concat encoding.
%%%
%%% Two silent-truncation bugs live in this wire path and both have
%%% fail-loud guards now:
%%%
%%% 1. `concat_key_type/1` serializes 8-bit type codes into a u32
%%%    NFTA_SET_KEY_TYPE, so the kernel supports at most 4 fields.
%%%    A 5th field shifts into bit 32+; Erlang keeps the bignum but
%%%    `<<Val:32/big>>' silently truncates at encode_u32. Guard now
%%%    errors `{concat_too_many_fields, N, max_4}`.
%%%
%%% 2. `udata_entry/2` TLV length is u8 (0..255). Oversized Data
%%%    silently wrapped mod 256, producing a wire blob that nft CLI
%%%    reads as corrupt (wrong typeof display). Guard now
%%%    `byte_size(Data) =< 255` fails with function_clause.
%%%
%%% The concat_key_type guard is stricter and fires first for the
%%% many-fields case, so this test now asserts on that.
%%% @end
%%%-------------------------------------------------------------------

-module(nft_set_udata_guard_tests).

-include_lib("eunit/include/eunit.hrl").

%% Small number of fields — userdata stays under 255, builds cleanly.
small_concat_userdata_encodes_cleanly_test() ->
    Fields = lists:duplicate(3, ipv4_addr),
    Msg = nft_set:add_concat_vmap(
        1,
        #{table => <<"t">>, name => <<"n">>, fields => Fields},
        1,
        1),
    ?assert(is_binary(Msg)),
    ?assert(byte_size(Msg) > 0).

%% Many fields — trips the concat_key_type 4-field kernel limit,
%% which is the first guard on the path (the udata_entry guard
%% would also fire later if this were not caught, but the earlier
%% guard gives a more actionable error).
large_concat_userdata_triggers_guard_test() ->
    Fields = lists:duplicate(30, ipv4_addr),
    ?assertError({concat_too_many_fields, 30, max_4},
        nft_set:add_concat_vmap(
            1,
            #{table => <<"t">>, name => <<"n">>, fields => Fields},
            1,
            1)).

%% Exactly 4 fields — at the kernel limit, should succeed.
four_field_concat_accepted_test() ->
    Fields = lists:duplicate(4, ipv4_addr),
    Msg = nft_set:add_concat_vmap(
        1,
        #{table => <<"t">>, name => <<"n">>, fields => Fields},
        1,
        1),
    ?assert(is_binary(Msg)).

%% Exactly 5 fields — one past the limit, should fail loud.
five_field_concat_rejected_test() ->
    Fields = lists:duplicate(5, ipv4_addr),
    ?assertError({concat_too_many_fields, 5, max_4},
        nft_set:add_concat_vmap(
            1,
            #{table => <<"t">>, name => <<"n">>, fields => Fields},
            1,
            1)).
