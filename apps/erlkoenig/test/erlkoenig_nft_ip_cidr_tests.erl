%%%-------------------------------------------------------------------
%%% EUnit: erlkoenig_nft_ip:parse_cidr4/1
%%%
%%% Verifies IPv4 CIDR parsing for the nft interval-set loader.
%%% Happy paths + edge cases + reject invalid inputs.
%%%-------------------------------------------------------------------
-module(erlkoenig_nft_ip_cidr_tests).

-include_lib("eunit/include/eunit.hrl").

%% --- /8 --------------------------------------------------------------

parse_slash_8_test() ->
    {ok, {<<10, 0, 0, 0>>, <<10, 255, 255, 255>>}} =
        erlkoenig_nft_ip:parse_cidr4("10.0.0.0/8").

%% --- /24 -------------------------------------------------------------

parse_slash_24_test() ->
    {ok, {<<192, 168, 1, 0>>, <<192, 168, 1, 255>>}} =
        erlkoenig_nft_ip:parse_cidr4("192.168.1.0/24").

%% --- /32 (singleton) -------------------------------------------------

parse_slash_32_test() ->
    {ok, {<<203, 0, 113, 5>>, <<203, 0, 113, 5>>}} =
        erlkoenig_nft_ip:parse_cidr4("203.0.113.5/32").

%% --- bare address (no slash) → /32 semantics -------------------------

parse_bare_address_test() ->
    {ok, {<<203, 0, 113, 5>>, <<203, 0, 113, 5>>}} =
        erlkoenig_nft_ip:parse_cidr4("203.0.113.5").

%% --- /0 → full IPv4 space --------------------------------------------

parse_slash_0_test() ->
    {ok, {<<0, 0, 0, 0>>, <<255, 255, 255, 255>>}} =
        erlkoenig_nft_ip:parse_cidr4("0.0.0.0/0").

%% --- host bits below mask are zeroed (cleaner error surface) --------

parse_host_bits_tolerant_test() ->
    %% 10.1.2.3/8 should normalize to 10.0.0.0/8 — same range.
    {ok, {<<10, 0, 0, 0>>, <<10, 255, 255, 255>>}} =
        erlkoenig_nft_ip:parse_cidr4("10.1.2.3/8").

%% --- binary input accepted identically to list ----------------------

parse_binary_input_test() ->
    {ok, {<<10, 0, 0, 0>>, <<10, 255, 255, 255>>}} =
        erlkoenig_nft_ip:parse_cidr4(<<"10.0.0.0/8">>).

%% --- rejects bad mask -----------------------------------------------

reject_oversize_mask_test() ->
    {error, bad_cidr} =
        erlkoenig_nft_ip:parse_cidr4("10.0.0.0/33").

reject_negative_mask_test() ->
    {error, bad_cidr} =
        erlkoenig_nft_ip:parse_cidr4("10.0.0.0/-1").

reject_non_numeric_mask_test() ->
    {error, bad_cidr} =
        erlkoenig_nft_ip:parse_cidr4("10.0.0.0/abc").

%% --- rejects malformed address --------------------------------------

reject_ipv6_test() ->
    {error, bad_cidr} =
        erlkoenig_nft_ip:parse_cidr4("2001:db8::/32").

reject_garbage_test() ->
    {error, bad_cidr} =
        erlkoenig_nft_ip:parse_cidr4("not an ip").

reject_empty_test() ->
    {error, bad_cidr} =
        erlkoenig_nft_ip:parse_cidr4("").
