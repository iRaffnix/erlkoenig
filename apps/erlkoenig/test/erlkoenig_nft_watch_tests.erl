-module(erlkoenig_nft_watch_tests).

-include_lib("eunit/include/eunit.hrl").

watch_requires_shared_netlink_server_test() ->
    ?assertEqual(
        unavailable,
        erlkoenig_nft_watch:resolve_server(missing_nfnl_server_for_watch_test)
    ).
