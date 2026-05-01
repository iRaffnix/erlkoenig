-module(nft_query_tests).
-include_lib("eunit/include/eunit.hrl").

parse_dump_done_test() ->
    ?assertEqual({done, []}, nft_query:parse_dump(nlmsg_done(), [])).

parse_dump_truncated_tail_fails_loud_test() ->
    ?assertEqual({error, malformed_netlink_dump},
                 nft_query:parse_dump(<<1, 2, 3>>, [])).

parse_dump_lying_length_fails_loud_test() ->
    Bin = <<64:32/little, 16#0A00:16/little, 0:16/little,
            1:32/little, 0:32/little, 0:32/little>>,
    ?assertEqual({error, malformed_netlink_dump},
                 nft_query:parse_dump(Bin, [])).

parse_dump_malformed_nla_fails_loud_test() ->
    ?assertEqual({error, malformed_netlink_dump},
                 nft_query:parse_dump(nft_msg_with_malformed_nla(), [])).

nlmsg_done() ->
    <<16:32/little, 3:16/little, 0:16/little, 1:32/little, 0:32/little>>.

nft_msg_with_malformed_nla() ->
    NfGenMsg = <<1, 0, 0:16>>,
    BadAttr = <<5:16/little, 1:16/little, 0>>,
    Payload = <<NfGenMsg/binary, BadAttr/binary>>,
    Len = 16 + byte_size(Payload),
    Type = 16#0A00,
    <<Len:32/little, Type:16/little, 0:16/little,
      1:32/little, 0:32/little, Payload/binary>>.
