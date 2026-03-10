-module(nfnl_response_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

all() ->
    [parse_single_ack,
     parse_single_error,
     parse_multiple_acks,
     parse_mixed,
     parse_empty,
     parse_einval,
     parse_eperm].

parse_single_ack(_) ->
    Msg = nlmsg_error(0, 42),
    ?assertEqual([ok], nfnl_response:parse(Msg)).

parse_single_error(_) ->
    Msg = nlmsg_error(-17, 42),
    ?assertEqual([{error, {-17, eexist}}], nfnl_response:parse(Msg)).

parse_multiple_acks(_) ->
    Bin = iolist_to_binary([nlmsg_error(0, 1), nlmsg_error(0, 2), nlmsg_error(0, 3)]),
    ?assertEqual([ok, ok, ok], nfnl_response:parse(Bin)).

parse_mixed(_) ->
    Bin = iolist_to_binary([nlmsg_error(0, 1), nlmsg_error(-22, 2), nlmsg_error(0, 3)]),
    ?assertEqual([ok, {error, {-22, einval}}, ok], nfnl_response:parse(Bin)).

parse_empty(_) ->
    ?assertEqual([], nfnl_response:parse(<<>>)).

parse_einval(_) ->
    Msg = nlmsg_error(-22, 99),
    ?assertEqual([{error, {-22, einval}}], nfnl_response:parse(Msg)).

parse_eperm(_) ->
    Msg = nlmsg_error(-1, 99),
    ?assertEqual([{error, {-1, eperm}}], nfnl_response:parse(Msg)).

%% --- Helpers ---

%% Build a minimal NLMSG_ERROR response
nlmsg_error(Error, Seq) ->
    %% 16 byte nlmsghdr + 4 byte error + 16 byte original header = 36
    OrigHdr = <<0:128>>,
    Len = 36,
    <<Len:32/little, 2:16/little, 0:16/little,
      Seq:32/little, 0:32/little,
      Error:32/signed-little, OrigHdr/binary>>.
