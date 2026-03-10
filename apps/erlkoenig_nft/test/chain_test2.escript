#!/usr/bin/env escript
%%! -pa _build/default/lib/erlkoenig_nft/ebin

-define(NFPROTO_INET, 1).
-define(AF_NETLINK, 16).

main(_) ->
    os:cmd("nft delete table inet testfw 2>/dev/null"),

    Seq = erlang:system_time(second),

    Msgs = [
        nft_table:add(?NFPROTO_INET, <<"testfw">>, Seq + 1),
        nft_chain:add(?NFPROTO_INET, #{
            table => <<"testfw">>,
            name => <<"input">>,
            hook => input,
            type => filter,
            priority => 0,
            policy => accept
        }, Seq + 2)
    ],

    Batch = nft_batch:wrap(Msgs, Seq),
    io:format("Sending ~w bytes~n", [byte_size(Batch)]),

    {ok, Sock} = socket:open(?AF_NETLINK, raw, 12),
    Bind = #{family => ?AF_NETLINK, addr => <<16:16/native, 0:16, 0:32/native, 0:32/native>>},
    ok = socket:bind(Sock, Bind),

    Dest = #{family => ?AF_NETLINK, addr => <<16:16/native, 0:16, 0:32/native, 0:32/native>>},
    Ret = socket:sendto(Sock, Batch, Dest),
    io:format("sendto: ~p~n", [Ret]),

    %% Try multiple recvs
    recv_loop(Sock, 3),

    socket:close(Sock),
    io:format("~n--- nft list ruleset ---~n"),
    io:format("~s", [os:cmd("nft list ruleset")]).

recv_loop(_Sock, 0) -> ok;
recv_loop(Sock, N) ->
    case socket:recv(Sock, 0, 3000) of
        {ok, Data} ->
            io:format("recv[~w]: ~w bytes: ", [N, byte_size(Data)]),
            parse_all(Data),
            recv_loop(Sock, N - 1);
        {error, timeout} ->
            io:format("recv[~w]: timeout~n", [N]);
        {error, R} ->
            io:format("recv[~w]: error ~p~n", [N, R])
    end.

parse_all(<<>>) -> ok;
parse_all(<<Len:32/little, 2:16/little, _:16/little,
            Seq:32/little, _:32/little, Error:32/signed-little, _Rest/binary>> = Data) when Len >= 20 ->
    Skip = Len - 16,
    <<_:16/binary, _:Skip/binary, Tail/binary>> = Data,
    case Error of
        0 -> io:format("seq ~w OK  ", [Seq]);
        N -> io:format("seq ~w ERR ~w  ", [Seq, N])
    end,
    parse_all(Tail);
parse_all(<<Len:32/little, Type:16/little, _/binary>> = Data) when Len >= 16 ->
    <<_:Len/binary, Tail/binary>> = Data,
    io:format("type=~w len=~w  ", [Type, Len]),
    parse_all(Tail);
parse_all(_) -> io:format("~n").
