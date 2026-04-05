#!/usr/bin/env escript
%%! -pa _build/default/lib/erlkoenig/ebin

-define(NFPROTO_INET, 1).

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
        }, Seq + 2),
        nft_chain:add(?NFPROTO_INET, #{
            table => <<"testfw">>,
            name => <<"forward">>,
            hook => forward,
            type => filter,
            priority => 0,
            policy => drop
        }, Seq + 3)
    ],

    Batch = nft_batch:wrap(Msgs, Seq),
    io:format("Sending ~w bytes~n", [byte_size(Batch)]),
    io:format("Hex: ~s~n~n", [bin_to_hex(Batch)]),

    {ok, Sock} = nfnl_socket:open(),
    case nfnl_socket:send(Sock, Batch) of
        ok -> io:format("send: ok~n");
        {ok, _} -> io:format("send: ok~n");
        Other -> io:format("send: ~p~n", [Other])
    end,

    %% Read all responses
    recv_loop(Sock),

    nfnl_socket:close(Sock),

    io:format("~n--- nft list ruleset ---~n"),
    io:format("~s", [os:cmd("nft list ruleset")]).

recv_loop(Sock) ->
    case nfnl_socket:recv(Sock) of
        {ok, Data} ->
            io:format("recv ~w bytes~n", [byte_size(Data)]),
            parse_all(Data),
            recv_loop(Sock);
        {error, timeout} ->
            io:format("recv: timeout (done)~n");
        {error, R} ->
            io:format("recv error: ~p~n", [R])
    end.

parse_all(<<>>) -> ok;
parse_all(<<Len:32/little, Type:16/little, _Flags:16/little,
            Seq:32/little, _Pid:32/little, Rest/binary>>) when Len >= 16 ->
    PayloadLen = Len - 16,
    <<Payload:PayloadLen/binary, Tail/binary>> = Rest,
    case Type of
        2 ->
            <<Error:32/signed-little, _/binary>> = Payload,
            case Error of
                0 -> io:format("  seq ~w: OK~n", [Seq]);
                N -> io:format("  seq ~w: ERROR ~w~n", [Seq, N])
            end;
        3 ->
            io:format("  NLMSG_DONE~n");
        _ ->
            io:format("  seq ~w: type=~w len=~w~n", [Seq, Type, Len])
    end,
    parse_all(Tail);
parse_all(Other) ->
    io:format("  unparsed: ~w~n", [Other]).

bin_to_hex(Bin) ->
    lists:flatten([io_lib:format("~2.16.0B", [B]) || <<B>> <= Bin]).
