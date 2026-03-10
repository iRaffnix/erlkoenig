#!/usr/bin/env escript
%%! -pa _build/default/lib/erlkoenig_nft/ebin

-define(NFPROTO_INET, 1).

main(_) ->
    Seq = erlang:system_time(second),
    Batch = nft_table:add(?NFPROTO_INET, <<"smoke">>, Seq),

    io:format("Sending ~w bytes~n", [byte_size(Batch)]),

    {ok, Sock} = nfnl_socket:open(),
    ok = nfnl_socket:send(Sock, Batch),

    case nfnl_socket:recv(Sock) of
        {ok, Resp} ->
            parse_response(Resp);
        {error, Reason} ->
            io:format("Recv error: ~p~n", [Reason])
    end,
    nfnl_socket:close(Sock).

parse_response(<<Len:32/little, Type:16/little, _Flags:16/little,
                 _Seq:32/little, _Pid:32/little, Rest/binary>>) ->
    case Type of
        2 -> %% NLMSG_ERROR
            <<Error:32/signed-little, _/binary>> = Rest,
            case Error of
                0 -> io:format("SUCCESS! Table created.~nRun: sudo nft list tables~n");
                N -> io:format("Kernel error: ~w (~s)~n", [N, errno(N)])
            end;
        _ ->
            io:format("Unknown response type: ~w (~w bytes)~n", [Type, Len])
    end.

errno(-1) -> "EPERM";
errno(-2) -> "ENOENT";
errno(-17) -> "EEXIST";
errno(-22) -> "EINVAL";
errno(-95) -> "EOPNOTSUPP";
errno(N) -> integer_to_list(N).
