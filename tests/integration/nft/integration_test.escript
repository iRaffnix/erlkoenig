#!/usr/bin/env escript
%%! -pa _build/default/lib/erlkoenig/ebin

-define(NFPROTO_INET, 1).
-define(REG1, 1).

main(_) ->
    os:cmd("nft delete table inet testfw 2>/dev/null"),

    Seq = erlang:system_time(second),

    Msgs = [
        nft_table:add(?NFPROTO_INET, <<"testfw">>, Seq + 1),

        %% POLICY ACCEPT - safe, won't lock us out
        nft_chain:add(?NFPROTO_INET, #{
            table => <<"testfw">>,
            name  => <<"input">>,
            hook  => input,
            type  => filter,
            priority => 0,
            policy   => accept
        }, Seq + 2),

        %% tcp dport 80 accept
        nft_rule:add(?NFPROTO_INET, <<"testfw">>, <<"input">>, [
            nft_expr_meta:load(l4proto, ?REG1),
            nft_expr_cmp:eq(?REG1, <<6>>),
            nft_expr_payload:tcp_dport(?REG1),
            nft_expr_cmp:eq(?REG1, <<0, 80>>),
            nft_expr_immediate:accept()
        ], Seq + 3),

        %% tcp dport 443 accept
        nft_rule:add(?NFPROTO_INET, <<"testfw">>, <<"input">>, [
            nft_expr_meta:load(l4proto, ?REG1),
            nft_expr_cmp:eq(?REG1, <<6>>),
            nft_expr_payload:tcp_dport(?REG1),
            nft_expr_cmp:eq(?REG1, <<1, 187>>),
            nft_expr_immediate:accept()
        ], Seq + 4)
    ],

    Batch = nft_batch:wrap(Msgs, Seq),
    io:format("Sending ~w bytes (~w messages)~n", [byte_size(Batch), length(Msgs)]),

    {ok, Sock} = nfnl_socket:open(),
    ok = nfnl_socket:send(Sock, Batch),
    recv_loop(Sock),
    nfnl_socket:close(Sock),

    io:format("~n--- nft list ruleset ---~n"),
    io:format("~s", [os:cmd("nft list ruleset")]).

recv_loop(Sock) ->
    case nfnl_socket:recv(Sock) of
        {ok, Data} -> parse_all(Data), recv_loop(Sock);
        {error, timeout} -> ok;
        {error, R} -> io:format("error: ~p~n", [R])
    end.

parse_all(<<>>) -> ok;
parse_all(<<Len:32/little, 2:16/little, _:16/little,
            Seq:32/little, _:32/little, Err:32/signed-little, _/binary>> = D) ->
    case Err of
        0 -> io:format("  seq ~w: OK~n", [Seq]);
        N -> io:format("  seq ~w: ERROR ~w~n", [Seq, N])
    end,
    <<_:Len/binary, Tail/binary>> = D,
    parse_all(Tail);
parse_all(<<Len:32/little, _/binary>> = D) ->
    <<_:Len/binary, Tail/binary>> = D,
    parse_all(Tail);
parse_all(_) -> ok.
