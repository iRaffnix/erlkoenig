#!/usr/bin/env escript
%%! -pa _build/default/lib/erlkoenig_nft/ebin

-define(INET, 1).

main(_) ->
    os:cmd("nft delete table inet dbg 2>/dev/null"),

    {ok, Srv} = nfnl_server:start_link(),
    T = <<"dbg">>,

    ok = nfnl_server:apply_msgs(Srv, [
        fun(S) -> nft_table:add(?INET, T, S) end,
        fun(S) -> nft_chain:add(?INET, #{
            table => T, name => <<"input">>,
            hook => input, type => filter,
            priority => 0, policy => accept
        }, S) end,
        nft_rules:tcp_accept_count(T, <<"input">>, 80)
    ]),

    {ok, Sock} = nfnl_socket:open(),
    FilterAttrs = nfnl_attr:encode_str(1, T),
    Msg = nfnl_msg:build_hdr(7, ?INET, 16#0301, 999, FilterAttrs),
    ok = nfnl_socket:send(Sock, Msg),

    {ok, Data} = nfnl_socket:recv(Sock),
    %% Skip nlmsghdr(16) + nfgenmsg(4)
    <<_:32/little, _:16/little, _:16/little, _:32/little, _:32/little,
      _:4/binary, Attrs/binary>> = Data,
    
    io:format("Raw attrs:~n~p~n~n", [nfnl_attr:decode(Attrs)]),

    nfnl_socket:close(Sock),
    nfnl_server:stop(Srv),
    os:cmd("nft delete table inet dbg").
