-module(erlkoenig_nft_ct_guard_SUITE).
-moduledoc false.
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

all() ->
    [
        flood_below_threshold,
        flood_at_threshold,
        flood_only_counts_within_window,
        port_scan_below_threshold,
        port_scan_at_threshold,
        port_scan_distinct_ports_only,
        already_banned_not_recounted,
        whitelist_tuple_format,
        whitelist_binary_format,
        whitelist_string_format,
        whitelisted_ip_not_banned,
        cleanup_old_events,
        cleanup_expired_bans
    ].

%% Each test creates its own ETS tables, no shared state

%% --- Detection ---

flood_below_threshold(_) ->
    {C, _B} = make_tables(),
    IP = <<10, 0, 0, 5>>,
    Now = erlang:system_time(second),
    insert_events(C, IP, Now, 49, 80),
    ?assertEqual(49, count_events(C, IP, Now - 10)),
    cleanup_tables(C, _B).

flood_at_threshold(_) ->
    {C, B} = make_tables(),
    IP = <<10, 0, 0, 5>>,
    Now = erlang:system_time(second),
    insert_events(C, IP, Now, 50, 80),
    ?assertEqual(50, count_events(C, IP, Now - 10)),
    cleanup_tables(C, B).

flood_only_counts_within_window(_) ->
    {C, B} = make_tables(),
    IP = <<10, 0, 0, 5>>,
    Now = erlang:system_time(second),
    insert_events(C, IP, Now - 20, 30, 80),
    insert_events(C, IP, Now, 10, 80),
    ?assertEqual(10, count_events(C, IP, Now - 10)),
    cleanup_tables(C, B).

port_scan_below_threshold(_) ->
    {C, B} = make_tables(),
    IP = <<10, 0, 0, 5>>,
    Now = erlang:system_time(second),
    lists:foreach(
        fun(Port) ->
            ets:insert(C, {{IP, Now, erlang:unique_integer([positive])}, Port})
        end,
        lists:seq(1, 19)
    ),
    ?assertEqual(19, length(distinct_ports(C, IP, Now - 60))),
    cleanup_tables(C, B).

port_scan_at_threshold(_) ->
    {C, B} = make_tables(),
    IP = <<10, 0, 0, 5>>,
    Now = erlang:system_time(second),
    lists:foreach(
        fun(Port) ->
            ets:insert(C, {{IP, Now, erlang:unique_integer([positive])}, Port})
        end,
        lists:seq(1, 20)
    ),
    ?assertEqual(20, length(distinct_ports(C, IP, Now - 60))),
    cleanup_tables(C, B).

port_scan_distinct_ports_only(_) ->
    {C, B} = make_tables(),
    IP = <<10, 0, 0, 5>>,
    Now = erlang:system_time(second),
    lists:foreach(
        fun(I) ->
            Port = (I rem 3) + 80,
            ets:insert(C, {{IP, Now, erlang:unique_integer([positive])}, Port})
        end,
        lists:seq(1, 50)
    ),
    ?assertEqual(3, length(distinct_ports(C, IP, Now - 60))),
    cleanup_tables(C, B).

already_banned_not_recounted(_) ->
    {C, B} = make_tables(),
    IP = <<10, 0, 0, 5>>,
    Now = erlang:system_time(second),
    ets:insert(B, {IP, Now, Now + 3600, conn_flood}),
    ?assert(ets:member(B, IP)),
    cleanup_tables(C, B).

%% --- Whitelist (no ETS needed) ---

whitelist_tuple_format(_) ->
    ?assertEqual([<<127, 0, 0, 1>>], normalize_whitelist([{127, 0, 0, 1}])).

whitelist_binary_format(_) ->
    ?assertEqual([<<10, 0, 0, 1>>], normalize_whitelist([<<10, 0, 0, 1>>])).

whitelist_string_format(_) ->
    ?assertEqual([<<192, 168, 1, 1>>], normalize_whitelist(["192.168.1.1"])).

whitelisted_ip_not_banned(_) ->
    WL = [<<127, 0, 0, 1>>, <<10, 0, 0, 1>>],
    ?assert(lists:member(<<127, 0, 0, 1>>, WL)),
    ?assertNot(lists:member(<<10, 0, 0, 5>>, WL)).

%% --- Cleanup ---

cleanup_old_events(_) ->
    {C, B} = make_tables(),
    IP = <<10, 0, 0, 5>>,
    Now = erlang:system_time(second),
    insert_events(C, IP, Now - 120, 20, 80),
    insert_events(C, IP, Now, 5, 80),
    ?assertEqual(25, ets:info(C, size)),
    Deleted = delete_before(C, ets:first(C), Now - 60, 0),
    ?assertEqual(20, Deleted),
    ?assertEqual(5, ets:info(C, size)),
    cleanup_tables(C, B).

cleanup_expired_bans(_) ->
    {C, B} = make_tables(),
    Now = erlang:system_time(second),
    ets:insert(B, {<<10, 0, 0, 1>>, Now - 7200, Now - 3600, conn_flood}),
    ets:insert(B, {<<10, 0, 0, 2>>, Now, Now + 3600, port_scan}),
    ?assertEqual(2, ets:info(B, size)),
    Expired = cleanup_bans(B, Now),
    ?assertEqual(1, Expired),
    ?assertNot(ets:member(B, <<10, 0, 0, 1>>)),
    ?assert(ets:member(B, <<10, 0, 0, 2>>)),
    cleanup_tables(C, B).

%% --- Table helpers ---

make_tables() ->
    C = ets:new(conns, [ordered_set, public]),
    B = ets:new(bans, [set, public]),
    {C, B}.

cleanup_tables(C, B) ->
    ets:delete(C),
    ets:delete(B).

%% --- Logic helpers ---

insert_events(C, IP, BaseTs, Count, Port) ->
    lists:foreach(
        fun(_) ->
            ets:insert(C, {{IP, BaseTs, erlang:unique_integer([positive])}, Port})
        end,
        lists:seq(1, Count)
    ).

count_events(C, SrcIP, Cutoff) ->
    count_range(C, ets:next(C, {SrcIP, Cutoff, 0}), SrcIP, 0).
count_range(_, '$end_of_table', _, Cnt) -> Cnt;
count_range(C, {IP, _, _} = K, IP, Cnt) -> count_range(C, ets:next(C, K), IP, Cnt + 1);
count_range(_, _, _, Cnt) -> Cnt.

distinct_ports(C, SrcIP, Cutoff) ->
    collect_ports(C, ets:next(C, {SrcIP, Cutoff, 0}), SrcIP, sets:new()).
collect_ports(_, '$end_of_table', _, P) ->
    sets:to_list(P);
collect_ports(C, {IP, _, _} = K, IP, P) ->
    case ets:lookup(C, K) of
        [{_, Dp}] -> collect_ports(C, ets:next(C, K), IP, sets:add_element(Dp, P));
        [] -> collect_ports(C, ets:next(C, K), IP, P)
    end;
collect_ports(_, _, _, P) ->
    sets:to_list(P).

delete_before(_, '$end_of_table', _, Cnt) ->
    Cnt;
delete_before(C, {_, Ts, _} = K, Cutoff, Cnt) when Ts < Cutoff ->
    Next = ets:next(C, K),
    ets:delete(C, K),
    delete_before(C, Next, Cutoff, Cnt + 1);
delete_before(_, _, _, Cnt) ->
    Cnt.

cleanup_bans(B, Now) ->
    ets:foldl(
        fun({IP, _, Exp, _}, Cnt) ->
            case Exp =< Now of
                true ->
                    ets:delete(B, IP),
                    Cnt + 1;
                false ->
                    Cnt
            end
        end,
        0,
        B
    ).

normalize_whitelist(L) ->
    lists:map(
        fun
            ({A, B, C, D}) ->
                <<A, B, C, D>>;
            (<<_, _, _, _>> = Bin) ->
                Bin;
            (Str) when is_list(Str) ->
                {ok, {A, B, C, D}} = inet:parse_ipv4_address(Str),
                <<A, B, C, D>>
        end,
        L
    ).
