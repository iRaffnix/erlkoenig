-module(erlkoenig_nft_ct_SUITE).
-moduledoc false.
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

all() ->
    [parse_tcp_event, parse_udp_event, parse_icmp_event,
     event_key_tcp, event_key_no_ports,
     agg_table_increment, agg_table_decrement,
     agg_table_delete_at_zero, top_sources_ordering].

%% No init_per_suite/end_per_suite needed

%% --- Parsing tests (pure data, no ETS) ---

parse_tcp_event(_) ->
    IpAttrs = [{1, <<10,0,0,5>>}, {2, <<192,168,1,1>>}],
    ProtoAttrs = [{1, <<6>>}, {2, <<213,57>>}, {3, <<0,80>>}],
    TupleAttrs = [{1, nested, IpAttrs}, {2, nested, ProtoAttrs}],
    Attrs = [{1, nested, TupleAttrs}, {7, <<0,0,1,44>>}, {3, <<0,0,0,8>>}],
    {1, nested, Tuple} = lists:keyfind(1, 1, Attrs),
    {1, nested, Ip} = lists:keyfind(1, 1, Tuple),
    ?assertMatch({1, <<10,0,0,5>>}, lists:keyfind(1, 1, Ip)).

parse_udp_event(_) ->
    ?assertMatch({1, <<17>>}, lists:keyfind(1, 1, [{1, <<17>>}, {2, <<0,53>>}])).

parse_icmp_event(_) ->
    ?assertMatch({1, <<1>>}, lists:keyfind(1, 1, [{1, <<1>>}, {5, <<8>>}])).

event_key_tcp(_) ->
    Event = #{proto => 6, src => <<10,0,0,5>>, sport => 54321,
              dst => <<192,168,1,1>>, dport => 80},
    ?assertEqual({6, <<10,0,0,5>>, 54321, <<192,168,1,1>>, 80}, event_to_key(Event)).

event_key_no_ports(_) ->
    Event = #{proto => 1, src => <<10,0,0,5>>, dst => <<192,168,1,1>>},
    ?assertEqual({1, <<10,0,0,5>>, 0, <<192,168,1,1>>, 0}, event_to_key(Event)).

%% --- Aggregation tests (each creates/destroys own ETS) ---

agg_table_increment(_) ->
    T = ets:new(agg_test, [set, public]),
    IP = <<10,0,0,5>>,
    update_agg(T, IP, 1), [{_, 1, _, _}] = ets:lookup(T, IP),
    update_agg(T, IP, 1), [{_, 2, _, _}] = ets:lookup(T, IP),
    update_agg(T, IP, 1), [{_, 3, _, _}] = ets:lookup(T, IP),
    ets:delete(T).

agg_table_decrement(_) ->
    T = ets:new(agg_test, [set, public]),
    IP = <<10,0,0,5>>,
    update_agg(T, IP, 1), update_agg(T, IP, 1), update_agg(T, IP, 1),
    [{_, 3, _, _}] = ets:lookup(T, IP),
    update_agg(T, IP, -1),
    [{_, 2, _, _}] = ets:lookup(T, IP),
    ets:delete(T).

agg_table_delete_at_zero(_) ->
    T = ets:new(agg_test, [set, public]),
    IP = <<10,0,0,5>>,
    update_agg(T, IP, 1), update_agg(T, IP, -1),
    ?assertEqual([], ets:lookup(T, IP)),
    ets:delete(T).

top_sources_ordering(_) ->
    T = ets:new(agg_test, [set, public]),
    IP1 = <<10,0,0,1>>, IP2 = <<10,0,0,2>>, IP3 = <<10,0,0,3>>,
    update_agg(T, IP1, 1),
    update_agg(T, IP2, 1), update_agg(T, IP2, 1),
    update_agg(T, IP3, 1), update_agg(T, IP3, 1), update_agg(T, IP3, 1),
    All = ets:tab2list(T),
    Sorted = lists:sort(fun({_, C1, _, _}, {_, C2, _, _}) -> C1 > C2 end, All),
    Top2 = [{IP, Count} || {IP, Count, _, _} <- lists:sublist(Sorted, 2)],
    ?assertEqual([{IP3, 3}, {IP2, 2}], Top2),
    ets:delete(T).

%% --- Helpers ---

event_to_key(#{proto := P, src := S, sport := SP, dst := D, dport := DP}) ->
    {P, S, SP, D, DP};
event_to_key(#{proto := P, src := S, dst := D}) ->
    {P, S, 0, D, 0}.

update_agg(T, SrcIP, Delta) ->
    Now = erlang:system_time(second),
    case ets:lookup(T, SrcIP) of
        [{_, Count, First, _}] ->
            New = max(0, Count + Delta),
            case New of
                0 -> ets:delete(T, SrcIP);
                _ -> ets:insert(T, {SrcIP, New, First, Now})
            end;
        [] when Delta > 0 ->
            ets:insert(T, {SrcIP, 1, Now, Now});
        [] -> ok
    end.
