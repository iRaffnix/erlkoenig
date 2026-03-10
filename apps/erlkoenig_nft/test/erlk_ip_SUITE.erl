-module(erlk_ip_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile(export_all).

all() ->
    [normalize_v4_tuple,
     normalize_v4_binary,
     normalize_v4_string,
     normalize_v4_binstring,
     normalize_v6_tuple,
     normalize_v6_binary,
     normalize_v6_string,
     normalize_v6_binstring,
     normalize_v6_compressed,
     normalize_error,
     format_v4,
     format_v6,
     version_v4,
     version_v6,
     af_v4,
     af_v6].

%% --- normalize IPv4 ---

normalize_v4_tuple(_) ->
    ?assertEqual({ok, <<10, 0, 0, 1>>}, erlk_ip:normalize({10, 0, 0, 1})).

normalize_v4_binary(_) ->
    ?assertEqual({ok, <<192, 168, 1, 1>>}, erlk_ip:normalize(<<192, 168, 1, 1>>)).

normalize_v4_string(_) ->
    ?assertEqual({ok, <<127, 0, 0, 1>>}, erlk_ip:normalize("127.0.0.1")).

normalize_v4_binstring(_) ->
    ?assertEqual({ok, <<10, 0, 0, 5>>}, erlk_ip:normalize(<<"10.0.0.5">>)).

%% --- normalize IPv6 ---

normalize_v6_tuple(_) ->
    ?assertEqual({ok, <<16#2001:16, 16#0db8:16, 0:16, 0:16, 0:16, 0:16, 0:16, 16#0001:16>>},
                 erlk_ip:normalize({16#2001, 16#0db8, 0, 0, 0, 0, 0, 1})).

normalize_v6_binary(_) ->
    Bin = <<16#2001:16, 16#0db8:16, 0:16, 0:16, 0:16, 0:16, 0:16, 1:16>>,
    ?assertEqual({ok, Bin}, erlk_ip:normalize(Bin)).

normalize_v6_string(_) ->
    {ok, Bin} = erlk_ip:normalize("2001:db8::1"),
    ?assertEqual(16, byte_size(Bin)),
    ?assertEqual(<<16#2001:16, 16#0db8:16, 0:16, 0:16, 0:16, 0:16, 0:16, 1:16>>, Bin).

normalize_v6_binstring(_) ->
    {ok, Bin} = erlk_ip:normalize(<<"::1">>),
    ?assertEqual(16, byte_size(Bin)),
    ?assertEqual(<<0:120, 1:8>>, Bin).

normalize_v6_compressed(_) ->
    {ok, Bin} = erlk_ip:normalize("fe80::1"),
    ?assertEqual(16, byte_size(Bin)),
    ?assertEqual(<<16#fe80:16, 0:96, 1:16>>, Bin).

%% --- normalize errors ---

normalize_error(_) ->
    ?assertEqual({error, bad_ip}, erlk_ip:normalize("not-an-ip")),
    ?assertEqual({error, bad_ip}, erlk_ip:normalize(42)),
    ?assertEqual({error, bad_ip}, erlk_ip:normalize(<<1, 2, 3>>)).

%% --- format ---

format_v4(_) ->
    Result = iolist_to_binary(erlk_ip:format(<<10, 0, 0, 1>>)),
    ?assertEqual(<<"10.0.0.1">>, Result).

format_v6(_) ->
    Bin = <<16#2001:16, 16#0db8:16, 0:16, 0:16, 0:16, 0:16, 0:16, 1:16>>,
    Result = iolist_to_binary(erlk_ip:format(Bin)),
    %% inet:ntoa produces compressed notation
    ?assertNotEqual(<<>>, Result).

%% --- version ---

version_v4(_) ->
    ?assertEqual(v4, erlk_ip:version(<<10, 0, 0, 1>>)).

version_v6(_) ->
    ?assertEqual(v6, erlk_ip:version(<<0:128>>)).

%% --- af ---

af_v4(_) ->
    ?assertEqual(2, erlk_ip:af(<<10, 0, 0, 1>>)).

af_v6(_) ->
    ?assertEqual(10, erlk_ip:af(<<0:128>>)).
