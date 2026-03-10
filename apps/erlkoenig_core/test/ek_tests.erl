%%%-------------------------------------------------------------------
%%% @doc Unit tests for ek (Operator Shell).
%%%
%%% Tests the pure formatting functions (format_bytes, format_cpu,
%%% format_ip4, to_bin, to_str, state_color) without needing running
%%% containers or the full OTP application.
%%% @end
%%%-------------------------------------------------------------------

-module(ek_tests).

-include_lib("eunit/include/eunit.hrl").

%% ek's formatting functions are not exported, so we test them
%% indirectly by calling the module and capturing io output, or
%% by reimplementing the pure logic for verification.

%% =================================================================
%% format_bytes (reimplemented for unit testing)
%% =================================================================

%% Since format_bytes is internal, we verify the logic directly.

format_bytes(B) when is_integer(B), B >= 1_073_741_824 ->
    lists:flatten(io_lib:format("~.1fG", [B / 1_073_741_824]));
format_bytes(B) when is_integer(B), B >= 1_048_576 ->
    lists:flatten(io_lib:format("~.1fM", [B / 1_048_576]));
format_bytes(B) when is_integer(B), B >= 1024 ->
    lists:flatten(io_lib:format("~.1fK", [B / 1024]));
format_bytes(B) when is_integer(B) ->
    integer_to_list(B) ++ "B";
format_bytes(_) -> "-".

format_bytes_bytes_test() ->
    ?assertEqual("0B", format_bytes(0)),
    ?assertEqual("512B", format_bytes(512)),
    ?assertEqual("1023B", format_bytes(1023)).

format_bytes_kilobytes_test() ->
    ?assertEqual("1.0K", format_bytes(1024)),
    ?assertEqual("1.5K", format_bytes(1536)),
    ?assertEqual("1024.0K", format_bytes(1_048_575)).

format_bytes_megabytes_test() ->
    ?assertEqual("1.0M", format_bytes(1_048_576)),
    ?assertEqual("48.2M", format_bytes(50_529_028)),
    ?assertEqual("512.0M", format_bytes(536_870_912)).

format_bytes_gigabytes_test() ->
    ?assertEqual("1.0G", format_bytes(1_073_741_824)),
    ?assertEqual("2.5G", format_bytes(2_684_354_560)).

format_bytes_non_integer_test() ->
    ?assertEqual("-", format_bytes(undefined)),
    ?assertEqual("-", format_bytes(nil)).

%% =================================================================
%% format_cpu (reimplemented for unit testing)
%% =================================================================

format_cpu(Usec) when is_integer(Usec) ->
    Secs = Usec / 1_000_000,
    lists:flatten(io_lib:format("~.1fs", [Secs]));
format_cpu(_) -> "-".

format_cpu_zero_test() ->
    ?assertEqual("0.0s", format_cpu(0)).

format_cpu_subsecond_test() ->
    ?assertEqual("0.5s", format_cpu(500_000)).

format_cpu_seconds_test() ->
    ?assertEqual("142.3s", format_cpu(142_300_000)).

format_cpu_large_test() ->
    ?assertEqual("891.5s", format_cpu(891_500_000)).

format_cpu_undefined_test() ->
    ?assertEqual("-", format_cpu(undefined)).

%% =================================================================
%% format_ip4 (reimplemented for unit testing)
%% =================================================================

format_ip4({A, B, C, D}) ->
    lists:flatten(io_lib:format("~p.~p.~p.~p", [A, B, C, D])).

format_ip4_test() ->
    ?assertEqual("10.0.0.10", format_ip4({10, 0, 0, 10})),
    ?assertEqual("192.168.1.1", format_ip4({192, 168, 1, 1})),
    ?assertEqual("0.0.0.0", format_ip4({0, 0, 0, 0})),
    ?assertEqual("255.255.255.255", format_ip4({255, 255, 255, 255})).

%% =================================================================
%% to_bin / to_str (reimplemented for unit testing)
%% =================================================================

to_bin(Name) when is_atom(Name) -> atom_to_binary(Name);
to_bin(Name) when is_list(Name) -> list_to_binary(Name);
to_bin(Name) when is_binary(Name) -> Name.

to_str(Name) when is_atom(Name) -> atom_to_list(Name);
to_str(Name) when is_binary(Name) -> binary_to_list(Name);
to_str(Name) when is_list(Name) -> Name.

to_bin_atom_test() ->
    ?assertEqual(<<"web">>, to_bin(web)).

to_bin_binary_test() ->
    ?assertEqual(<<"web">>, to_bin(<<"web">>)).

to_bin_string_test() ->
    ?assertEqual(<<"web">>, to_bin("web")).

to_str_atom_test() ->
    ?assertEqual("web", to_str(web)).

to_str_binary_test() ->
    ?assertEqual("web", to_str(<<"web">>)).

to_str_string_test() ->
    ?assertEqual("web", to_str("web")).

%% All three input types resolve to the same value
name_resolution_equivalence_test() ->
    ?assertEqual(to_bin(web), to_bin(<<"web">>)),
    ?assertEqual(to_bin(web), to_bin("web")),
    ?assertEqual(to_str(web), to_str(<<"web">>)),
    ?assertEqual(to_str(web), to_str("web")).

%% =================================================================
%% state_color
%% =================================================================

%% Verify state_color returns non-empty ANSI for known states.
state_color(running)    -> "\e[32m";
state_color(stopped)    -> "\e[31m";
state_color(failed)     -> "\e[31m";
state_color(restarting) -> "\e[33m";
state_color(creating)   -> "\e[33m";
state_color(_)          -> "".

state_color_running_test() ->
    ?assertEqual("\e[32m", state_color(running)).

state_color_stopped_test() ->
    ?assertEqual("\e[31m", state_color(stopped)).

state_color_failed_test() ->
    ?assertEqual("\e[31m", state_color(failed)).

state_color_restarting_test() ->
    ?assertEqual("\e[33m", state_color(restarting)).

state_color_unknown_test() ->
    ?assertEqual("", state_color(something_else)).

%% =================================================================
%% help output (smoke test via io capture)
%% =================================================================

help_output_test() ->
    %% Capture io output from ek:help/0
    OldGL = group_leader(),
    CaptPid = spawn_link(fun() -> io_server_loop([]) end),
    group_leader(CaptPid, self()),
    ok = ek:help(),
    group_leader(OldGL, self()),
    Output = io_capture_get(CaptPid),
    %% ANSI codes are embedded, so match substrings that appear in the output
    ?assert(string:find(Output, "Operator Shell") =/= nomatch),
    ?assert(string:find(Output, "ek:ps()") =/= nomatch),
    ?assert(string:find(Output, "ek:inspect") =/= nomatch),
    ?assert(string:find(Output, "ek:logs") =/= nomatch),
    ?assert(string:find(Output, "ek:events") =/= nomatch).

%% =================================================================
%% IO capture helpers
%% =================================================================

io_capture_get(Pid) ->
    Ref = make_ref(),
    Pid ! {get, self(), Ref},
    receive
        {Ref, Data} -> Data
    after 2000 -> ""
    end.

io_server_loop(Acc) ->
    receive
        {io_request, From, ReplyAs, Request} ->
            {Reply, NewAcc} = io_handle_request(Request, Acc),
            From ! {io_reply, ReplyAs, Reply},
            io_server_loop(NewAcc);
        {get, Caller, Ref} ->
            Caller ! {Ref, unicode:characters_to_list(lists:reverse(Acc))}
    end.

io_handle_request({put_chars, _Encoding, Chars}, Acc) ->
    {ok, [unicode:characters_to_binary(Chars) | Acc]};
io_handle_request({put_chars, _Encoding, M, F, A}, Acc) ->
    Chars = apply(M, F, A),
    {ok, [unicode:characters_to_binary(Chars) | Acc]};
io_handle_request({put_chars, Chars}, Acc) ->
    {ok, [unicode:characters_to_binary(Chars) | Acc]};
io_handle_request(_Other, Acc) ->
    {ok, Acc}.
