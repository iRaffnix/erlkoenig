%%%-------------------------------------------------------------------
%%% @doc Kernel-response nft parsers fuzz.
%%%
%%% These parse raw bytes that come back from nf_tables netlink
%%% requests.  A malformed kernel response (bug in kernel, corruption,
%%% or an attacker with NET_ADMIN injecting traffic on the socket)
%%% crashing a parser here can cascade through nft_query /
%%% nft_object callers.
%%%
%%% Targets:
%%%   - `nft_decode:rule_description/1`  — rule → human string
%%%   - `nft_query:parse_dump/2`          — table/chain/rule dump
%%%   - `nft_object:parse_obj_response/1` — counter object
%%%   - `nft_object:parse_dump/2`         — counter bulk dump
%%% @end
%%%-------------------------------------------------------------------

-module(nft_parsers_fuzz_test).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(nowarn_unused_function).

rule_description_arbitrary_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_rule_description_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

nft_query_parse_dump_arbitrary_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_nft_query_parse_dump_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

nft_object_parse_obj_arbitrary_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_nft_object_parse_obj_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

nft_object_parse_dump_arbitrary_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_nft_object_parse_dump_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

nft_decode_inner_exprs_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_nft_decode_inner_exprs_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

prop_rule_description_safe() ->
    ?FORALL(Bin, proper_types:binary(),
        run_safely(fun() -> nft_decode:rule_description(Bin) end, Bin)).

prop_nft_query_parse_dump_safe() ->
    ?FORALL(Bin, proper_types:binary(),
        run_safely(fun() -> nft_query:parse_dump(Bin, []) end, Bin)).

prop_nft_object_parse_obj_safe() ->
    ?FORALL(Bin, proper_types:binary(),
        run_safely(fun() -> nft_object:parse_obj_response(Bin) end, Bin)).

prop_nft_object_parse_dump_safe() ->
    ?FORALL(Bin, proper_types:binary(),
        run_safely(fun() -> nft_object:parse_dump(Bin, []) end, Bin)).

%% Each of the per-expr clauses inside nft_decode takes the expr
%% name + attribute list.  Random combinations of both.
prop_nft_decode_inner_exprs_safe() ->
    ?FORALL({Name, Attrs}, {expr_name_gen(), attrs_gen()},
        begin
            Self = self(),
            Pid = spawn(fun() ->
                R = try nft_decode:decode_expr(Name, Attrs) of
                        V -> {ok, V}
                    catch C:E:_ -> {crash, C, E}
                    end,
                Self ! {self(), R}
            end),
            receive
                {Pid, {ok, _}} -> true;
                {Pid, {crash, C, E}} ->
                    io:format(user,
                              "CRASH decode_expr(~p, ~p): ~p:~p~n",
                              [Name, Attrs, C, E]),
                    false
            after 2000 ->
                exit(Pid, kill), false
            end
        end).

expr_name_gen() ->
    proper_types:oneof([<<"meta">>, <<"cmp">>, <<"payload">>,
                        <<"immediate">>, <<"counter">>, <<"ct">>,
                        <<"bitwise">>, <<"lookup">>,
                        <<"unknown_expr">>, <<>>]).

attrs_gen() ->
    ?LET(N, proper_types:choose(0, 6),
         [attr_entry() || _ <- lists:seq(1, N)]).

attr_entry() ->
    ?LET({K, V}, {proper_types:choose(1, 20),
                  ?LET(N, proper_types:choose(0, 32),
                       proper_types:binary(N))},
         {K, V}).

run_safely(F, Label) ->
    Self = self(),
    Pid = spawn(fun() ->
        R = try F() of
                V -> {ok, V}
            catch
                C:E:_ -> {crash, C, E}
            end,
        Self ! {self(), R}
    end),
    receive
        {Pid, {ok, _}} -> true;
        {Pid, {crash, C, E}} ->
            io:format(user, "CRASH ~p:~p on ~p bytes~n",
                      [C, E, byte_size(Label)]),
            false
    after 2000 ->
        exit(Pid, kill),
        io:format(user, "TIMEOUT on ~p bytes~n", [byte_size(Label)]),
        false
    end.
