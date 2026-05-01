-module(nft_vm_ruleset_tests).
-include_lib("eunit/include/eunit.hrl").

jump_return_continues_in_calling_chain_test() ->
    Chains = #{
        <<"input">> => [jump(<<"child">>), accept()],
        <<"child">> => [return()]
    },
    {Verdict, Trace} = nft_vm:eval_ruleset(Chains, <<"input">>, pkt(), drop),
    ?assertEqual(accept, Verdict),
    ?assertEqual(3, length(Trace)).

goto_return_does_not_continue_calling_chain_test() ->
    Chains = #{
        <<"input">> => [goto(<<"child">>), accept()],
        <<"child">> => [return()]
    },
    {Verdict, Trace} = nft_vm:eval_ruleset(Chains, <<"input">>, pkt(), drop),
    ?assertEqual(drop, Verdict),
    ?assertEqual(2, length(Trace)).

jump_target_terminal_verdict_wins_test() ->
    Chains = #{
        <<"input">> => [jump(<<"child">>), accept()],
        <<"child">> => [drop()]
    },
    {Verdict, Trace} = nft_vm:eval_ruleset(Chains, <<"input">>, pkt(), drop),
    ?assertEqual(drop, Verdict),
    ?assertEqual(2, length(Trace)).

regular_chain_end_behaves_like_return_test() ->
    Chains = #{
        <<"input">> => [jump(<<"child">>), accept()],
        <<"child">> => []
    },
    {Verdict, Trace} = nft_vm:eval_ruleset(Chains, <<"input">>, pkt(), drop),
    ?assertEqual(accept, Verdict),
    ?assertEqual(2, length(Trace)).

legacy_eval_chain_still_exposes_jump_verdict_test() ->
    {Verdict, _Trace} = nft_vm:eval_chain([jump(<<"child">>)], pkt(), drop),
    ?assertEqual({jump, <<"child">>}, Verdict).

unknown_chain_fails_loud_test() ->
    Chains = #{<<"input">> => [jump(<<"missing">>)]},
    ?assertMatch({error, {unknown_chain, <<"missing">>, _}},
                 nft_vm:eval_ruleset(Chains, <<"input">>, pkt(), drop)).

jump(Name) ->
    [{immediate, #{verdict => {jump, Name}}}].

goto(Name) ->
    [{immediate, #{verdict => {goto, Name}}}].

return() ->
    [{immediate, #{verdict => return}}].

accept() ->
    [{immediate, #{verdict => accept}}].

drop() ->
    [{immediate, #{verdict => drop}}].

pkt() ->
    nft_vm_pkt:tcp(#{saddr => {10, 0, 0, 1}}, #{dport => 22}).
