#!/usr/bin/env escript
%% -*- erlang -*-
%% Test 30: nft_set_elem:add_range_elems/5 round-trips through the
%% kernel for interval-flagged sets.
%%
%% Creates a fresh nft table + interval ipv4 set, pushes a KEY +
%% KEY_END batch via add_range_elems, then asks the kernel whether
%% test IPs lie inside / outside the loaded ranges. This proves the
%% `NFTA_SET_ELEM_KEY_END` wire format and
%% `erlkoenig_nft_ip:parse_cidr4/1` line up with real netfilter.
%%
%% Root required (AF_NETLINK write to NFNL_SUBSYS_NFTABLES).
-mode(compile).

-define(SRV,  erlkoenig_nft_srv).
-define(INET, 1).

main(_) ->
    true = code:add_patha(filename:dirname(escript:script_name())),
    io:format("~n=== Test 30: interval-set range elements ===~n~n"),

    case string:trim(os:cmd("id -u")) of
        "0" -> ok;
        _   -> io:format("ERROR: must run as root~n"), halt(1)
    end,

    %% Full boot so nfnl_server + nft supervisors are up.
    test_helper:boot(),
    logger:set_primary_config(level, error),

    Table = <<"test30">>,
    Set   = <<"trusted">>,

    %% Clean slate: drop any stale table from a previous run.
    _ = os:cmd("nft delete table inet " ++ binary_to_list(Table) ++
               " 2>/dev/null"),

    test_helper:step(
      "create table + interval set via nfnl_server",
      fun() ->
          case nfnl_server:apply_msgs(?SRV, [
              fun(S) -> nft_table:add(?INET, Table, S) end,
              fun(S) -> nft_set:add(?INET, #{
                           table => Table, name => Set,
                           type  => ipv4_addr,
                           flags => [interval]
                       }, S) end
          ]) of
              ok -> ok;
              Err -> {error, Err}
          end
      end),

    Ranges = [
        begin {ok, R} = erlkoenig_nft_ip:parse_cidr4(S), R end
        || S <- ["10.0.0.0/8", "192.168.1.0/24", "203.0.113.42"]
    ],

    test_helper:step(
      "load 3 CIDR ranges via add_range_elems/5",
      fun() ->
          case nfnl_server:apply_msgs(?SRV, [
              fun(S) -> nft_set_elem:add_range_elems(?INET, Table, Set,
                                                     Ranges, S) end
          ]) of
              ok -> ok;
              Err -> {error, Err}
          end
      end),

    test_helper:step(
      "kernel lists the set with `flags interval`",
      fun() ->
          Out = os:cmd("nft list set inet " ++ binary_to_list(Table) ++
                       " " ++ binary_to_list(Set)),
          case re:run(Out, "flags\\s+interval", [{capture, none}]) of
              match -> ok;
              _     -> {error, {no_interval_flag, Out}}
          end
      end),

    test_helper:step(
      "all three CIDRs appear in the kernel listing",
      fun() ->
          Out = os:cmd("nft list set inet " ++ binary_to_list(Table) ++
                       " " ++ binary_to_list(Set)),
          Expected = ["10.0.0.0/8", "192.168.1.0/24", "203.0.113.42"],
          Missing = [E || E <- Expected,
                          re:run(Out, escape(E), [{capture, none}])
                              =/= match],
          case Missing of
              [] -> ok;
              _  -> {error, {missing, Missing, Out}}
          end
      end),

    test_helper:step(
      "kernel accepts an IP inside 10.0.0.0/8 as a member",
      fun() ->
          Out = os:cmd("nft get element inet " ++ binary_to_list(Table) ++
                       " " ++ binary_to_list(Set) ++
                       " { 10.42.5.1 } 2>&1"),
          case re:run(Out, "10\\.0\\.0\\.0/8", [{capture, none}]) of
              match -> ok;
              _     -> {error, {probe_failed, Out}}
          end
      end),

    test_helper:step(
      "kernel rejects an IP outside every range",
      fun() ->
          Out = os:cmd("nft get element inet " ++ binary_to_list(Table) ++
                       " " ++ binary_to_list(Set) ++
                       " { 172.16.0.1 } 2>&1"),
          Patterns = ["No such file", "does not exist",
                      "Could not process", "Error"],
          case lists:any(fun(P) ->
                              re:run(Out, P, [{capture, none}]) =:= match
                         end, Patterns) of
              true  -> ok;
              false -> {error, {unexpected_probe_match, Out}}
          end
      end),

    _ = os:cmd("nft delete table inet " ++ binary_to_list(Table) ++
               " 2>/dev/null"),

    io:format("~n=== Test 30 passed ===~n~n"),
    halt(0).

escape(Str) ->
    re:replace(Str, "\\.", "\\\\.", [global, {return, list}]).
