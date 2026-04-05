#!/usr/bin/env escript
%% -*- erlang -*-
%%
%% Apply a .term config via the full erlkoenig_nft OTP application.
%% Designed to run inside an unshare -n namespace.
%%
%% Usage: escript nfnl_apply.escript <rootdir> <config.term>
%%
%% The escript dynamically loads all beam files from <rootdir>/lib/*/ebin,
%% copies the config to etc/firewall.term (where the app expects it),
%% then starts the full OTP application which applies the rules via Netlink.
%%
%% Note: No -mode(compile) — module references must be resolved at runtime
%% because code paths are added dynamically.

main([RootDir, TermFile]) ->
    %% Add all ebin paths from the release
    Paths = filelib:wildcard(RootDir ++ "/lib/*/ebin"),
    [code:add_pathz(P) || P <- Paths],

    %% Copy config to where the application expects it
    ConfDir = "etc",
    filelib:ensure_dir(ConfDir ++ "/"),
    file:delete(ConfDir ++ "/firewall.term"),
    {ok, _} = file:copy(TermFile, ConfDir ++ "/firewall.term"),

    %% Start the full OTP application (crypto -> compiler -> erlkoenig_nft)
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(compiler),
    case application:ensure_all_started(erlkoenig_nft) of
        {ok, _} ->
            halt(0);
        {error, {erlkoenig_nft, Reason}} ->
            io:format(standard_error, "start error: ~p~n", [Reason]),
            halt(1)
    end;

main(_) ->
    io:format(standard_error, "Usage: nfnl_apply.escript <rootdir> <config.term>~n", []),
    halt(1).
