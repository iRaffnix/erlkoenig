%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%

-module(erlkoenig_nft_nflog_tests).

-include_lib("eunit/include/eunit.hrl").

%% ============================================================
%% Phase 6.0c: ensure_started/1 receiver pooling
%% ============================================================
%%
%% The actual gen_server cannot be started in non-root eunit
%% (NFLOG socket open requires CAP_NET_ADMIN). What we test is the
%% pooling guarantee: when a process is already registered under
%% `name_for(Group)', `ensure_started/1' returns that pid instead
%% of trying to spawn a new gen_server.

name_for_test_() ->
    [
        ?_assertEqual(erlkoenig_nft_nflog_100,
                      erlkoenig_nft_nflog:name_for(100)),
        ?_assertEqual(erlkoenig_nft_nflog_0,
                      erlkoenig_nft_nflog:name_for(0)),
        ?_assertEqual(erlkoenig_nft_nflog_42,
                      erlkoenig_nft_nflog:name_for(42))
    ].

ensure_started_returns_existing_pid_test() ->
    Group = 9999,
    Name = erlkoenig_nft_nflog:name_for(Group),
    %% Spawn a placeholder that holds the registered name, simulating
    %% an already-running receiver. The placeholder responds to no
    %% messages — `ensure_started/1' must return its pid based on
    %% `whereis/1' alone, not by sending probes.
    DummyPid = spawn(fun loop_until_killed/0),
    true = register(Name, DummyPid),
    try
        ?assertEqual({ok, DummyPid},
                     erlkoenig_nft_nflog:ensure_started(Group)),
        ?assert(lists:member(DummyPid, linked_processes()))
    after
        unlink(DummyPid),
        case whereis(Name) of
            DummyPid -> unregister(Name);
            _ -> ok
        end,
        exit(DummyPid, kill)
    end.

linked_processes() ->
    {links, Links} = process_info(self(), links),
    Links.

loop_until_killed() ->
    receive _ -> loop_until_killed() end.
