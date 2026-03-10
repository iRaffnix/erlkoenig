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

%%%-------------------------------------------------------------------
%% @doc erlkoenig application callback
%%
%% Boot order:
%%   1. Start supervisor (core services incl. zones + firewall table)
%%   2. Setup nftables (per-zone masquerade + NAT)
%%   3. Autostart containers from config file
%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    {ok, Sup} = erlkoenig_sup:start_link(),
    setup_firewall(),
    autostart_containers(),
    {ok, Sup}.

stop(_State) ->
    _ = erlkoenig_firewall_nft:teardown_table(),
    ok.

%% Setup nftables table with masquerade for all zones.
setup_firewall() ->
    Zones = try erlkoenig_zone:zones() catch _:_ -> [] end,
    ZoneConfigs = [erlkoenig_zone:zone_config(Z) || Z <- Zones],
    case erlkoenig_firewall_nft:setup_table(ZoneConfigs) of
        ok -> ok;
        {error, Reason} ->
            logger:error("firewall setup failed: ~p", [Reason])
    end.

%% Auto-start containers from config file.
%% Searches: {erlkoenig, [{config_file, "/etc/erlkoenig/cluster.term"}]}
%% Or default: /etc/erlkoenig/cluster.term
autostart_containers() ->
    ConfigFile = application:get_env(erlkoenig_core, config_file, "/etc/erlkoenig/cluster.term"),
    case filelib:is_regular(ConfigFile) of
        true ->
            logger:info("autostart: loading ~s", [ConfigFile]),
            case erlkoenig_config:load(ConfigFile) of
                {ok, Started} ->
                    logger:info("autostart: ~p containers started", [length(Started)]);
                {error, Reason} ->
                    logger:warning("autostart: failed to load ~s: ~p",
                                   [ConfigFile, Reason])
            end;
        false ->
            ok
    end.
