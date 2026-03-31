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

-module(erlkoenig_nft_config).
-moduledoc """
Shared configuration utilities.

Locates the firewall.term config file using the search order:
  1. $ERLKOENIG_CONFIG_DIR/firewall.term (explicit override)
  2. etc/firewall.term (relative to CWD — works for release and dev)
  3. /opt/erlkoenig_nft/etc/firewall.term (installed release)
""".

-export([config_path/0]).

-spec config_path() -> {ok, string()} | {error, not_found}.
config_path() ->
    Candidates =
        case os:getenv("ERLKOENIG_CONFIG_DIR") of
            false ->
                [
                    "etc/firewall.term",
                    "/opt/erlkoenig_nft/etc/firewall.term"
                ];
            Dir ->
                [filename:join(Dir, "firewall.term")]
        end,
    find_first(Candidates).

-spec find_first([string()]) -> {ok, string()} | {error, not_found}.
find_first([]) ->
    {error, not_found};
find_first([Path | Rest]) ->
    case filelib:is_regular(Path) of
        true -> {ok, Path};
        false -> find_first(Rest)
    end.
