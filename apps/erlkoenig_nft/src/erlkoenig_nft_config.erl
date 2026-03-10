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
  1. $ERLKOENIG_CONFIG_DIR/firewall.term (default: /etc/erlkoenig_nft)
  2. code:priv_dir(erlkoenig_nft)/firewall.term
  3. priv/firewall.term (development fallback)
""".

-export([config_path/0]).

-spec config_path() -> {ok, string()} | {error, not_found}.
config_path() ->
    ConfigDir = os:getenv("ERLKOENIG_CONFIG_DIR", "/etc/erlkoenig_nft"),
    EtcPath = filename:join(ConfigDir, "firewall.term"),
    case filelib:is_regular(EtcPath) of
        true ->
            {ok, EtcPath};
        false ->
            case code:priv_dir(erlkoenig_nft) of
                {error, _} ->
                    case filelib:is_regular("priv/firewall.term") of
                        true  -> {ok, "priv/firewall.term"};
                        false -> {error, not_found}
                    end;
                PrivDir ->
                    Path = filename:join(PrivDir, "firewall.term"),
                    case filelib:is_regular(Path) of
                        true  -> {ok, Path};
                        false ->
                            case filelib:is_regular("priv/firewall.term") of
                                true  -> {ok, "priv/firewall.term"};
                                false -> {error, not_found}
                            end
                    end
            end
    end.
