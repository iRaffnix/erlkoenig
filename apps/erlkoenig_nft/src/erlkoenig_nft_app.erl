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

-module(erlkoenig_nft_app).
-moduledoc """
Erlkönig OTP application.

Starts the supervision tree with a named nfnl_server process.
The server is registered as `erlkoenig_nft_srv` and can be used
directly from any process, including Elixir/Phoenix.

    :erlkoenig_nft_srv
    |> :nfnl_server.apply_msgs([...])
""".

-behaviour(application).

-export([start/2, stop/1]).

-spec start(atom(), list()) -> {ok, pid()} | {error, term()}.
start(_Type, _Args) ->
    erlkoenig_nft_sup:start_link().

-spec stop(any()) -> ok.
stop(_State) ->
    ok.
