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

-module(erlkoenig_amqp_forwarder).
-moduledoc """
Thin gen_event handler on erlkoenig_events.

Receives internal events, delegates encoding to erlkoenig_amqp_codec,
and forwards the result via gen_server:cast to the publisher process.

No I/O, no network, no state beyond the publisher PID.
""".

-behaviour(gen_event).

-export([init/1, handle_event/2, handle_call/2, handle_info/2,
         terminate/2, code_change/3]).

init(PublisherPid) ->
    {ok, PublisherPid}.

handle_event(Event, PublisherPid) ->
    case erlkoenig_amqp_codec:encode(Event) of
        {ok, RoutingKey, JsonBin} ->
            gen_server:cast(PublisherPid, {publish, RoutingKey, JsonBin});
        skip ->
            ok
    end,
    {ok, PublisherPid}.

handle_call(_Request, State) ->
    {ok, {error, not_supported}, State}.

handle_info(_Info, State) ->
    {ok, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
