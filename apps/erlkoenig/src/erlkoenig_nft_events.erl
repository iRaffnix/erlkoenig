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

-module(erlkoenig_nft_events).
-moduledoc """
Central event emission for the erlkoenig_nft extension boundary.

All domain events flow through this module. Extensions subscribe via pg.
Delivery is best-effort, non-blocking, fire-and-forget.

This module MUST NOT contain knowledge about specific consumers
(no OTel, no Audit, no export logic).

## Control-Plane Events

`notify_control/3` emits structured events for facade operations:

    erlkoenig_nft_events:notify_control(ban, ok, #{ip => <<"10.0.0.5">>}).

Events are published to the `control_events` pg group as:

    {control_event, #{
        kind    => op_complete,
        op_id   => reference(),
        ts      => integer(),       %% erlang:monotonic_time(microsecond)
        wall_ts => integer(),       %% erlang:system_time(microsecond)
        action  => ban,
        status  => ok,
        details => #{ip => <<"10.0.0.5">>}
    }}

## Existing Event Streams

`notify_ct/1`, `notify_nflog/1`, and `notify_counter_event/1` are
consolidated replacements for the local `broadcast/1` functions that
were previously duplicated across four modules. Message formats are
unchanged — pure pass-through.

## Delivery Semantics

All emission is best-effort via `pg:get_members/2` + `Pid ! Msg`.
No persistence, no backpressure, no delivery guarantee. Consumers
must tolerate loss, gaps, and potential duplicates after restarts.
""".

%% Control-plane events (new)
-export([notify_control/3]).
%% Existing event streams (consolidated from local broadcast/1)
-export([notify_ct/1, notify_nflog/1, notify_counter_event/1]).

%% --- Control-Plane Events ---

-doc """
Emit a control-plane domain event.

Called by the facade after completing an operation. The raw Result
is normalized into a stable external form (status + reason).

    notify_control(ban, ok, #{ip => IPBin})
    notify_control(reload, {error, {-22, einval}}, #{})
""".
-spec notify_control(atom(), ok | {error, term()}, map()) -> ok.
notify_control(Action, Result, Details) ->
    {Status, NormDetails} = normalize_result(Result, Details),
    Event = #{
        kind => op_complete,
        op_id => make_ref(),
        ts => erlang:monotonic_time(microsecond),
        wall_ts => erlang:system_time(microsecond),
        action => Action,
        status => Status,
        details => NormDetails
    },
    broadcast(control_events, {control_event, Event}).

%% --- Existing Event Streams ---

-doc "Publish a conntrack event to the `ct_events` pg group. Pass-through, no wrapping.".
-spec notify_ct(term()) -> ok.
notify_ct(Msg) ->
    broadcast(ct_events, Msg).

-doc "Publish an NFLOG event to the `nflog_events` pg group. Pass-through, no wrapping.".
-spec notify_nflog(term()) -> ok.
notify_nflog(Msg) ->
    broadcast(nflog_events, Msg).

-doc """
Publish a counter event to the `counter_events` pg group.

Generic pass-through — carries both `{counter_event, Name, Data}`
and `{threshold_event, Id, Name, Metric, Current, Threshold}`
with unchanged message format. No wrapping, no rewriting.
""".
-spec notify_counter_event(term()) -> ok.
notify_counter_event(Msg) ->
    broadcast(counter_events, Msg).

%% --- Internal ---

-type pg_group() :: control_events | counter_events | ct_events | nflog_events.
-spec broadcast(pg_group(), term()) -> ok.
broadcast(Group, Msg) ->
    try
        Members = pg:get_members(erlkoenig_nft, Group),
        _ = [Pid ! Msg || Pid <- Members],
        ok
    catch
        _:_ -> ok
    end.

-doc false.
-spec normalize_result(ok | {error, term()}, map()) ->
    {ok | error, map()}.
normalize_result(ok, Details) ->
    {ok, Details};
normalize_result({error, {ErrNo, Code}}, Details) when
    is_integer(ErrNo), is_atom(Code)
->
    %% Netlink-style errors: {-22, einval} → #{reason => einval}
    {error, Details#{
        reason => Code,
        message => iolist_to_binary(io_lib:format("~p (~B)", [Code, ErrNo]))
    }};
normalize_result({error, Reason}, Details) when is_atom(Reason) ->
    {error, Details#{
        reason => Reason,
        message => atom_to_binary(Reason)
    }};
normalize_result({error, Reason}, Details) ->
    %% Catch-all: unknown internal error form → stable external form
    {error, Details#{
        reason => internal_error,
        message => iolist_to_binary(io_lib:format("~p", [Reason]))
    }}.
