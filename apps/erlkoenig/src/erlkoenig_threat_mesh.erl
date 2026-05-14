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

-module(erlkoenig_threat_mesh).
-moduledoc """
Single source of truth for kernel-level IP bans.

Only this process calls erlkoenig_nft:ban/unban. Threat actors send
ban/unban intentions via local_ban/3 and local_unban/1 — they never
speak to the kernel directly.

Each ban is tracked per source (node). A local unban only removes the
local source; the kernel ban stays if a remote source is still active.
This prevents the micro-unban race where a local timer expiry would
briefly open the firewall while a remote ban is still valid.

In cluster mode, bans are propagated via pg. BanUntil uses
os:system_time(millisecond) (epoch-millis) for cluster-wide
comparability. Merge rule: max(all source expiries).

Anti-entropy: on nodeup, all active bans are re-broadcast.
""".

-behaviour(gen_server).

-include("erlkoenig_error.hrl").
-include("nft_tables.hrl").

-export([start_link/1, local_ban/3, local_unban/1, active_bans/0, reconfigure/1]).
-export([init/1, handle_cast/2, handle_info/2, handle_call/3, terminate/2]).

-ifdef(TEST).
-export([extra_ban_set_targets/1, kernel_ban_error/3, kernel_unban_error/2,
         normalize_whitelist/1]).
-endif.

-define(PG_SCOPE, erlkoenig_nft).
-define(PG_GROUP, erlkoenig_threats).

-record(state, {
    %% #{IP => #{SourceNode => ExpiryMs}}
    active_bans :: #{binary() => #{node() => integer()}},
    whitelist :: [binary()],
    %% Timer refs for kernel unban: #{IP => reference()}
    unban_timers :: #{binary() => reference()}
}).

%% ===================================================================
%% Public API
%% ===================================================================

-doc "Start the threat mesh. Config may contain `whitelist`.".
-spec start_link(map()) -> gen_server:start_ret().
start_link(Config) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Config, []).

-doc """
Record a local ban intention from a threat actor.

BanUntil is os:system_time(millisecond) — an absolute epoch timestamp.
The mesh applies the ban to the kernel and broadcasts to the cluster.
""".
-spec local_ban(binary(), integer(), atom()) -> ok.
local_ban(IP, BanUntil, Reason) ->
    gen_server:cast(?MODULE, {local_ban, IP, BanUntil, Reason}).

-doc """
Record a local unban intention from a threat actor.

The kernel ban is only removed if no other source (remote node) still
holds an active ban for this IP.
""".
-spec local_unban(binary()) -> ok.
local_unban(IP) ->
    gen_server:cast(?MODULE, {local_unban, IP}).

-doc "Return all currently active bans with their sources.".
-spec active_bans() -> #{binary() => #{node() => integer()}}.
active_bans() ->
    gen_server:call(?MODULE, active_bans).

-doc "Reconfigure whitelist at runtime (called from erlkoenig_config).".
-spec reconfigure(map()) -> ok.
reconfigure(Config) ->
    gen_server:call(?MODULE, {reconfigure, Config}).

%% ===================================================================
%% gen_server callbacks
%% ===================================================================

init(Config) ->
    try pg:join(?PG_SCOPE, ?PG_GROUP, self())
    catch _:_ -> ok  %% pg scope might not exist in test
    end,
    _ = net_kernel:monitor_nodes(true),
    Whitelist = normalize_whitelist(maps:get(whitelist, Config, [])),
    {ok, #state{
        active_bans = #{},
        whitelist = Whitelist,
        unban_timers = #{}
    }}.

%% --- Local ban (from threat_actor) ---

handle_cast({local_ban, IP, BanUntil, Reason}, State) ->
    case is_whitelisted(IP, State#state.whitelist) of
        true ->
            {noreply, State};
        false ->
            {State2, Applied} = merge_ban(IP, node(), BanUntil, Reason, State),
            case Applied of
                true -> pg_send({ban, IP, BanUntil, Reason, node()});
                false -> ok
            end,
            {noreply, State2}
    end;

%% --- Local unban (from threat_actor timer expiry) ---

handle_cast({local_unban, IP}, State) ->
    State2 = remove_source(IP, node(), State),
    {noreply, State2};

handle_cast(_, State) ->
    {noreply, State}.

%% --- Remote ban (from another node via pg) ---

handle_info({ban, IP, BanUntil, Reason, FromNode}, State)
  when FromNode =/= node() ->
    case is_whitelisted(IP, State#state.whitelist) of
        true ->
            {noreply, State};
        false ->
            {State2, _Applied} = merge_ban(IP, FromNode, BanUntil, Reason, State),
            {noreply, State2}
    end;

%% --- Remote unban ---

handle_info({unban, IP, FromNode}, State) when FromNode =/= node() ->
    State2 = remove_source(IP, FromNode, State),
    {noreply, State2};

%% --- Anti-entropy: on nodeup, re-broadcast all active bans ---

handle_info({nodeup, _Node}, State) ->
    Now = os:system_time(millisecond),
    maps:foreach(fun(IP, Sources) ->
        case effective_expiry(Sources) of
            Exp when Exp > Now ->
                pg_send({ban, IP, Exp, resync, node()});
            _ ->
                ok
        end
    end, State#state.active_bans),
    {noreply, State};

handle_info({nodedown, _Node}, State) ->
    {noreply, State};

%% --- Kernel unban timer ---

handle_info({kernel_unban, IP}, State) ->
    %% Timer fired — check if ban is truly expired (no active sources)
    Now = os:system_time(millisecond),
    Sources = maps:get(IP, State#state.active_bans, #{}),
    ActiveSources = maps:filter(fun(_, Exp) -> Exp > Now end, Sources),
    case {map_size(Sources), map_size(ActiveSources)} of
        {0, _} ->
            Timers2 = maps:remove(IP, State#state.unban_timers),
            {noreply, State#state{unban_timers = Timers2}};
        {_, 0} ->
            _ = do_kernel_unban(IP),
            Bans2 = maps:remove(IP, State#state.active_bans),
            Timers2 = maps:remove(IP, State#state.unban_timers),
            {noreply, State#state{active_bans = Bans2, unban_timers = Timers2}};
        _ ->
            %% Still active sources — reschedule
            State2 = schedule_unban_timer(IP, ActiveSources, State),
            {noreply, State2#state{active_bans = maps:put(IP, ActiveSources,
                                                           State2#state.active_bans)}}
    end;

handle_info(_, State) ->
    {noreply, State}.

handle_call(active_bans, _From, State) ->
    {reply, State#state.active_bans, State};

handle_call({reconfigure, Config}, _From, State) ->
    Whitelist = normalize_whitelist(maps:get(whitelist, Config, [])),
    %% If an operator adds an IP to the whitelist to correct a
    %% wrongful ban, the natural expectation is "ban lifted now" —
    %% not "ban lifted in up to 24 hours when the timer finally
    %% fires". Walk active_bans, drop any kernel ban for IPs that
    %% the new whitelist covers, cancel their unban timers, and
    %% broadcast the unban so peer nodes converge. Non-whitelisted
    %% bans stay untouched.
    WhitelistSet = sets:from_list(Whitelist, [{version, 2}]),
    {CleanedBans, CleanedTimers} =
        maps:fold(
            fun(IP, _Sources, {BansAcc, TimersAcc}) ->
                case sets:is_element(IP, WhitelistSet) of
                    true ->
                        do_kernel_unban(IP),
                        case maps:find(IP, TimersAcc) of
                            {ok, Ref} -> _ = erlang:cancel_timer(Ref), ok;
                            error -> ok
                        end,
                        pg_send({unban, IP, node()}),
                        {maps:remove(IP, BansAcc),
                         maps:remove(IP, TimersAcc)};
                    false ->
                        {BansAcc, TimersAcc}
                end
            end,
            {State#state.active_bans, State#state.unban_timers},
            State#state.active_bans),
    {reply, ok, State#state{whitelist = Whitelist,
                            active_bans = CleanedBans,
                            unban_timers = CleanedTimers}};

handle_call(_, _From, State) ->
    {reply, {error, unknown}, State}.

terminate(_Reason, _State) ->
    ok.

%% ===================================================================
%% Internal
%% ===================================================================

%% Merge a ban source. Apply to kernel if effective expiry changed.
-spec merge_ban(binary(), node(), integer(), atom(), #state{}) -> {#state{}, boolean()}.
merge_ban(IP, Source, BanUntil, Reason, #state{active_bans = Bans} = State) ->
    Sources = maps:get(IP, Bans, #{}),
    OldExpiry = maps:get(Source, Sources, 0),
    NewExpiry = max(OldExpiry, BanUntil),
    Sources2 = Sources#{Source => NewExpiry},
    OldEffective = effective_expiry(Sources),
    NewEffective = effective_expiry(Sources2),
    %% Apply to kernel if effective expiry increased
    Applied = case NewEffective > OldEffective of
        true ->
            do_kernel_ban(IP, NewEffective, Reason);
        false ->
            ok
    end,
    case Applied of
        ok ->
            State2 = State#state{active_bans = Bans#{IP => Sources2}},
            {schedule_unban_timer(IP, Sources2, State2), true};
        {error, _Error} ->
            {State, false}
    end.

%% Remove a source. Kernel-unban only if no active sources remain.
-spec remove_source(binary(), node(), #state{}) -> #state{}.
remove_source(IP, Source, #state{active_bans = Bans} = State) ->
    Sources = maps:get(IP, Bans, #{}),
    case maps:is_key(Source, Sources) of
        false ->
            State;
        true ->
            Sources2 = maps:remove(Source, Sources),
            Now = os:system_time(millisecond),
            ActiveSources = maps:filter(fun(_, Exp) -> Exp > Now end, Sources2),
            case map_size(ActiveSources) of
                0 ->
                    _ = do_kernel_unban(IP),
                    cancel_unban_timer(IP, State),
                    case Source =:= node() of
                        true -> pg_send({unban, IP, node()});
                        false -> ok
                    end,
                    State#state{
                        active_bans = maps:remove(IP, Bans),
                        unban_timers = maps:remove(IP, State#state.unban_timers)
                    };
                _ ->
                    %% Remote sources still active — keep kernel ban
                    State2 = schedule_unban_timer(IP, ActiveSources, State),
                    State2#state{active_bans = Bans#{IP => ActiveSources}}
            end
    end.

%% Apply ban to the kernel.
-spec do_kernel_ban(binary(), integer(), atom()) -> ok | {error, term()}.
do_kernel_ban(IP, EffectiveExpiry, Reason) ->
    Result = try erlkoenig_nft:ban(IP) of
        ok ->
            TimeoutMs = max(100, EffectiveExpiry - os:system_time(millisecond)),
            case apply_extra_ban_targets(IP, TimeoutMs) of
                ok ->
                    logger:notice("[threat_mesh] banned ~s reason=~p",
                                  [erlkoenig_nft_ip:format(IP), Reason]),
                    ok;
                {error, Err} ->
                    Error = kernel_ban_error(IP, Reason, Err),
                    logger:warning("[threat_mesh] ban fan-out failed ~s code=~p: ~p",
                                   [erlkoenig_nft_ip:format(IP), error_code(Error), Err]),
                    broadcast_guard({ct_guard_ban_failed,
                                     #{ip => IP, reason => Reason,
                                       code => error_code(Error), error => Error}}),
                    ok
            end;
        {error, Err} ->
            Error = kernel_ban_error(IP, Reason, Err),
            logger:warning("[threat_mesh] ban failed ~s code=~p: ~p",
                           [erlkoenig_nft_ip:format(IP), error_code(Error), Err]),
            broadcast_guard({ct_guard_ban_failed,
                             #{ip => IP, reason => Reason,
                               code => error_code(Error), error => Error}}),
            {error, Error}
    catch
        C:R ->
            %% Crash path also emits ct_guard_ban_failed — dashboards
            %% subscribed to this event need to see kernel-ban failures
            %% regardless of whether they manifested as {error, _} or
            %% as an exception from erlkoenig_nft:ban/1 (e.g. nfnl_server
            %% crashed, call timeout). Previously only the error-return
            %% branch notified, so a crashed nft gen_server silently
            %% produced no dashboard signal.
            Error = threat_error(kernel_ban_crashed,
                                 #{ip => IP, reason => Reason,
                                   class => C, error => R}),
            logger:warning("[threat_mesh] ban crashed ~s code=~p: ~p:~p",
                           [erlkoenig_nft_ip:format(IP), error_code(Error), C, R]),
            broadcast_guard({ct_guard_ban_failed,
                             #{ip => IP, reason => Reason,
                               code => error_code(Error), error => Error}}),
            {error, Error}
    end,
    Result.

%% Remove ban from the kernel.
-spec do_kernel_unban(binary()) -> ok | {error, term()}.
do_kernel_unban(IP) ->
    Result = try erlkoenig_nft:unban(IP) of
        ok ->
            case apply_extra_unban_targets(IP) of
                ok ->
                    logger:notice("[threat_mesh] unbanned ~s",
                                  [erlkoenig_nft_ip:format(IP)]),
                    broadcast_guard({ct_guard_unban, #{ip => IP}}),
                    ok;
                {error, Err} ->
                    Error = kernel_unban_error(IP, Err),
                    logger:warning("[threat_mesh] unban fan-out failed ~s code=~p: ~p",
                                   [erlkoenig_nft_ip:format(IP), error_code(Error), Err]),
                    broadcast_guard({ct_guard_unban_failed,
                                     #{ip => IP, code => error_code(Error),
                                       error => Error}}),
                    {error, Error}
            end;
        {error, Err} ->
            Error = kernel_unban_error(IP, Err),
            logger:warning("[threat_mesh] unban failed ~s code=~p: ~p",
                           [erlkoenig_nft_ip:format(IP), error_code(Error), Err]),
            broadcast_guard({ct_guard_unban_failed,
                             #{ip => IP, code => error_code(Error),
                               error => Error}}),
            {error, Error}
    catch
        C:R ->
            Error = threat_error(kernel_unban_crashed,
                                 #{ip => IP, class => C, error => R}),
            logger:warning("[threat_mesh] unban crashed ~s code=~p: ~p:~p",
                           [erlkoenig_nft_ip:format(IP), error_code(Error), C, R]),
            broadcast_guard({ct_guard_unban_failed,
                             #{ip => IP, code => error_code(Error),
                               error => Error}}),
            {error, Error}
    end,
    Result.

apply_extra_ban_targets(IP, TimeoutMs) ->
    apply_extra_target_msgs(
        [begin
             Msg = nft_rules:ban_ip(Table, SetName, IP, TimeoutMs),
             fun(S) -> Msg(S) end
         end || {Table, SetName} <- extra_ban_set_targets(IP)]).

apply_extra_unban_targets(IP) ->
    apply_extra_target_msgs(
        [begin
             Msg = nft_rules:unban_ip(Table, SetName, IP),
             fun(S) -> Msg(S) end
         end || {Table, SetName} <- extra_ban_set_targets(IP)]).

apply_extra_target_msgs([]) ->
    ok;
apply_extra_target_msgs(Msgs) ->
    nfnl_server:apply_msgs(erlkoenig_nft_srv, Msgs).

extra_ban_set_targets(IP) ->
    lists:usort([{Table, SetName}
                 || {Table, SetName} <- erlkoenig_config_nft:ban_set_targets(IP),
                    Table =/= ?EK_NFT_TABLE_HOST]).

%% Schedule a timer for kernel unban at the effective expiry.
-spec schedule_unban_timer(binary(), #{node() => integer()}, #state{}) -> #state{}.
schedule_unban_timer(IP, Sources, State) ->
    cancel_unban_timer(IP, State),
    EffExp = effective_expiry(Sources),
    Now = os:system_time(millisecond),
    DelayMs = max(100, EffExp - Now),
    Ref = erlang:send_after(DelayMs, self(), {kernel_unban, IP}),
    State#state{unban_timers = (State#state.unban_timers)#{IP => Ref}}.

-spec cancel_unban_timer(binary(), #state{}) -> ok.
cancel_unban_timer(IP, #state{unban_timers = Timers}) ->
    case maps:find(IP, Timers) of
        {ok, Ref} -> _ = erlang:cancel_timer(Ref), ok;
        error -> ok
    end,
    ok.

%% Max expiry across all sources. 0 if empty.
-spec effective_expiry(#{node() => integer()}) -> integer().
effective_expiry(Sources) when map_size(Sources) =:= 0 -> 0;
effective_expiry(Sources) -> lists:max(maps:values(Sources)).

%% Broadcast to ct_guard_events pg group (existing event bus).
broadcast_guard(Msg) ->
    try
        Members = pg:get_members(?PG_SCOPE, ct_guard_events),
        _ = [Pid ! Msg || Pid <- Members],
        ok
    catch _:_ -> ok
    end.

%% Send to all threat mesh members (other nodes).
pg_send(Msg) ->
    try
        Members = pg:get_members(?PG_SCOPE, ?PG_GROUP),
        _ = [Pid ! Msg || Pid <- Members, Pid =/= self()],
        ok
    catch C:R ->
        _ = threat_error(mesh_propagation_failed,
                         #{message => Msg, class => C, error => R}),
        ok
    end.

%% Normalize whitelist entries to binary IP format.
normalize_whitelist(List) ->
    lists:filtermap(fun(Entry) ->
        case erlkoenig_nft_ip:normalize(Entry) of
            {ok, Bin} -> {true, Bin};
            {error, Reason} ->
                _ = threat_error(whitelist_parse_failed,
                                 #{entry => Entry, reason => Reason}),
                false
        end
    end, List).

is_whitelisted(IP, Whitelist) ->
    lists:member(IP, Whitelist).

kernel_ban_error(IP, Reason, #{code := 'EK_NFT_TIMEOUT'} = Err) ->
    threat_error(kernel_ban_timeout,
                 #{ip => IP, reason => Reason,
                   nft_code => maps:get(code, Err),
                   nft_error => Err});
kernel_ban_error(IP, Reason, Err) ->
    threat_error(kernel_ban_rejected,
                 #{ip => IP, reason => Reason,
                   nft_code => nested_code(Err),
                   nft_error => Err}).

kernel_unban_error(IP, #{code := 'EK_NFT_TIMEOUT'} = Err) ->
    threat_error(kernel_unban_timeout,
                 #{ip => IP, nft_code => maps:get(code, Err),
                   nft_error => Err});
kernel_unban_error(IP, Err) ->
    threat_error(kernel_unban_rejected,
                 #{ip => IP, nft_code => nested_code(Err),
                   nft_error => Err}).

threat_error(kernel_ban_rejected, Data) ->
    ?EK_ERROR(threat, kernel_ban_rejected,
              "kernel rejected threat ban", Data);
threat_error(kernel_ban_timeout, Data) ->
    ?EK_ERROR(threat, kernel_ban_timeout,
              "threat ban timed out while applying kernel state", Data);
threat_error(kernel_ban_crashed, Data) ->
    ?EK_ERROR(threat, kernel_ban_crashed,
              "threat ban crashed while applying kernel state", Data);
threat_error(kernel_unban_rejected, Data) ->
    ?EK_ERROR(threat, kernel_unban_rejected,
              "kernel rejected threat unban", Data);
threat_error(kernel_unban_timeout, Data) ->
    ?EK_ERROR(threat, kernel_unban_timeout,
              "threat unban timed out while applying kernel state", Data);
threat_error(kernel_unban_crashed, Data) ->
    ?EK_ERROR(threat, kernel_unban_crashed,
              "threat unban crashed while applying kernel state", Data);
threat_error(mesh_propagation_failed, Data) ->
    ?EK_ERROR(threat, mesh_propagation_failed,
              "threat mesh propagation failed", Data);
threat_error(whitelist_parse_failed, Data) ->
    ?EK_ERROR(threat, whitelist_parse_failed,
              "threat whitelist entry could not be parsed", Data).

nested_code(#{code := Code}) ->
    Code;
nested_code(_) ->
    undefined.

error_code(#{code := Code}) ->
    Code;
error_code(_) ->
    undefined.
