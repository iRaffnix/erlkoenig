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

-module(erlkoenig_health).
-moduledoc """
Health checks for containers.

Periodically checks container health via TCP connect.
If a check fails N times in a row, the container is restarted.

Usage:
  erlkoenig_health:add(ContainerPid, #{
      type => tcp,
      port => 8080,
      interval => 5000,    %% ms between checks (default 5s)
      timeout => 2000,     %% connect timeout (default 2s)
      retries => 3         %% failures before action (default 3)
  }).
  erlkoenig_health:remove(ContainerPid).
  erlkoenig_health:status().
""".

-behaviour(gen_server).

-export([start_link/0,
         add/2,
         remove/1,
         status/0]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-record(check, {
    pid       :: pid(),
    ip        :: inet:ip4_address(),
    type      :: tcp,
    port      :: inet:port_number(),
    interval  :: pos_integer(),
    timeout   :: pos_integer(),
    retries   :: pos_integer(),
    failures  = 0 :: non_neg_integer(),
    last      :: ok | fail | undefined,
    timer     :: reference() | undefined
}).

%% =================================================================
%% API
%% =================================================================

-spec start_link() -> gen_server:start_ret().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-spec add(pid(), map()) -> ok | {error, term()}.
add(ContainerPid, Opts) ->
    gen_server:call(?MODULE, {add, ContainerPid, Opts}).

-spec remove(pid()) -> ok.
remove(ContainerPid) ->
    gen_server:call(?MODULE, {remove, ContainerPid}).

-spec status() -> [map()].
status() ->
    gen_server:call(?MODULE, status).

%% =================================================================
%% gen_server callbacks
%% =================================================================

init([]) ->
    process_flag(trap_exit, true),
    proc_lib:set_label(erlkoenig_health),
    {ok, #{}}.

handle_call({add, Pid, Opts}, _From, State) ->
    case get_container_ip(Pid) of
        {ok, Ip} ->
            Check = #check{
                pid      = Pid,
                ip       = Ip,
                type     = maps:get(type, Opts, tcp),
                port     = maps:get(port, Opts, 80),
                interval = maps:get(interval, Opts, 5000),
                timeout  = maps:get(timeout, Opts, 2000),
                retries  = maps:get(retries, Opts, 3)
            },
            Check2 = schedule_check(Check),
            monitor(process, Pid),
            {reply, ok, State#{Pid => Check2}};
        {error, _} = Err ->
            {reply, Err, State}
    end;

handle_call({remove, Pid}, _From, State) ->
    State2 = cancel_and_remove(Pid, State),
    {reply, ok, State2};

handle_call(status, _From, State) ->
    Result = maps:fold(fun(Pid, #check{} = C, Acc) ->
        [#{pid => Pid,
           ip => C#check.ip,
           port => C#check.port,
           failures => C#check.failures,
           last => C#check.last,
           retries => C#check.retries} | Acc]
    end, [], State),
    {reply, Result, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({check, Pid}, State) ->
    case maps:find(Pid, State) of
        {ok, Check} ->
            Check2 = run_check(Check),
            Check3 = schedule_check(Check2),
            {noreply, State#{Pid := Check3}};
        error ->
            {noreply, State}
    end;

handle_info({'DOWN', _Ref, process, Pid, _Reason}, State) ->
    {noreply, cancel_and_remove(Pid, State)};

handle_info(_Msg, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    maps:foreach(fun(_Pid, #check{timer = T}) ->
        cancel_timer(T)
    end, State),
    ok.

%% =================================================================
%% Internal
%% =================================================================

-spec get_container_ip(pid()) -> {ok, inet:ip4_address()} | {error, term()}.
get_container_ip(Pid) ->
    try erlkoenig_ct:get_info(Pid) of
        #{state := running, net_info := #{ip := Ip}} -> {ok, Ip};
        #{state := running, id := _} -> {error, no_ip};
        #{state := S} -> {error, {not_running, S}}
    catch exit:{noproc, _} -> {error, not_found}
    end.

-spec schedule_check(#check{}) -> #check{}.
schedule_check(#check{interval = Interval, pid = Pid} = Check) ->
    Ref = erlang:send_after(Interval, self(), {check, Pid}),
    Check#check{timer = Ref}.

-spec cancel_timer(reference() | undefined) -> ok.
cancel_timer(undefined) -> ok;
cancel_timer(Ref) -> _ = erlang:cancel_timer(Ref), ok.

-spec cancel_and_remove(pid(), map()) -> map().
cancel_and_remove(Pid, State) ->
    case maps:find(Pid, State) of
        {ok, #check{timer = T}} ->
            cancel_timer(T),
            maps:remove(Pid, State);
        error ->
            State
    end.

-spec run_check(#check{}) -> #check{}.
run_check(#check{type = tcp, ip = Ip, port = Port, timeout = Timeout} = Check) ->
    case gen_tcp:connect(inet:ntoa(Ip), Port, [binary, {active, false}], Timeout) of
        {ok, Sock} ->
            gen_tcp:close(Sock),
            Check#check{failures = 0, last = ok};
        {error, _} ->
            handle_failure(Check)
    end.

-spec handle_failure(#check{}) -> #check{}.
handle_failure(#check{failures = F, retries = Max, pid = Pid} = Check) ->
    NewF = F + 1,
    Check2 = Check#check{failures = NewF, last = fail},
    case NewF >= Max of
        true ->
            logger:warning("health check failed for ~p (~p/~p), restarting",
                           [Pid, NewF, Max]),
            erlkoenig_events:notify({container_unhealthy, get_id(Pid), NewF}),
            %% Restart: stop + the restart policy handles the rest
            try _ = erlkoenig_ct:stop_container(Pid)
            catch _:_ -> ok
            end,
            Check2#check{failures = 0};
        false ->
            logger:info("health check failed for ~p (~p/~p)",
                        [Pid, NewF, Max]),
            Check2
    end.

-spec get_id(pid()) -> binary().
get_id(Pid) ->
    try erlkoenig_ct:get_info(Pid) of
        #{id := Id} -> Id
    catch _:_ -> <<"unknown">>
    end.
