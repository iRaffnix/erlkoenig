%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_dns_filter).
-moduledoc """
Per-container DNS allowlist enforcement.

Implements the L7 half of SPEC-AS-009: a container that declares
`requires :"dns.allowlist", hosts: [...]` gets an allowlist
registered against its IPVLAN source IP. `erlkoenig_dns` consults
this filter before forwarding any external query; a lookup whose
name is not in the container's allowlist is answered with NXDOMAIN
and audit-logged.

The complementary L4 policy (container cannot reach any other
resolver than the zone gateway) stays in the operator-written
container nft block — see SPEC-AS-009 §3 "Operator vs. Platform
layers" and the `feedback_no_magic_inject` rule.

The matcher understands two pattern forms:

  * `<<"api.openai.com">>`  — exact match (case-insensitive, trailing
    dot tolerated)
  * `<<"*.example.com">>`   — wildcard, matches any non-empty label
    prefix (`a.example.com`, `a.b.example.com`; NOT the bare
    `example.com` — list both if needed)

Allowlists are compiled at registration time so the hot path
(`check/2`) is a single ETS lookup plus a short lists:any/2.

Reads go directly to the named ETS table (public). Writes
(register/unregister) route through the gen_server so the table
stays consistent under concurrent registrations.
""".

-behaviour(gen_server).

-export([start_link/0, stop/0,
         register_allowlist/2,
         unregister/1,
         check/2,
         compile_patterns/1]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2]).

-define(TAB, ?MODULE).

-type host_pattern() :: {exact, binary()} | {suffix, binary()}.
-export_type([host_pattern/0]).
%% Exposed for fuzzing.
-export([compile_one/1]).

%%%===================================================================
%%% API
%%%===================================================================

-spec start_link() -> gen_server:start_ret().
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-doc "Stop the filter (drops all registrations).".
-spec stop() -> ok.
stop() ->
    gen_server:stop(?MODULE).

-doc """
Register an allowlist for a container's source IP.

`Hosts` is a list of binaries accepted by `compile_patterns/1`.
Replaces any existing registration for the same IP.
""".
-spec register_allowlist(inet:ip4_address(), [binary()]) -> ok.
register_allowlist(Ip, Hosts) when is_tuple(Ip), is_list(Hosts) ->
    gen_server:call(?MODULE, {register, Ip, Hosts}).

-doc "Drop the allowlist registration for a container IP. Idempotent.".
-spec unregister(inet:ip4_address()) -> ok.
unregister(Ip) when is_tuple(Ip) ->
    gen_server:call(?MODULE, {unregister, Ip}).

-doc """
Check whether `Name` is allowed for a query from `Ip`.

Returns:

  * `no_filter` — no allowlist registered for this IP; DNS behaves
    as if the filter weren't there (forward as usual)
  * `allow` — name matches a registered pattern
  * `{deny, not_in_allowlist}` — allowlist exists and name is not in it

The hot path is a single ETS lookup plus a pattern walk; safe to
call from `erlkoenig_dns`'s UDP receive handler without contention.
""".
-spec check(inet:ip4_address(), binary()) ->
          no_filter | allow | {deny, not_in_allowlist}.
check(Ip, Name) when is_tuple(Ip), is_binary(Name) ->
    Normalised = normalise(Name),
    try
        case ets:lookup(?TAB, Ip) of
            [] ->
                no_filter;
            [{Ip, Patterns}] ->
                case matches_any(Normalised, Patterns) of
                    true  -> allow;
                    false -> {deny, not_in_allowlist}
                end
        end
    catch
        error:badarg ->
            %% Table missing → filter not started → fail open so a
            %% crashed filter does not break DNS for every container.
            no_filter
    end.

-doc """
Compile a user-facing host list into internal patterns.

Raw compiler — errors may appear in the result list as
`{error, invalid_host}`. Filtering of invalids happens at the
registration seam (`handle_call({register, ...})`) so tests can
assert the per-entry outcome.

Exported so the DSL (or tests) can pre-validate a list without
registering it.
""".
-spec compile_patterns([binary()]) -> [host_pattern() | {error, invalid_host}].
compile_patterns(Hosts) ->
    [compile_one(H) || H <- Hosts].

%% Drop `{error, invalid_host}' entries and log each one — called
%% right before ETS insert. Previously these errors flowed into the
%% ETS value as-is, and `matches_any/2`'s generic catch-all clause
%% silently treated them as non-matching patterns → operator writes
%% 5 hosts, 2 are typos, allowlist silently behaves as 3 patterns.
-spec filter_valid_patterns([host_pattern() | {error, invalid_host}], binary()) ->
    [host_pattern()].
filter_valid_patterns(Patterns, SourceLabel) ->
    lists:filtermap(fun
        ({error, invalid_host}) ->
            logger:warning(
                "[dns_filter] invalid host pattern dropped from ~s "
                "allowlist (entry has no effect)", [SourceLabel]),
            false;
        ({exact, _} = P) -> {true, P};
        ({suffix, _} = P) -> {true, P}
    end, Patterns).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    proc_lib:set_label(erlkoenig_dns_filter),
    _ = ets:new(?TAB, [named_table, public, {read_concurrency, true}]),
    %% Re-populate from running containers. This matters after a
    %% gen_server crash: the supervisor restarts us, ETS is fresh,
    %% but the running containers (with `requires :"dns.allowlist"`)
    %% never re-register themselves — that happens only at
    %% `running(enter)`. Walking the pg group of running containers
    %% and pulling their `dns_allowlist` closes the gap without
    %% leaking filter bypass during the crash window.
    Recovered = recover_from_running_containers(),
    case Recovered of
        0 ->
            ok;
        N ->
            logger:warning(
              "[dns_filter] recovered ~p allowlists from running "
              "containers after restart", [N])
    end,
    {ok, #{recovered => Recovered}}.

%% Best-effort walk of `erlkoenig_cts` process group. Each container's
%% info map carries the DSL-declared dns_allowlist (or undefined).
%% Returns the count of allowlists re-inserted into ETS.
-spec recover_from_running_containers() -> non_neg_integer().
recover_from_running_containers() ->
    Pids = try pg:get_members(erlkoenig_pg, erlkoenig_cts)
           catch _:_ -> []
           end,
    lists:foldl(
      fun(Pid, Acc) ->
          case recover_one(Pid) of
              ok -> Acc + 1;
              skip -> Acc
          end
      end, 0, Pids).

recover_one(Pid) ->
    case erlkoenig_ct:dns_filter_state(Pid) of
        {Ip, Hosts} when is_list(Hosts), Hosts =/= [] ->
            Label = iolist_to_binary(io_lib:format(
                "recovered-ip-~s", [inet:ntoa(Ip)])),
            Patterns = filter_valid_patterns(
                         compile_patterns(Hosts), Label),
            true = ets:insert(?TAB, {Ip, Patterns}),
            ok;
        _ ->
            skip
    end.

handle_call({register, Ip, Hosts}, _From, State) ->
    Label = iolist_to_binary(io_lib:format(
        "ip-~s", [inet:ntoa(Ip)])),
    Patterns = filter_valid_patterns(
                 compile_patterns(Hosts), Label),
    true = ets:insert(?TAB, {Ip, Patterns}),
    {reply, ok, State};

handle_call({unregister, Ip}, _From, State) ->
    true = ets:delete(?TAB, Ip),
    {reply, ok, State};

handle_call(_Req, _From, State) ->
    {reply, {error, unknown}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    %% Table is owned by this process and auto-deleted on exit.
    ok.

%%%===================================================================
%%% Internals
%%%===================================================================

%% Strip a single trailing dot + lowercase for case-insensitive
%% comparison. Done once per query in `check/2` and once per host
%% in `compile_one/1`.
-spec normalise(binary()) -> binary().
normalise(Name) ->
    %% DNS names are bytes, not UTF-8 — `string:lowercase` crashes
    %% with badarg on high-bit-set labels.  Do a byte-safe ASCII
    %% lowercase so malformed-but-technically-valid DNS names
    %% don't crash allowlist compilation.
    Lower = ascii_lowercase(Name),
    case Lower of
        <<>> -> <<>>;
        _ ->
            case binary:last(Lower) of
                $. -> binary:part(Lower, 0, byte_size(Lower) - 1);
                _  -> Lower
            end
    end.

-spec ascii_lowercase(binary()) -> binary().
ascii_lowercase(Bin) ->
    << <<(if C >= $A, C =< $Z -> C + 32; true -> C end)>> || <<C>> <= Bin >>.

-spec compile_one(binary()) -> host_pattern() | {error, invalid_host}.
compile_one(<<"*.", Rest/binary>>) when byte_size(Rest) > 0 ->
    {suffix, normalise(Rest)};
%% Any OTHER `*`-prefixed input (`"*"`, `"*."`, `"**.foo"`, `"*abc"`)
%% is a malformed wildcard. The only legal shape is `*.<non-empty>`,
%% handled by the clause above. Without this explicit rejection,
%% `"*."` falls through to the exact-match clause and gets stored
%% as `{exact, <<"*">>}` — a pattern that can never match a real DNS
%% query (star isn't a valid label character), so the operator's
%% intended wildcard becomes a silently dead entry in the allowlist.
%% The DSL-side regex in dsl/lib/erlkoenig/pod/builder.ex rejects
%% these, but this module is also callable programmatically and
%% defense-in-depth belongs at every layer (same Muster-9 class of
%% clause-ordering bugs we fixed in erlkoenig_nft_container and
%% erlkoenig_config.expand_nft_rule).
compile_one(<<$*, _/binary>>) ->
    {error, invalid_host};
compile_one(Host) when is_binary(Host), byte_size(Host) > 0 ->
    {exact, normalise(Host)};
compile_one(_) ->
    %% Empty binary or non-binary — never silently accept. Callers
    %% that produced this garbage should get a clean tagged error
    %% rather than a function_clause.
    {error, invalid_host}.

-spec matches_any(binary(), [host_pattern()]) -> boolean().
matches_any(_Name, []) -> false;
matches_any(Name, [{exact, Name} | _]) -> true;
matches_any(Name, [{suffix, Suffix} | Rest]) ->
    case has_dot_suffix(Name, Suffix) of
        true  -> true;
        false -> matches_any(Name, Rest)
    end;
matches_any(Name, [_ | Rest]) ->
    matches_any(Name, Rest).

%% True when `Name` ends in `.` + `Suffix` AND has at least one
%% non-empty label before the dot. Pattern `*.example.com` must
%% match `a.example.com` but NOT `example.com`.
-spec has_dot_suffix(binary(), binary()) -> boolean().
has_dot_suffix(Name, Suffix) ->
    NameLen   = byte_size(Name),
    SuffixLen = byte_size(Suffix),
    DottedLen = SuffixLen + 1,
    case NameLen > DottedLen of
        false -> false;
        true ->
            Prefix = binary:part(Name, 0, NameLen - DottedLen),
            Tail   = binary:part(Name, NameLen - DottedLen, DottedLen),
            Tail =:= <<".", Suffix/binary>> andalso byte_size(Prefix) > 0
    end.
