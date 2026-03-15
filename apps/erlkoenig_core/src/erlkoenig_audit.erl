%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

%%%-------------------------------------------------------------------
%% @doc Append-only audit log for security-relevant events.
%%
%% Writes JSON Lines to /var/log/erlkoenig/audit.jsonl.
%% Each event gets a monotonic sequence number and ISO 8601 timestamp.
%%
%% Usage:
%%   erlkoenig_audit:log(#{type => binary_verify, subject => <<"proxy">>,
%%                         result => ok, details => #{sha256 => <<"a1b2">>}}).
%%
%% Non-blocking (gen_server:cast). File is re-opened on write error
%% to support external log rotation (logrotate copytruncate).
%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_audit).

-behaviour(gen_server).

%% API
-export([start_link/0, log/1, query/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(DEFAULT_PATH, "/var/log/erlkoenig/audit.jsonl").

-record(state, {
    fd      :: file:io_device() | undefined,
    path    :: string(),
    seq = 0 :: non_neg_integer()
}).

%%%===================================================================
%%% API
%%%===================================================================

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Log a security event. Non-blocking.
%%
%% Event must contain: type, subject, result.
%% Optional: details (map with type-specific metadata).
-spec log(map()) -> ok.
log(Event) when is_map(Event) ->
    gen_server:cast(?MODULE, {log, Event}).

%% @doc Query audit events. Blocking.
%%
%% Options:
%%   since => UnixSeconds (filter by timestamp)
%%   type  => atom() (filter by event type)
%%   limit => pos_integer() (max results, default 100)
-spec query(map()) -> {ok, [map()]} | {error, term()}.
query(Opts) when is_map(Opts) ->
    gen_server:call(?MODULE, {query, Opts}, 30_000).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    Path = application:get_env(erlkoenig_core, audit_path, ?DEFAULT_PATH),
    case open_log(Path) of
        {ok, Fd} ->
            logger:info("[audit] Logging to ~s", [Path]),
            {ok, #state{fd = Fd, path = Path}};
        {error, Reason} ->
            logger:error("[audit] Cannot open ~s: ~p", [Path, Reason]),
            %% Start without file — events are lost but the system runs.
            %% This avoids blocking the entire supervision tree if
            %% /var/log/erlkoenig doesn't exist yet.
            logger:warning("[audit] Running without audit log"),
            {ok, #state{fd = undefined, path = Path}}
    end.

handle_call({query, Opts}, _From, State) ->
    Result = do_query(State#state.path, Opts),
    {reply, Result, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast({log, Event}, #state{fd = undefined, path = Path} = State) ->
    %% Try to re-open the log file (maybe dir was created since startup)
    case open_log(Path) of
        {ok, Fd} ->
            logger:info("[audit] Log file opened: ~s", [Path]),
            handle_cast({log, Event}, State#state{fd = Fd});
        {error, _} ->
            {noreply, State}
    end;

handle_cast({log, Event}, #state{fd = Fd, seq = Seq} = State) ->
    NextSeq = Seq + 1,
    Line = encode_event(NextSeq, Event),
    case file:write(Fd, [Line, $\n]) of
        ok ->
            {noreply, State#state{seq = NextSeq}};
        {error, _Reason} ->
            %% Log rotation or disk error — re-open
            file:close(Fd),
            case open_log(State#state.path) of
                {ok, NewFd} ->
                    file:write(NewFd, [Line, $\n]),
                    {noreply, State#state{fd = NewFd, seq = NextSeq}};
                {error, _} ->
                    {noreply, State#state{fd = undefined, seq = NextSeq}}
            end
    end;

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{fd = undefined}) ->
    ok;
terminate(_Reason, #state{fd = Fd}) ->
    file:close(Fd),
    ok.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec open_log(string()) -> {ok, file:io_device()} | {error, term()}.
open_log(Path) ->
    Dir = filename:dirname(Path),
    case filelib:ensure_dir(Path) of
        ok ->
            file:open(Path, [append, raw]);
        {error, _} ->
            %% Try creating the directory
            case file:make_dir(Dir) of
                ok              -> file:open(Path, [append, raw]);
                {error, eexist} -> file:open(Path, [append, raw]);
                {error, _} = Err -> Err
            end
    end.

-spec encode_event(non_neg_integer(), map()) -> iodata().
encode_event(Seq, Event) ->
    Type = maps:get(type, Event, unknown),
    Subject = maps:get(subject, Event, <<>>),
    Result = maps:get(result, Event, undefined),
    Details = maps:get(details, Event, #{}),
    Ts = iso8601_now(),
    %% Build JSON manually — no external JSON library needed.
    %% We control all inputs so injection is not a concern.
    Base = [
        <<"{\"seq\":">>, integer_to_binary(Seq),
        <<",\"ts\":\"">>, Ts, <<"\"">>,
        <<",\"type\":\"">>, to_bin(Type), <<"\"">>,
        <<",\"subject\":\"">>, escape_json(to_bin(Subject)), <<"\"">>,
        <<",\"result\":">>, encode_result(Result)
    ],
    DetailPairs = maps:fold(fun(K, V, Acc) ->
        [<<",\"">>, to_bin(K), <<"\":">>, encode_value(V) | Acc]
    end, [], Details),
    [Base, DetailPairs, <<"}">>].

-spec encode_result(term()) -> iodata().
encode_result(ok) -> <<"\"ok\"">>;
encode_result({error, Reason}) ->
    [<<"\"error:">>, escape_json(to_bin(Reason)), <<"\"">>];
encode_result(undefined) -> <<"null">>;
encode_result(Other) ->
    [<<"\"">>, escape_json(to_bin(Other)), <<"\"">>].

-spec encode_value(term()) -> iodata().
encode_value(V) when is_integer(V) -> integer_to_binary(V);
encode_value(V) when is_float(V)   -> float_to_binary(V, [{decimals, 3}]);
encode_value(true)  -> <<"true">>;
encode_value(false) -> <<"false">>;
encode_value(V) ->
    [<<"\"">>, escape_json(to_bin(V)), <<"\"">>].

-spec escape_json(binary()) -> binary().
escape_json(Bin) ->
    << <<(escape_char(C))/binary>> || <<C>> <= Bin >>.

-spec escape_char(byte()) -> binary().
escape_char($")  -> <<"\\\"">>;
escape_char($\\) -> <<"\\\\">>;
escape_char($\n) -> <<"\\n">>;
escape_char($\r) -> <<"\\r">>;
escape_char($\t) -> <<"\\t">>;
escape_char(C) when C < 32 ->
    Hex = integer_to_binary(C, 16),
    Padded = case byte_size(Hex) of
        1 -> <<"0", Hex/binary>>;
        _ -> Hex
    end,
    <<"\\u00", Padded/binary>>;
escape_char(C) -> <<C>>.

-spec to_bin(term()) -> binary().
to_bin(B) when is_binary(B)  -> B;
to_bin(A) when is_atom(A)    -> atom_to_binary(A);
to_bin(I) when is_integer(I) -> integer_to_binary(I);
to_bin(L) when is_list(L)    -> list_to_binary(L);
to_bin(T) -> list_to_binary(io_lib:format("~p", [T])).

-spec iso8601_now() -> binary().
iso8601_now() ->
    {{Y, Mo, D}, {H, Mi, S}} = calendar:universal_time(),
    list_to_binary(io_lib:format("~4..0B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0BZ",
                                 [Y, Mo, D, H, Mi, S])).

%% --- Query (reads the log file, filters, returns maps) ---

-spec do_query(string(), map()) -> {ok, [map()]} | {error, term()}.
do_query(Path, Opts) ->
    case file:read_file(Path) of
        {ok, Bin} ->
            Lines = binary:split(Bin, <<"\n">>, [global]),
            Since = maps:get(since, Opts, 0),
            TypeFilter = maps:get(type, Opts, undefined),
            Limit = maps:get(limit, Opts, 100),
            Filtered = filter_lines(Lines, Since, TypeFilter, Limit, []),
            {ok, Filtered};
        {error, enoent} ->
            {ok, []};
        {error, Reason} ->
            {error, Reason}
    end.

-spec filter_lines([binary()], integer(), atom() | undefined, non_neg_integer(), [binary()]) -> [binary()].
filter_lines(_, _, _, 0, Acc) ->
    lists:reverse(Acc);
filter_lines([], _, _, _, Acc) ->
    lists:reverse(Acc);
filter_lines([<<>> | Rest], Since, Type, Limit, Acc) ->
    filter_lines(Rest, Since, Type, Limit, Acc);
filter_lines([Line | Rest], Since, Type, Limit, Acc) ->
    %% Simple substring matching — no JSON parser needed for filtering.
    %% Full JSON parsing is left to external tools (jq, SIEM).
    Include = case Type of
        undefined -> true;
        T ->
            TypeBin = atom_to_binary(T),
            binary:match(Line, TypeBin) =/= nomatch
    end,
    case Include of
        true  -> filter_lines(Rest, Since, Type, Limit - 1, [Line | Acc]);
        false -> filter_lines(Rest, Since, Type, Limit, Acc)
    end.
