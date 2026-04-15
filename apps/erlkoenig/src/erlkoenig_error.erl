%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_error).
-moduledoc """
Structured error representation and event emission.

Replaces loose `{error, Reason}` tuples at error-reporting call sites
with a richer map carrying type, context, source location, severity,
and optional container id. Errors are emitted through the existing
`erlkoenig_events' bus, which routes them onto AMQP as
`error.<type>.<reason>' events (category + entity).

## Usage

Two forms: construct + emit, or build inline.

    %% Construct
    Err = erlkoenig_error:make(network, econnrefused, "connect to runtime",
                               #{ip => Ip, port => Port}),
    erlkoenig_error:emit(Err, ContainerId),

    %% Inline (with optional source-location macro, see include/erlkoenig_error.hrl)
    erlkoenig_error:emit(
      erlkoenig_error:make(config, parse_failed, "bad term file",
                           #{path => Path, reason => R})).

The `make/N' family always returns a map. It never throws — callers
can store, return, or emit the error. `emit/1,2' is fail-safe: if the
event bus is not running (bootstrap window or after a shutdown), the
error is logged and silently dropped rather than crashing the caller.

## Map shape

    #{type       => atom(),        %% network | config | runtime | io | security | ...
      reason     => atom(),        %% econnrefused | timeout | parse_failed | ...
      context    => binary(),      %% short human description
      data       => map(),         %% optional extra fields (ip, port, pid, ...)
      severity   => warn | error | critical,
      source     => #{module => atom(), line => pos_integer(),
                      function => atom(), arity => non_neg_integer()},
      ts         => integer(),     %% system_time(millisecond)
      container  => binary() | undefined}

All fields except `type'/`reason' have sensible defaults.
""".

-export([make/2, make/3, make/4, make/5,
         emit/1, emit/2,
         to_string/1,
         to_map/1,
         routing_key/1,
         payload/1]).

-export_type([error_map/0, severity/0]).

-type severity() :: warn | error | critical.
-type error_map() :: #{type     := atom(),
                       reason   := atom(),
                       context  := binary(),
                       data     := map(),
                       severity := severity(),
                       source   := map(),
                       ts       := integer(),
                       container := binary() | undefined}.

%%====================================================================
%% Constructors
%%====================================================================

-doc "Build an error map with only type + reason.".
-spec make(atom(), atom()) -> error_map().
make(Type, Reason) ->
    make(Type, Reason, <<>>, #{}, #{}).

-doc "Build an error map with type, reason, and context string.".
-spec make(atom(), atom(), iodata()) -> error_map().
make(Type, Reason, Context) ->
    make(Type, Reason, Context, #{}, #{}).

-doc "Build an error map with extra data.".
-spec make(atom(), atom(), iodata(), map()) -> error_map().
make(Type, Reason, Context, Data) ->
    make(Type, Reason, Context, Data, #{}).

-doc """
Full constructor.

Opts keys:
  severity  — warn | error | critical (default: error)
  source    — #{module, line, function, arity} (default: #{})
  container — binary container id (default: undefined)
""".
-spec make(atom(), atom(), iodata(), map(), map()) -> error_map().
make(Type, Reason, Context, Data, Opts)
  when is_atom(Type), is_atom(Reason), is_map(Data), is_map(Opts) ->
    #{type      => Type,
      reason    => Reason,
      context   => iolist_to_binary(Context),
      data      => Data,
      severity  => maps:get(severity, Opts, error),
      source    => maps:get(source, Opts, #{}),
      ts        => erlang:system_time(millisecond),
      container => maps:get(container, Opts, undefined)}.

%%====================================================================
%% Emission
%%====================================================================

-doc """
Emit an error onto the event bus.

Fail-safe: if the bus is not running, the error is logged via
`logger:warning' and dropped. Never crashes the caller.
""".
-spec emit(error_map()) -> ok.
emit(#{type := _, reason := _} = Err) ->
    case erlang:whereis(erlkoenig_events) of
        undefined ->
            logger:warning("erlkoenig_error: event bus down, dropped ~s",
                           [to_string(Err)]),
            ok;
        _Pid ->
            try
                erlkoenig_events:notify({error, Err})
            catch Class:Reason:Stack ->
                logger:warning("erlkoenig_error: notify failed ~p:~p at ~p~n"
                               "  error was: ~s",
                               [Class, Reason, Stack, to_string(Err)]),
                ok
            end
    end.

-doc "Emit an error attached to a specific container id.".
-spec emit(error_map(), binary() | undefined) -> ok.
emit(Err, ContainerId) ->
    emit(Err#{container => ContainerId}).

%%====================================================================
%% Formatting
%%====================================================================

-doc "Compact single-line representation for logs.".
-spec to_string(error_map()) -> iodata().
to_string(#{type := T, reason := R, context := C, data := D,
            severity := S, container := Ct}) ->
    CtStr = case Ct of
        undefined -> "";
        Bin       -> [" ct=", Bin]
    end,
    CtxStr = case C of
        <<>> -> "";
        _    -> [": ", C]
    end,
    DataStr = case map_size(D) of
        0 -> "";
        _ -> io_lib:format(" ~p", [D])
    end,
    io_lib:format("[~s/~s/~s]~s~s~s",
                  [S, T, R, CtStr, CtxStr, DataStr]).

-doc """
Convert to a map suitable for JSON (AMQP payload). Atoms are
stringified so Python can consume without Erlang-specific decoders.
""".
-spec to_map(error_map()) -> map().
to_map(#{type := T, reason := R, context := C, data := D,
         severity := S, source := Src, ts := Ts, container := Ct}) ->
    Base = #{<<"type">>     => atom_to_binary(T),
             <<"reason">>   => atom_to_binary(R),
             <<"context">>  => C,
             <<"data">>     => jsonable_map(D),
             <<"severity">> => atom_to_binary(S),
             <<"source">>   => jsonable_map(Src),
             <<"ts_ms">>    => Ts},
    case Ct of
        undefined -> Base;
        Bin       -> Base#{<<"container">> => Bin}
    end.

%%====================================================================
%% AMQP helpers (used by erlkoenig_amqp_codec)
%%====================================================================

-doc """
Routing key for an error: `error.<type>.<reason>'.

Routing keys follow the project schema `<category>.<entity>.<event>'
(see erlkoenig_amqp_codec moduledoc). `error' is the category,
`<type>' the entity (e.g. network, config), `<reason>' the event.
""".
-spec routing_key(error_map()) -> binary().
routing_key(#{type := T, reason := R}) ->
    iolist_to_binary([<<"error.">>,
                      atom_to_binary(T),
                      $.,
                      atom_to_binary(R)]).

-doc "JSON payload map for AMQP.".
-spec payload(error_map()) -> map().
payload(Err) ->
    to_map(Err).

%%====================================================================
%% Internal
%%====================================================================

%% Best-effort conversion: atoms → binaries, tuples → lists, nested
%% maps recursed. Anything exotic becomes its ~p iolist.
jsonable_map(M) when is_map(M) ->
    maps:fold(fun(K, V, Acc) ->
        Acc#{jsonable_key(K) => jsonable_value(V)}
    end, #{}, M);
jsonable_map(Other) ->
    jsonable_value(Other).

jsonable_key(K) when is_atom(K)   -> atom_to_binary(K);
jsonable_key(K) when is_binary(K) -> K;
jsonable_key(K)                   -> iolist_to_binary(io_lib:format("~p", [K])).

jsonable_value(V) when is_atom(V), V =/= undefined, V =/= true, V =/= false, V =/= null ->
    atom_to_binary(V);
jsonable_value(V) when is_atom(V)    -> V;
jsonable_value(V) when is_binary(V)  -> V;
jsonable_value(V) when is_integer(V) -> V;
jsonable_value(V) when is_float(V)   -> V;
jsonable_value(V) when is_boolean(V) -> V;
jsonable_value(V) when is_map(V)     -> jsonable_map(V);
jsonable_value(V) when is_list(V)    ->
    %% IP tuples often come as lists after binary_to_term etc.
    case io_lib:printable_unicode_list(V) of
        true  -> iolist_to_binary(V);
        false -> [jsonable_value(X) || X <- V]
    end;
jsonable_value({A, B, C, D}) when is_integer(A), is_integer(B),
                                   is_integer(C), is_integer(D) ->
    %% IPv4 → dotted string
    iolist_to_binary(io_lib:format("~b.~b.~b.~b", [A, B, C, D]));
jsonable_value(V) when is_tuple(V) ->
    [jsonable_value(X) || X <- tuple_to_list(V)];
jsonable_value(V) ->
    iolist_to_binary(io_lib:format("~p", [V])).
