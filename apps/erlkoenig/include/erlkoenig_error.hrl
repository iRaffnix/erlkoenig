%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%
%% Helper macros for constructing structured errors with source
%% location baked in. See erlkoenig_error for the emission API.
%%

-ifndef(ERLKOENIG_ERROR_HRL).
-define(ERLKOENIG_ERROR_HRL, 1).

%% Build an error map with source = {module, function/arity, line}.
%% Use inside any function; ?MODULE / ?FUNCTION_NAME / ?FUNCTION_ARITY
%% / ?LINE are provided by the compiler.
-define(EK_ERROR(Type, Reason, Context, Data),
    erlkoenig_error:make(
        Type, Reason, Context, Data,
        #{source => #{module   => ?MODULE,
                      function => ?FUNCTION_NAME,
                      arity    => ?FUNCTION_ARITY,
                      line     => ?LINE}})).

%% Same, but with explicit severity.
-define(EK_ERROR_S(Severity, Type, Reason, Context, Data),
    erlkoenig_error:make(
        Type, Reason, Context, Data,
        #{severity => Severity,
          source   => #{module   => ?MODULE,
                        function => ?FUNCTION_NAME,
                        arity    => ?FUNCTION_ARITY,
                        line     => ?LINE}})).

-endif.
