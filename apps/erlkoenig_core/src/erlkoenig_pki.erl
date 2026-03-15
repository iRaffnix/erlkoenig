%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

%%%-------------------------------------------------------------------
%% @doc Certificate chain validation and trust store.
%%
%% Manages trusted Root CA certificates and validates certificate
%% chains from .sig files against them. Configured via sys.config:
%%
%%   {signature, #{
%%       mode => on | warn | off,
%%       trust_roots => ["/etc/erlkoenig/ca/root.pem"],
%%       min_chain_depth => 2
%%   }}
%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_pki).

-behaviour(gen_server).

-include_lib("public_key/include/public_key.hrl").

%% API
-export([start_link/0, verify_chain/1, mode/0, reload/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, terminate/2]).

-record(state, {
    trust_roots = [] :: [public_key:der_encoded()],
    mode = off       :: on | warn | off,
    min_depth = 2    :: pos_integer()
}).

%%%===================================================================
%%% API
%%%===================================================================

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Verify a certificate chain against the trust store.
%%
%% CertChain: list of DER-encoded certificates, leaf first.
%% Returns ok if the chain is valid and chains to a trusted root.
-spec verify_chain([public_key:der_encoded()]) ->
    ok | {error, chain_too_short | expired | untrusted_root | term()}.
verify_chain(CertChain) ->
    gen_server:call(?MODULE, {verify_chain, CertChain}).

%% @doc Get current signature verification mode.
-spec mode() -> on | warn | off.
mode() ->
    gen_server:call(?MODULE, mode).

%% @doc Reload trust roots from disk.
-spec reload() -> ok | {error, term()}.
reload() ->
    gen_server:call(?MODULE, reload).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    Config = application:get_env(erlkoenig_core, signature, #{}),
    Mode = maps:get(mode, Config, off),
    MinDepth = maps:get(min_chain_depth, Config, 2),
    RootPaths = maps:get(trust_roots, Config, []),
    Roots = load_trust_roots(RootPaths),
    logger:info("[pki] mode=~p, trust_roots=~p, loaded=~p",
                [Mode, length(RootPaths), length(Roots)]),
    erlkoenig_audit:log(#{
        type => pki_loaded,
        subject => <<"pki">>,
        result => ok,
        details => #{roots_loaded => length(Roots), mode => Mode}
    }),
    {ok, #state{trust_roots = Roots, mode = Mode, min_depth = MinDepth}}.

handle_call(mode, _From, #state{mode = Mode} = State) ->
    {reply, Mode, State};

handle_call(reload, _From, State) ->
    Config = application:get_env(erlkoenig_core, signature, #{}),
    RootPaths = maps:get(trust_roots, Config, []),
    Roots = load_trust_roots(RootPaths),
    logger:info("[pki] reloaded ~p trust roots", [length(Roots)]),
    {reply, ok, State#state{trust_roots = Roots}};

handle_call({verify_chain, CertChain}, _From, #state{} = State) ->
    Result = do_verify_chain(CertChain, State),
    {reply, Result, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

%%%===================================================================
%%% Internal
%%%===================================================================

-spec load_trust_roots([string()]) -> [public_key:der_encoded()].
load_trust_roots(Paths) ->
    lists:flatmap(fun(Path) ->
        case file:read_file(Path) of
            {ok, PemBin} ->
                [Der || {'Certificate', Der, _} <- public_key:pem_decode(PemBin)];
            {error, Reason} ->
                logger:error("[pki] cannot read trust root ~s: ~p", [Path, Reason]),
                []
        end
    end, Paths).

-spec do_verify_chain([public_key:der_encoded()], #state{}) ->
    ok | {error, term()}.
do_verify_chain(CertChain, #state{trust_roots = Roots, min_depth = MinDepth}) ->
    %% Chain depth: leaf + intermediates + root >= MinDepth
    %% The chain from the .sig file does NOT include the root.
    %% So we need: length(CertChain) + 1 (for root) >= MinDepth
    case length(CertChain) + 1 >= MinDepth of
        false ->
            {error, chain_too_short};
        true ->
            validate_against_roots(CertChain, Roots)
    end.

-spec validate_against_roots([public_key:der_encoded()], [public_key:der_encoded()]) ->
    ok | {error, term()}.
validate_against_roots(_CertChain, []) ->
    {error, untrusted_root};
validate_against_roots(CertChain, [Root | RestRoots]) ->
    case try_validate(CertChain, Root) of
        ok -> ok;
        {error, _} -> validate_against_roots(CertChain, RestRoots)
    end.

-spec try_validate([public_key:der_encoded()], public_key:der_encoded()) ->
    ok | {error, term()}.
try_validate(CertChain, RootDer) ->
    %% Build the chain: leaf -> ... -> intermediate -> root
    %% pkix_path_validation expects: [Root, ..., Leaf] (root first)
    %% But the .sig chain is [Leaf, ..., Intermediate]
    FullChain = lists:reverse(CertChain) ++ [RootDer],
    %% Decode root for path validation
    RootCert = public_key:pkix_decode_cert(RootDer, otp),
    %% The path to validate is everything except the trust anchor (root)
    PathCerts = [public_key:pkix_decode_cert(D, otp) || D <- lists:reverse(CertChain)],
    case public_key:pkix_path_validation(RootCert, PathCerts, []) of
        {ok, _} ->
            %% Also check that all certs are not expired
            check_expiry(FullChain);
        {error, {bad_cert, Reason}} ->
            {error, Reason}
    end.

-spec check_expiry([public_key:der_encoded()]) -> ok | {error, expired}.
check_expiry([]) -> ok;
check_expiry([DerCert | Rest]) ->
    case public_key:pkix_is_issuer(DerCert, DerCert) of
        true  -> check_expiry(Rest); %% skip self-check for root
        false -> check_expiry(Rest)
    end.
%% Note: pkix_path_validation already checks validity periods.
%% This function is kept as a placeholder for additional expiry logic
%% (e.g., grace periods) in future phases.
