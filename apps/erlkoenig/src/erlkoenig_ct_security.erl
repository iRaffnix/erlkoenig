%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%

-module(erlkoenig_ct_security).
-moduledoc """
Pre-spawn security gates and post-crash bookkeeping.

Three concerns live together here because they are the
security-policy boundary of `erlkoenig_ct':

  1. **Signature verification** (SPEC-EK-017).
     `maybe_verify_signature/1' is called from `creating(enter, _)'
     before the C runtime even spawns. Verifies the binary against
     its `.sig' + cert chain. Per-container `signature_required'
     promotes the effective mode to `enforce' regardless of the
     global PKI mode.

  2. **Admission + quarantine gate**.
     `admission_then_quarantine/2' is the combined gate: first a
     quarantine check (crashloop circuit breaker), then admission
     acquire. Quarantine remains fail-open for isolated test fixtures.
     Quarantine and admission are fail-closed in resource_protection
     mode `production' and fail-open only in development mode.

  3. **Post-mortem bookkeeping**.
     `safe_record_crash/1' feeds the quarantine counter on
     failure-state entry. `format_hash_prefix/1' is a tiny helper
     used by audit entries that display a binary hash prefix.

Left deliberately in `erlkoenig_ct': the state-callback entry
points (`creating/3', `failed/3') that call these — they
orchestrate which gate runs when.
""".

-include("erlkoenig_ct_state.hrl").

%% erlkoenig_sig:verify uses throw() internally — dialyzer can't
%% infer the success path.
-dialyzer({no_match, [maybe_verify_signature/1]}).

-export([
    %% Signature verification
    maybe_verify_signature/1,
    resolve_sig_path/1,
    %% Admission + quarantine gate
    resource_then_admission_then_quarantine/4,
    admission_then_quarantine/2,
    safe_resource_admit/2,
    confirm_resource_admission/1,
    release_resource_admission/1,
    safe_quarantine_check/1,
    safe_admission_acquire/1,
    admission_acquire_timeout_ms/0,
    admission_scope/1,
    release_admission_token/1,
    %% Post-mortem bookkeeping
    safe_record_crash/1,
    format_hash_prefix/1
]).

%% -- Resource admission + admission + quarantine gate --------------

-spec resource_then_admission_then_quarantine(binary(), map(),
                                              atom() | binary(), binary()) ->
    {ok, reference() | undefined}
  | {error, {resource_admission_denied, term()}}
  | {error, admission_timeout | admission_queue_full
            | admission_unavailable | quarantine_unavailable}
  | {error, {quarantined, binary(), integer()}}.
resource_then_admission_then_quarantine(ContainerId, Limits, Zone, BinaryPath) ->
    case safe_resource_admit(ContainerId, Limits) of
        ok ->
            case admission_then_quarantine(Zone, BinaryPath) of
                {ok, _} = Ok ->
                    Ok;
                {error, _} = Err ->
                    release_resource_admission(ContainerId),
                    Err
            end;
        {error, Reason} ->
            {error, {resource_admission_denied, Reason}}
    end.

-spec safe_resource_admit(binary(), map()) -> ok | {error, term()}.
safe_resource_admit(ContainerId, Limits) ->
    try erlkoenig_node_resources:admit(ContainerId, Limits)
    catch
        exit:{noproc, _} ->
            case erlkoenig_cgroup:production_mode() of
                true  -> {error, node_resources_unavailable};
                false -> ok
            end;
        exit:{timeout, _} ->
            {error, node_resources_unavailable}
    end.

-spec confirm_resource_admission(#ct_data{} | binary()) -> ok.
confirm_resource_admission(#ct_data{id = Id}) ->
    confirm_resource_admission(Id);
confirm_resource_admission(Id) when is_binary(Id) ->
    try erlkoenig_node_resources:confirm_running(Id)
    catch _:_ -> ok
    end.

-spec release_resource_admission(#ct_data{} | binary()) -> ok.
release_resource_admission(#ct_data{id = Id}) ->
    release_resource_admission(Id);
release_resource_admission(Id) when is_binary(Id) ->
    try erlkoenig_node_resources:release_commit(Id)
    catch _:_ -> ok
    end.

%% -- Admission + quarantine gate ---------------------------------

-spec admission_then_quarantine(atom() | binary(), binary()) ->
    {ok, reference() | undefined}
  | {error, admission_timeout | admission_queue_full
            | admission_unavailable | quarantine_unavailable}
  | {error, {quarantined, binary(), integer()}}.
admission_then_quarantine(Zone, BinaryPath) ->
    %% Quarantine check first — it's cheap, a hashmap lookup plus a
    %% hash-file call, and rejecting a quarantined binary early means
    %% we don't hold an admission token we'll just release anyway.
    case safe_quarantine_check(BinaryPath) of
        ok ->
            Scope = admission_scope(Zone),
            case safe_admission_acquire(Scope) of
                {ok, Token}  -> {ok, Token};
                {error, _} = E -> E
            end;
        {error, {quarantined, _, _}} = E -> E;
        {error, _} = E -> E
    end.

safe_quarantine_check(BinaryPath) ->
    try erlkoenig_quarantine:check(BinaryPath)
    catch
        %% Quarantine gen_server not running (isolated eunit contexts
        %% that don't need it). In production, missing quarantine is a
        %% hard safety failure because crashloop protection is part of
        %% the pre-spawn contract.
        exit:{noproc, _} ->
            case erlkoenig_cgroup:production_mode() of
                true  -> {error, quarantine_unavailable};
                false -> ok
            end;
        exit:{timeout, _} ->
            case erlkoenig_cgroup:production_mode() of
                true  -> {error, quarantine_unavailable};
                false -> ok
            end
    end.

safe_admission_acquire(Scope) ->
    try erlkoenig_admission:acquire(Scope, admission_acquire_timeout_ms()) of
        {ok, Token} -> {ok, Token};
        {error, timeout}    -> {error, admission_timeout};
        {error, queue_full} -> {error, admission_queue_full}
    catch
        %% Same rationale as quarantine: the admission gate is
        %% supposed to be there, but tests don't always start it. In
        %% production, missing admission is a hard safety failure.
        exit:{noproc, _} ->
            case erlkoenig_cgroup:production_mode() of
                true  -> {error, admission_unavailable};
                false -> {ok, undefined}
            end;
        exit:{timeout, _} -> {error, admission_timeout}
    end.

admission_acquire_timeout_ms() ->
    application:get_env(erlkoenig, admission_acquire_timeout_ms, 30_000).

admission_scope(undefined) -> host;
admission_scope(default)   -> host;
admission_scope(Zone) when is_atom(Zone) -> atom_to_binary(Zone, utf8);
admission_scope(Zone) when is_binary(Zone) -> Zone;
admission_scope(_) -> host.

-spec release_admission_token(#ct_data{}) -> ok.
release_admission_token(#ct_data{admission_token = undefined}) -> ok;
release_admission_token(#ct_data{admission_token = Token}) ->
    try erlkoenig_admission:release(Token)
    catch _:_ -> ok
    end.

-spec safe_record_crash(binary() | undefined) -> ok.
safe_record_crash(undefined) -> ok;
safe_record_crash(BinaryPath) ->
    try erlkoenig_quarantine:record_crash(BinaryPath)
    catch _:_ -> ok
    end.

-spec format_hash_prefix(binary()) -> binary().
format_hash_prefix(Hash) when is_binary(Hash), byte_size(Hash) >= 8 ->
    <<Prefix:8/binary, _/binary>> = Hash,
    Prefix;
format_hash_prefix(Hash) -> Hash.

%% -- Signature verification (SPEC-EK-017) -------------------------

-spec maybe_verify_signature(#ct_data{}) -> {ok, #ct_data{}} | {error, term()}.
maybe_verify_signature(Data) ->
    %% Per-container `signature_required: true' promotes the effective
    %% mode to `enforce' even if the global PKI mode is `off'.  This is
    %% the Glasbox side of the SPEC-EK-017 contract: the operator says
    %% "this workload must be signed" in the DSL, and the runtime
    %% treats that as a hard gate — regardless of cluster-wide setting.
    GlobalMode = erlkoenig_pki:mode(),
    EffectiveMode = case {GlobalMode, Data#ct_data.signature_required} of
        {off, true} -> enforce;
        _           -> GlobalMode
    end,
    case EffectiveMode of
        off ->
            {ok, Data};
        Mode ->
            SigPath = resolve_sig_path(Data),
            case erlkoenig_sig:verify(Data#ct_data.binary_path, SigPath) of
                {ok, Meta} ->
                    erlkoenig_audit:log(#{
                        type => binary_verify,
                        subject => Data#ct_data.id,
                        result => ok,
                        details => maps:without([chain], Meta)
                    }),
                    case erlkoenig_pki:verify_chain(maps:get(chain, Meta)) of
                        ok ->
                            erlkoenig_events:notify({signature_verified,
                                Data#ct_data.id, Data#ct_data.name, Meta}),
                            {ok, Data#ct_data{sig_verified = true, sig_meta = Meta}};
                        {error, ChainErr} when Mode =:= warn ->
                            logger:warning("[~s] chain verification failed: ~p (warn mode)",
                                          [Data#ct_data.id, ChainErr]),
                            erlkoenig_audit:log(#{
                                type => binary_verify,
                                subject => Data#ct_data.id,
                                result => {error, ChainErr},
                                details => #{mode => warn}
                            }),
                            {ok, Data};
                        {error, ChainErr} ->
                            erlkoenig_events:notify({signature_rejected,
                                Data#ct_data.id, Data#ct_data.name,
                                {chain_invalid, ChainErr}}),
                            erlkoenig_audit:log(#{
                                type => binary_reject,
                                subject => Data#ct_data.id,
                                result => {error, ChainErr},
                                details => #{binary => Data#ct_data.binary_path}
                            }),
                            {error, {chain_invalid, ChainErr}}
                    end;
                {error, Err} when Mode =:= warn ->
                    logger:warning("[~s] signature verification failed: ~p (warn mode)",
                                  [Data#ct_data.id, Err]),
                    erlkoenig_audit:log(#{
                        type => binary_verify,
                        subject => Data#ct_data.id,
                        result => {error, Err},
                        details => #{mode => warn}
                    }),
                    {ok, Data};
                {error, Err} ->
                    erlkoenig_events:notify({signature_rejected,
                        Data#ct_data.id, Data#ct_data.name, Err}),
                    erlkoenig_audit:log(#{
                        type => binary_reject,
                        subject => Data#ct_data.id,
                        result => {error, Err},
                        details => #{binary => Data#ct_data.binary_path}
                    }),
                    {error, Err}
            end
    end.

-spec resolve_sig_path(#ct_data{}) -> binary().
resolve_sig_path(#ct_data{sig_path = undefined, binary_path = Bin}) ->
    <<Bin/binary, ".sig">>;
resolve_sig_path(#ct_data{sig_path = Path}) ->
    Path.
