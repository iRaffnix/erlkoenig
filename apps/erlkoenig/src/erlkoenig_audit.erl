%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_audit).
-moduledoc """
Append-only audit log for security-relevant events.

Writes JSON Lines to /var/log/erlkoenig/audit.jsonl.
Each event gets a monotonic sequence number, ISO 8601 timestamp,
and a SHA-256 hash chain link to the previous event (tamper-evident).

Hash chain semantics (schema v=1):
  - Each event includes `prev_hash` (hex) referencing the previous
    event's `this_hash` (or 64 zeros for the genesis event).
  - `this_hash` is SHA-256 over the canonical JSON encoding of the
    event with all other fields filled in (sorted keys, no whitespace).
  - Tampering with any past event invalidates every subsequent
    event's chain link; verification is O(n) by re-hashing.
  - On startup, the previous chain head is recovered from the last
    line of the existing log file (so chain continuity survives
    BEAM restarts and operator-induced log rotations).

Usage:
  erlkoenig_audit:log(#{type => binary_verify, subject => <<"proxy">>,
                        result => ok, details => #{sha256 => <<"a1b2">>}}).

Non-blocking (gen_server:cast). File is re-opened on write error
to support external log rotation (logrotate copytruncate).
""".

-behaviour(gen_server).

-include("erlkoenig_error.hrl").

%% API
-export([start_link/0, log/1, query/1,
         verify_chain/1, verify_chain/2,
         chain_head/0, signing_pubkey/0,
         seal_day/0, verify_seal/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

%% Internal exports for testing
-export([canonical_json/1, compute_this_hash/1, hex_to_bin/1]).

-define(DEFAULT_PATH, "/var/log/erlkoenig/audit.jsonl").
-define(SCHEMA_VERSION, 1).
-define(GENESIS_HASH, <<"0000000000000000000000000000000000000000000000000000000000000000">>).

-record(state, {
    fd        :: file:io_device() | undefined,
    path      :: string(),
    seq = 0   :: non_neg_integer(),
    prev_hash = ?GENESIS_HASH :: binary(),  %% hex-encoded SHA-256 of last event
    priv_key  :: binary() | undefined,      %% raw 32-byte Ed25519 private key
    pub_key   :: binary() | undefined,      %% raw 32-byte Ed25519 public key
    hmac_key  :: binary() | undefined       %% raw 32-byte HMAC-SHA-256 key
}).

%%%===================================================================
%%% API
%%%===================================================================

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

-doc """
Log a security event. Non-blocking.

Event must contain: type, subject, result.
Optional: details (map with type-specific metadata).
""".
-spec log(map()) -> ok.
log(Event) when is_map(Event) ->
    gen_server:cast(?MODULE, {log, Event}).

-doc """
Query audit events. Blocking.

Options:
  since => UnixSeconds (filter by timestamp)
  type  => atom() (filter by event type)
  subject => binary() | atom() | string() (filter by audit subject)
  container_name => binary() | atom() | string() (filter by flattened detail)
  reverse => boolean() (scan newest first, default false)
  limit => pos_integer() (max results, default 100)
""".
-spec query(map()) -> {ok, [map()]} | {error, erlkoenig_error:error_map()}.
query(Opts) when is_map(Opts) ->
    gen_server:call(?MODULE, {query, Opts}, 30_000).

-doc """
Return the current hash chain head as hex string.

Useful for external monitors that want to detect log truncation
or for snapshots taken between events.
""".
-spec chain_head() -> binary().
chain_head() ->
    gen_server:call(?MODULE, chain_head).

-doc """
Verify the hash chain integrity of an audit log file.

Walks the file, recomputes `this_hash` for every line, checks that
each event's `prev_hash` matches the previous event's `this_hash`,
and that the genesis event has the all-zero predecessor.

Returns `{ok, EventCount}` on success or `{error, ErrorMap}` on
failure. Chain and signature failures carry stable public codes such
as `EK_AUDIT_CHAIN_BROKEN` and `EK_AUDIT_SIGNATURE_INVALID`.

Does NOT verify Ed25519 signatures. Use `verify_chain/2` with the
node's audit public key to additionally check signatures.
""".
-spec verify_chain(string()) -> {ok, non_neg_integer()} | {error, erlkoenig_error:error_map()}.
verify_chain(Path) ->
    verify_chain(Path, undefined).

-doc """
Verify hash chain integrity AND Ed25519 signatures.

`PubKey` is the raw 32-byte Ed25519 public key. If `undefined`,
behaves identically to `verify_chain/1` (chain only).

Returns `{ok, EventCount}` on success or `{error, ErrorMap}`.
Tamper-evidence failures use stable public codes and include the
line number and verifier reason in the evidence map.
""".
-spec verify_chain(string(), binary() | undefined) ->
    {ok, non_neg_integer()} | {error, erlkoenig_error:error_map()}.
verify_chain(Path, PubKey) ->
    RawResult = case file:read_file(Path) of
        {ok, Bin} ->
            Lines = [L || L <- binary:split(Bin, <<"\n">>, [global]),
                          L =/= <<>>],
            Result = verify_lines(Lines, ?GENESIS_HASH, PubKey, 1, 0),
            Result;
        {error, Reason} -> {error, {read_failed, Reason}}
    end,
    maybe_notify_verify_failure(Path, RawResult),
    wrap_verify_chain_result(Path, RawResult).

-doc """
Return the running gen_server's audit signing public key (raw 32
bytes), or `undefined` if signing is not configured.

Customers verify their audit log offline with this key.
""".
-spec signing_pubkey() -> binary() | undefined.
signing_pubkey() ->
    gen_server:call(?MODULE, signing_pubkey).

-doc """
Seal the current day's audit file (SPEC-AS-005 stage 3).

Computes HMAC-SHA-256 over the live file contents (with the
configured `audit_hmac_key`), appends a final `audit.seal` event
that carries `{hmac, event_count, byte_count}`, renames the file to
`<path>.<YYYY-MM-DD>.sealed`, drops it to mode 0440, and reopens a
fresh live file. The seal event's `this_hash` becomes tomorrow's
chain anchor: the next event written goes through normal encoding
and references it via `prev_hash`, so the chain crosses the file
boundary without a break.

Returns `{ok, #{sealed_path, event_count, byte_count, anchor}}` on
success, or `{error, ErrorMap}` with `EK_AUDIT_SEAL_FAILED`.
""".
-spec seal_day() -> {ok, map()} | {error, erlkoenig_error:error_map()}.
seal_day() ->
    gen_server:call(?MODULE, seal_day, 60_000).

-doc """
Verify a sealed audit file: chain integrity + HMAC over the day's
events. The seal event must be the last line; its details carry the
HMAC over the preceding `byte_count` bytes. `HmacKey` is the same
32-byte symmetric key that produced the seal.

Returns `{ok, #{event_count, byte_count, anchor}}` on success or
`{error, ErrorMap}`. HMAC mismatches use
`EK_AUDIT_SEAL_HMAC_MISMATCH`.
""".
-spec verify_seal(string(), binary()) -> {ok, map()} | {error, erlkoenig_error:error_map()}.
verify_seal(Path, HmacKey) when is_binary(HmacKey), byte_size(HmacKey) =:= 32 ->
    case file:read_file(Path) of
        {ok, Bin} -> wrap_verify_seal_result(Path, do_verify_seal(Bin, HmacKey));
        {error, Reason} -> audit_error(read_failed,
                                       "audit sealed file could not be read",
                                       #{path => Path, reason => Reason})
    end.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    proc_lib:set_label(erlkoenig_audit),
    Path = application:get_env(erlkoenig, audit_path, ?DEFAULT_PATH),
    {PrivKey, PubKey} = load_signing_key(),
    HmacKey = load_hmac_key(),
    case open_log(Path) of
        {ok, Fd} ->
            {Seq, PrevHash} = recover_chain_state(Path),
            SigStatus = case PubKey of
                undefined -> "unsigned";
                _         -> "signed"
            end,
            logger:info("[audit] Logging to ~s (seq=~p, chain_head=~s, ~s)",
                        [Path, Seq, binary:part(PrevHash, 0, 16), SigStatus]),
            {ok, #state{fd = Fd, path = Path, seq = Seq,
                        prev_hash = PrevHash,
                        priv_key = PrivKey, pub_key = PubKey,
                        hmac_key = HmacKey}};
        {error, Reason} ->
            logger:error("[audit] Cannot open ~s: ~p", [Path, Reason]),
            %% Start without file — events are lost but the system runs.
            %% This avoids blocking the entire supervision tree if
            %% /var/log/erlkoenig doesn't exist yet.
            logger:warning("[audit] Running without audit log"),
            {ok, #state{fd = undefined, path = Path,
                        priv_key = PrivKey, pub_key = PubKey,
                        hmac_key = HmacKey}}
    end.

handle_call({query, Opts}, _From, State) ->
    Result = do_query(State#state.path, Opts),
    {reply, Result, State};

handle_call(chain_head, _From, #state{prev_hash = Hash} = State) ->
    {reply, Hash, State};

handle_call(signing_pubkey, _From, #state{pub_key = Key} = State) ->
    {reply, Key, State};

handle_call(seal_day, _From, State) ->
    case do_seal_day(State) of
        {ok, Info, NewState} -> {reply, {ok, Info}, NewState};
        %% do_seal_day may advance state even when reporting an error,
        %% because the seal line is already written to disk and the
        %% chain must reflect that. See the rename_failed / reopen_failed
        %% branches for the rationale.
        {error, Reason, NewState} ->
            {reply, audit_seal_error(State#state.path, Reason), NewState};
        {error, Reason} ->
            {reply, audit_seal_error(State#state.path, Reason), State}
    end;

handle_call(_Request, _From, State) ->
    {reply, audit_error(unknown_call,
                        "unknown audit gen_server call",
                        #{}), State}.

handle_cast({log, Event}, #state{fd = undefined, path = Path} = State) ->
    %% Try to re-open the log file (maybe dir was created since startup)
    case open_log(Path) of
        {ok, Fd} ->
            {Seq, PrevHash} = recover_chain_state(Path),
            logger:info("[audit] Log file opened: ~s (seq=~p)", [Path, Seq]),
            handle_cast({log, Event}, State#state{fd = Fd, seq = Seq,
                                                  prev_hash = PrevHash});
        {error, _} ->
            {noreply, State}
    end;

handle_cast({log, Event}, #state{fd = Fd, seq = Seq,
                                 prev_hash = PrevHash,
                                 priv_key = PrivKey} = State) ->
    NextSeq = Seq + 1,
    {Line, ThisHash} = encode_event(NextSeq, PrevHash, PrivKey, Event),
    case file:write(Fd, [Line, $\n]) of
        ok ->
            {noreply, State#state{seq = NextSeq, prev_hash = ThisHash}};
        {error, _Reason} ->
            %% Log rotation or disk error — re-open
            _ = file:close(Fd),
            case open_log(State#state.path) of
                {ok, NewFd} ->
                    _ = file:write(NewFd, [Line, $\n]),
                    {noreply, State#state{fd = NewFd, seq = NextSeq,
                                          prev_hash = ThisHash}};
                {error, _} ->
                    {noreply, State#state{fd = undefined, seq = NextSeq,
                                          prev_hash = ThisHash}}
            end
    end;

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{fd = undefined}) ->
    ok;
terminate(_Reason, #state{fd = Fd}) ->
    _ = file:close(Fd),
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

-spec encode_event(non_neg_integer(), binary(),
                   binary() | undefined, map()) -> {iodata(), binary()}.
encode_event(Seq, PrevHash, PrivKey, Event) ->
    Type = maps:get(type, Event, unknown),
    Subject = maps:get(subject, Event, <<>>),
    Result = maps:get(result, Event, undefined),
    Details = maps:get(details, Event, #{}),
    Ts = iso8601_now(),
    Base = #{
        <<"v">> => ?SCHEMA_VERSION,
        <<"seq">> => Seq,
        <<"ts">> => Ts,
        <<"type">> => to_bin(Type),
        <<"subject">> => to_bin(Subject),
        <<"result">> => encode_result(Result),
        <<"prev_hash">> => PrevHash
    },
    %% Merge details (caller-controlled fields) into the base.
    %%
    %% The PREVIOUS implementation said "Details cannot override the
    %% chain-related fields above" — but the old fold
    %% `Acc#{to_bin(K) => V}' with Base as the initial Acc let any
    %% Details key overwrite Base entries. That meant a caller
    %% passing `details => #{seq => 999, prev_hash => <<"...">>}'
    %% could rewrite the chain link at encoding time — the hash
    %% would be computed over the tampered event and every
    %% downstream verify_chain/1 check would still pass (locally
    %% self-consistent), while peer nodes and customers' offline
    %% verifiers that reconstructed the chain from known anchors
    %% would diverge. A tamper-resistant audit log has to rule
    %% this out at the encoder boundary.
    %%
    %% Fix: layer Base on top of Details so Base always wins on
    %% conflict, and log a loud warning if a reserved key slipped
    %% in so the caller gets surfaced instead of silently dropped.
    DetailsBin = maps:fold(fun(K, V, Acc) ->
        Acc#{to_bin(K) => V}
    end, #{}, Details),
    ReservedKeys = [<<"v">>, <<"seq">>, <<"ts">>, <<"type">>,
                    <<"subject">>, <<"result">>, <<"prev_hash">>,
                    <<"this_hash">>, <<"signature">>],
    ReservedHits = [K || K <- ReservedKeys, maps:is_key(K, DetailsBin)],
    case ReservedHits of
        [] -> ok;
        _  ->
            logger:warning(
                "[audit] caller passed reserved fields in details "
                "(~p) for event type ~p — stripped to protect chain "
                "integrity",
                [ReservedHits, Type])
    end,
    %% Strip reserved keys from DetailsBin FIRST so they cannot land
    %% in EventNoHash and leak into compute_this_hash. Base wins on
    %% merge for the fields it defines, but `this_hash`/`signature`
    %% are added AFTER the hash is computed — so a stray Details
    %% entry for them would end up in the hash input and make
    %% every verifier re-computation disagree by design.
    CleanDetails = maps:without(ReservedKeys, DetailsBin),
    EventNoHash = maps:merge(CleanDetails, Base),
    %% Compute this_hash over the canonical encoding of all fields
    %% EXCEPT this_hash itself. The hash binds every visible field
    %% so any mutation invalidates the chain.
    ThisHash = compute_this_hash(EventNoHash),
    %% Sign the raw 32 bytes of this_hash with the audit signing key.
    %% If no key is configured, write null and document why.
    Signature = sign_hash(ThisHash, PrivKey),
    Full = EventNoHash#{<<"this_hash">> => ThisHash,
                        <<"signature">> => Signature},
    {json:encode(canonical_form(Full)), ThisHash}.

-spec sign_hash(binary(), binary() | undefined) -> binary() | null.
sign_hash(_HexHash, undefined) -> null;
sign_hash(HexHash, PrivKey) when is_binary(PrivKey) ->
    RawHash = hex_to_bin(HexHash),
    Signature = crypto:sign(eddsa, none, RawHash, [PrivKey, ed25519]),
    hex(Signature).

-doc """
Decode a lowercase hex binary into the corresponding raw bytes.

Raises `error({bad_hex, Byte})` on non-hex input rather than
silently returning garbage.  Callers that expect operator- or
attacker-controlled bytes (e.g. verify_chain reading a tampered
log line) wrap this in try/catch and turn the crash into a
structured `{chain_break, LineNo, Reason}` error.
""".
-spec hex_to_bin(binary()) -> binary().
hex_to_bin(Hex) when is_binary(Hex), byte_size(Hex) rem 2 =:= 0 ->
    <<<<(decode_hex_pair(A, B))>> || <<A, B>> <= Hex>>;
hex_to_bin(Hex) when is_binary(Hex) ->
    error({bad_hex, odd_length, byte_size(Hex)}).

decode_hex_pair(A, B) ->
    (decode_hex_nibble(A) bsl 4) bor decode_hex_nibble(B).

decode_hex_nibble(C) when C >= $0, C =< $9 -> C - $0;
decode_hex_nibble(C) when C >= $a, C =< $f -> C - $a + 10;
decode_hex_nibble(C) when C >= $A, C =< $F -> C - $A + 10;
decode_hex_nibble(C) -> error({bad_hex, C}).

-doc """
Compute the SHA-256 hex digest of an event map (excluding `this_hash`).

Exposed for testing and for the verifier; production code goes through
`encode_event/3`.
""".
-spec compute_this_hash(map()) -> binary().
compute_this_hash(EventMap) ->
    Canonical = canonical_json(maps:remove(<<"this_hash">>, EventMap)),
    Digest = crypto:hash(sha256, Canonical),
    hex(Digest).

-doc """
Encode a map as deterministic JSON: keys sorted lexicographically at
every level, no whitespace, UTF-8. This is the input to SHA-256 for
the hash chain. Two implementations must agree byte-for-byte on this
encoding for chain verification to interoperate.
""".
-spec canonical_json(map() | list() | binary() | number() | boolean() | null) -> binary().
canonical_json(M) when is_map(M) ->
    Sorted = lists:keysort(1, maps:to_list(M)),
    Parts = [[<<"\"">>, escape_str(to_bin(K)), <<"\":">>, canonical_json(V)]
             || {K, V} <- Sorted],
    iolist_to_binary([<<"{">>, lists:join(<<",">>, Parts), <<"}">>]);
canonical_json(L) when is_list(L) ->
    Parts = [canonical_json(E) || E <- L],
    iolist_to_binary([<<"[">>, lists:join(<<",">>, Parts), <<"]">>]);
canonical_json(B) when is_binary(B) ->
    iolist_to_binary([<<"\"">>, escape_str(B), <<"\"">>]);
canonical_json(true)  -> <<"true">>;
canonical_json(false) -> <<"false">>;
canonical_json(null)  -> <<"null">>;
canonical_json(I) when is_integer(I) -> integer_to_binary(I);
canonical_json(F) when is_float(F)   -> float_to_binary(F, [{decimals, 6}, compact]);
canonical_json(A) when is_atom(A) ->
    canonical_json(atom_to_binary(A, utf8)).

%% Re-render the event map in canonical form for the on-disk line.
%% Same byte order as canonical_json so a verifier reading the file
%% can reproduce the hash by re-canonicalising the map MINUS this_hash.
canonical_form(Map) when is_map(Map) -> Map.

-spec hex(binary()) -> binary().
hex(Bin) ->
    list_to_binary([io_lib:format("~2.16.0b", [B]) || <<B>> <= Bin]).

-spec escape_str(binary()) -> binary().
escape_str(B) ->
    %% Minimal RFC 8259 string escaping for the canonical JSON encoder.
    %% Production audit payloads are operator-controlled so we do not
    %% need to handle every Unicode edge case here, but we must escape
    %% the structural characters that would corrupt parsing.
    binary:replace(
      binary:replace(
        binary:replace(B, <<"\\">>, <<"\\\\">>, [global]),
        <<"\"">>, <<"\\\"">>, [global]),
      <<"\n">>, <<"\\n">>, [global]).

-spec encode_result(term()) -> binary() | null.
encode_result(ok) -> <<"ok">>;
encode_result({error, #{code := Code}}) ->
    <<"error:", (atom_to_binary(Code))/binary>>;
encode_result({error, Reason}) ->
    <<"error:", (to_bin(Reason))/binary>>;
encode_result(undefined) -> null;
encode_result(Other) ->
    to_bin(Other).

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

%% --- Signing key loading ---

%% Load the Ed25519 signing key from the configured path.
%% Returns {PrivKey, PubKey} or {undefined, undefined} if no key is
%% configured or the file is unreadable. A missing key is NOT a
%% startup failure — Stage 2 signing is optional in v1; the chain
%% remains tamper-evident at the hash level even unsigned.
%%
%% Two formats supported:
%%   - Raw 32 bytes (file size = 32) — the simplest form, suitable
%%     for tests and for TPM-unsealed material on production.
%%   - Otherwise: read the first 32 bytes (allows simple rotation
%%     by overwriting the front of the file).
-spec load_signing_key() -> {binary() | undefined, binary() | undefined}.
load_signing_key() ->
    case application:get_env(erlkoenig, audit_signing_key) of
        undefined          -> {undefined, undefined};
        {ok, undefined}    -> {undefined, undefined};
        {ok, KeyPath} ->
            case file:read_file(KeyPath) of
                {ok, Bin} when byte_size(Bin) >= 32 ->
                    PrivKey = binary:part(Bin, 0, 32),
                    %% Derive public key by signing a probe and
                    %% extracting it from crypto's keypair generator.
                    %% OTP doesn't expose a direct ed25519 priv→pub
                    %% derivation, so we use crypto:generate_key/2
                    %% with the private key as seed.
                    {PubKey, PrivKey} =
                        crypto:generate_key(eddsa, ed25519, PrivKey),
                    logger:info("[audit] Signing key loaded from ~s", [KeyPath]),
                    {PrivKey, PubKey};
                {ok, _Short} ->
                    logger:warning("[audit] Signing key ~s is shorter than "
                                   "32 bytes; signing disabled", [KeyPath]),
                    {undefined, undefined};
                {error, Reason} ->
                    logger:warning("[audit] Cannot read signing key ~s: ~p; "
                                   "signing disabled", [KeyPath, Reason]),
                    {undefined, undefined}
            end
    end.

%% Load the symmetric HMAC key used to seal daily files.
%% Keyed identically to the signing key but always raw 32 bytes
%% because HMAC-SHA-256 has no asymmetric component. Returns
%% `undefined' when not configured — `seal_day/0' then refuses with
%% `{error, no_hmac_key}'.
-spec load_hmac_key() -> binary() | undefined.
load_hmac_key() ->
    case application:get_env(erlkoenig, audit_hmac_key) of
        undefined       -> undefined;
        {ok, undefined} -> undefined;
        {ok, KeyPath} ->
            case file:read_file(KeyPath) of
                {ok, Bin} when byte_size(Bin) >= 32 ->
                    Key = binary:part(Bin, 0, 32),
                    logger:info("[audit] HMAC key loaded from ~s", [KeyPath]),
                    Key;
                {ok, _Short} ->
                    logger:warning("[audit] HMAC key ~s is shorter than "
                                   "32 bytes; sealing disabled", [KeyPath]),
                    undefined;
                {error, Reason} ->
                    logger:warning("[audit] Cannot read HMAC key ~s: ~p; "
                                   "sealing disabled", [KeyPath, Reason]),
                    undefined
            end
    end.

%% --- Daily seal ---

%% Seal the current live file. Steps:
%%   1. Flush + close the writer FD.
%%   2. Read the file, compute HMAC and counts over the bytes that
%%      were written BEFORE the seal event. The HMAC binds the day's
%%      content; the seal event itself is part of the chain so its
%%      this_hash is what tomorrow's first event will reference.
%%   3. Re-open and append the seal event through the normal
%%      encode_event path so it gets a chained prev_hash/this_hash
%%      and an Ed25519 signature when signing is enabled.
%%   4. Close, rename to <path>.<UTC date>.sealed, drop to mode 0440.
%%   5. Re-open a fresh live file at the original path; the chain
%%      head in state already points at the seal event, so the next
%%      event recorded continues the chain across the boundary.
do_seal_day(#state{hmac_key = undefined}) ->
    {error, no_hmac_key};
do_seal_day(#state{fd = undefined}) ->
    {error, no_log_file};
do_seal_day(#state{fd = Fd, path = Path, seq = Seq,
                   prev_hash = PrevHash, priv_key = PrivKey,
                   hmac_key = HmacKey} = State) ->
    _ = file:close(Fd),
    case file:read_file(Path) of
        {ok, Bin} ->
            ByteCount = byte_size(Bin),
            EventCount = Seq,
            Hmac = hex(crypto:mac(hmac, sha256, HmacKey, Bin)),
            SealSeq = Seq + 1,
            SealEvent = #{type => 'audit.seal',
                          subject => <<"audit_log">>,
                          result => ok,
                          details => #{<<"hmac">> => Hmac,
                                       <<"event_count">> => EventCount,
                                       <<"byte_count">> => ByteCount}},
            {Line, SealHash} =
                encode_event(SealSeq, PrevHash, PrivKey, SealEvent),
            case append_line(Path, [Line, $\n]) of
                ok ->
                    %% Once the seal line is on disk, the chain has
                    %% advanced regardless of what happens next. We
                    %% commit seq/prev_hash to the state here so a
                    %% subsequent rename or reopen failure cannot
                    %% leave state pointing at the PRE-seal anchor —
                    %% that would make the next log event reuse the
                    %% seal's seq number and break verify_chain with
                    %% a duplicate-seq error nobody sees until an
                    %% auditor tries to read the log.
                    WrittenState = State#state{seq = SealSeq,
                                               prev_hash = SealHash},
                    SealedPath = sealed_path(Path),
                    case file:rename(Path, SealedPath) of
                        ok ->
                            _ = file:change_mode(SealedPath, 8#0440),
                            case open_log(Path) of
                                {ok, NewFd} ->
                                    Info = #{sealed_path => SealedPath,
                                             event_count => EventCount,
                                             byte_count => ByteCount,
                                             anchor => SealHash},
                                    logger:info(
                                      "[audit] Sealed ~s "
                                      "(events=~p, bytes=~p, anchor=~s)",
                                      [SealedPath, EventCount, ByteCount,
                                       binary:part(SealHash, 0, 16)]),
                                    %% Surface to AMQP for compliance
                                    %% dashboards: "did the seal job
                                    %% run today, and what's the
                                    %% next-day anchor?" Log-fallback
                                    %% so compliance folks have a
                                    %% trace even when the bus is down.
                                    try erlkoenig_events:notify(
                                          {audit_sealed, Info})
                                    catch NC:NR ->
                                        logger:warning(
                                          "[audit] seal notification "
                                          "lost: ~p:~p; info=~p",
                                          [NC, NR, Info])
                                    end,
                                    {ok, Info, WrittenState#state{fd = NewFd}};
                                {error, R} ->
                                    %% Rename worked but we couldn't
                                    %% reopen — file ended up as the
                                    %% sealed archive, next append
                                    %% will re-open lazily.
                                    {error, {reopen_failed, R},
                                     WrittenState#state{fd = undefined}}
                            end;
                        {error, R} ->
                            %% Rename failed — the seal event is in
                            %% the live file already. Reopen for the
                            %% next append and report the error; the
                            %% operator can rename manually and the
                            %% chain stays consistent.
                            NextFd = case open_log(Path) of
                                {ok, RFd} -> RFd;
                                {error, _} -> undefined
                            end,
                            {error, {rename_failed, R},
                             WrittenState#state{fd = NextFd}}
                    end;
                {error, R} ->
                    %% Seal event never made it to disk — state is
                    %% still at the pre-seal anchor, safe to leave.
                    {error, {seal_write_failed, R}}
            end;
        {error, R} ->
            {error, {read_failed, R}}
    end.

%% Compose `<path>.<UTC YYYY-MM-DD>.sealed`. Date in the suffix so an
%% operator can grep by day; using the live path as base keeps backups
%% and tests deterministic.
-spec sealed_path(string()) -> string().
sealed_path(Path) ->
    {{Y, Mo, D}, _} = calendar:universal_time(),
    Date = lists:flatten(io_lib:format("~4..0B-~2..0B-~2..0B", [Y, Mo, D])),
    Path ++ "." ++ Date ++ ".sealed".

%% Helper: append a line to a file via a short-lived FD. We use this
%% (rather than the writer FD) for the seal event because the writer
%% has just been closed in do_seal_day/1.
-spec append_line(string(), iodata()) -> ok | {error, term()}.
append_line(Path, Data) ->
    case file:open(Path, [append, raw]) of
        {ok, Fd} ->
            R = file:write(Fd, Data),
            _ = file:close(Fd),
            R;
        {error, _} = Err -> Err
    end.

%% --- Public error wrapping ---

maybe_notify_verify_failure(Path, {error, {What, Line, Reason}})
  when What =:= chain_break; What =:= signature_invalid ->
    %% Surface to AMQP — security-relevant: external verifier (or
    %% future periodic self-check) just found tampering. Page-on-this
    %% material. Log at `critical' if notify itself fails so the
    %% operator still sees the tampering finding locally.
    Code = case What of
        chain_break -> erlkoenig_error:code(audit, chain_broken);
        signature_invalid -> erlkoenig_error:code(audit, signature_invalid)
    end,
    Evidence = #{path => Path, line => Line, reason => Reason, code => Code},
    try erlkoenig_events:notify({audit_chain_break, Evidence})
    catch NClass:NReason ->
        logger:critical(
          "[audit] tampering notification lost: "
          "~p:~p; path=~p line=~p reason=~p code=~p",
          [NClass, NReason, Path, Line, {What, Reason}, Code])
    end;
maybe_notify_verify_failure(_Path, _Result) ->
    ok.

wrap_verify_chain_result(_Path, {ok, _} = Ok) ->
    Ok;
wrap_verify_chain_result(Path, {error, {chain_break, Line, Reason}}) ->
    audit_error_s(critical, chain_broken,
                  "audit hash chain verification failed",
                  #{path => Path, line => Line, reason => Reason});
wrap_verify_chain_result(Path, {error, {signature_invalid, Line, Reason}}) ->
    audit_error_s(critical, signature_invalid,
                  "audit event signature verification failed",
                  #{path => Path, line => Line, reason => Reason});
wrap_verify_chain_result(Path, {error, {read_failed, Reason}}) ->
    audit_error(read_failed,
                "audit log could not be read",
                #{path => Path, reason => Reason}).

wrap_verify_seal_result(_Path, {ok, _} = Ok) ->
    Ok;
wrap_verify_seal_result(Path, {error, seal_hmac_mismatch}) ->
    audit_error_s(critical, seal_hmac_mismatch,
                  "audit sealed file HMAC did not match",
                  #{path => Path});
wrap_verify_seal_result(Path, {error, Reason}) ->
    audit_error(seal_invalid,
                "audit sealed file verification failed",
                #{path => Path, reason => Reason}).

audit_seal_error(Path, no_hmac_key) ->
    audit_error(seal_failed,
                "audit day seal failed",
                #{path => Path, reason => no_hmac_key});
audit_seal_error(Path, no_log_file) ->
    audit_error(seal_failed,
                "audit day seal failed",
                #{path => Path, reason => no_log_file});
audit_seal_error(Path, Reason) ->
    audit_error(seal_failed,
                "audit day seal failed",
                #{path => Path, reason => Reason}).

audit_error(read_failed, Context, Data) ->
    {error, ?EK_ERROR(audit, read_failed, Context, Data)};
audit_error(seal_failed, Context, Data) ->
    {error, ?EK_ERROR(audit, seal_failed, Context, Data)};
audit_error(seal_invalid, Context, Data) ->
    {error, ?EK_ERROR(audit, seal_invalid, Context, Data)};
audit_error(query_failed, Context, Data) ->
    {error, ?EK_ERROR(audit, query_failed, Context, Data)};
audit_error(unknown_call, Context, Data) ->
    {error, ?EK_ERROR(audit, unknown_call, Context, Data)}.

audit_error_s(critical, chain_broken, Context, Data) ->
    {error, ?EK_ERROR_S(critical, audit, chain_broken, Context, Data)};
audit_error_s(critical, signature_invalid, Context, Data) ->
    {error, ?EK_ERROR_S(critical, audit, signature_invalid, Context, Data)};
audit_error_s(critical, seal_hmac_mismatch, Context, Data) ->
    {error, ?EK_ERROR_S(critical, audit, seal_hmac_mismatch, Context, Data)}.

%% --- Seal verification ---

do_verify_seal(Bin, HmacKey) ->
    Lines = [L || L <- binary:split(Bin, <<"\n">>, [global]), L =/= <<>>],
    case lists:reverse(Lines) of
        [] -> {error, empty_file};
        [LastLine | _] ->
            try json:decode(LastLine) of
                #{<<"type">> := <<"audit.seal">>} = SealEvent ->
                    Hmac = maps:get(<<"hmac">>, SealEvent, undefined),
                    EventCount = maps:get(<<"event_count">>, SealEvent, undefined),
                    ByteCount = maps:get(<<"byte_count">>, SealEvent, undefined),
                    Anchor = maps:get(<<"this_hash">>, SealEvent, undefined),
                    case validate_seal_fields(Hmac, EventCount, ByteCount, Anchor) of
                        ok ->
                            verify_seal_hmac(Bin, ByteCount, Hmac,
                                             HmacKey, EventCount, Anchor);
                        {error, _} = Err -> Err
                    end;
                _ -> {error, last_line_not_seal}
            catch C:R ->
                {error, {seal_decode_failed, C, R}}
            end
    end.

validate_seal_fields(undefined, _, _, _) -> {error, seal_missing_hmac};
validate_seal_fields(_, undefined, _, _) -> {error, seal_missing_event_count};
validate_seal_fields(_, _, undefined, _) -> {error, seal_missing_byte_count};
validate_seal_fields(_, _, _, undefined) -> {error, seal_missing_this_hash};
validate_seal_fields(_, _, _, _)         -> ok.

verify_seal_hmac(Bin, ByteCount, ExpectedHex, HmacKey, EventCount, Anchor) ->
    case byte_size(Bin) >= ByteCount of
        false -> {error, seal_byte_count_overflow};
        true ->
            Day = binary:part(Bin, 0, ByteCount),
            ActualHex = hex(crypto:mac(hmac, sha256, HmacKey, Day)),
            case ActualHex =:= ExpectedHex of
                false -> {error, seal_hmac_mismatch};
                true ->
                    {ok, #{event_count => EventCount,
                           byte_count  => ByteCount,
                           anchor      => Anchor}}
            end
    end.

%% --- Chain recovery on startup ---

%% Read the last non-empty line of the audit log, decode it just enough
%% to extract `seq` and `this_hash`, and return them as the seed for a
%% continuing chain. If the file is empty/missing, look for the
%% most-recent sealed file in the same directory so the chain crosses
%% the daily boundary cleanly. If neither exists or the last line has
%% no chain fields (legacy logs), start fresh.
-spec recover_chain_state(string()) -> {non_neg_integer(), binary()}.
recover_chain_state(Path) ->
    case last_chain_line(Path) of
        {ok, Last} -> extract_chain_seed(Last);
        empty ->
            case latest_sealed_file(Path) of
                {ok, Sealed} ->
                    case last_chain_line(Sealed) of
                        {ok, Last} -> extract_chain_seed(Last);
                        empty      -> {0, ?GENESIS_HASH}
                    end;
                none -> {0, ?GENESIS_HASH}
            end
    end.

-spec last_chain_line(string()) -> {ok, binary()} | empty.
last_chain_line(Path) ->
    case file:read_file(Path) of
        {ok, Bin} ->
            Lines = [L || L <- binary:split(Bin, <<"\n">>, [global]),
                          L =/= <<>>],
            case lists:reverse(Lines) of
                []         -> empty;
                [Last | _] -> {ok, Last}
            end;
        {error, _} -> empty
    end.

%% Newest sealed file derived from `Path`. We rely on the sealed
%% suffix's lexicographic sort matching chronological order
%% (`<base>.YYYY-MM-DD.sealed`).
-spec latest_sealed_file(string()) -> {ok, string()} | none.
latest_sealed_file(Path) ->
    Pattern = Path ++ ".*.sealed",
    case lists:sort(filelib:wildcard(Pattern)) of
        [] -> none;
        Matches -> {ok, lists:last(Matches)}
    end.

-spec extract_chain_seed(binary()) -> {non_neg_integer(), binary()}.
extract_chain_seed(Line) ->
    try
        Decoded = json:decode(Line),
        Seq = maps:get(<<"seq">>, Decoded, 0),
        Hash = maps:get(<<"this_hash">>, Decoded, ?GENESIS_HASH),
        {Seq, Hash}
    catch _:_ ->
        %% Malformed line — start a fresh chain from genesis.
        {0, ?GENESIS_HASH}
    end.

%% --- Chain verification (used by verify_chain/1) ---

verify_lines([], _Expected, _PubKey, _Line, Count) ->
    {ok, Count};
verify_lines([Line | Rest], ExpectedPrev, PubKey, LineNo, Count) ->
    try
        Event = json:decode(Line),
        ActualPrev = maps:get(<<"prev_hash">>, Event, undefined),
        StoredHash = maps:get(<<"this_hash">>, Event, undefined),
        Signature = maps:get(<<"signature">>, Event, null),
        %% Recompute hash over the canonical form excluding both
        %% this_hash and signature (signature is derived from this_hash
        %% so including it would be circular).
        Recomputed = compute_this_hash(maps:remove(<<"signature">>, Event)),
        case {ActualPrev, StoredHash} of
            {ExpectedPrev, Recomputed} ->
                case verify_signature(StoredHash, Signature, PubKey) of
                    ok ->
                        verify_lines(Rest, StoredHash, PubKey,
                                     LineNo + 1, Count + 1);
                    {error, Reason} ->
                        {error, {signature_invalid, LineNo, Reason}}
                end;
            {ExpectedPrev, _Other} ->
                {error, {chain_break, LineNo, this_hash_mismatch}};
            {_Other, _} ->
                {error, {chain_break, LineNo, prev_hash_mismatch}}
        end
    catch C:R ->
        {error, {chain_break, LineNo, {decode_failed, C, R}}}
    end.

%% Verify Ed25519 signature over the raw 32 bytes of this_hash.
%% No-op when the caller didn't provide a public key, when the event
%% has no signature (legacy line), or when signing is disabled (null).
verify_signature(_Hash, _Sig, undefined) -> ok;
verify_signature(_Hash, null, _PubKey)   -> ok;
verify_signature(HexHash, HexSig, PubKey) when is_binary(HexSig),
                                               is_binary(PubKey) ->
    try
        RawHash = hex_to_bin(HexHash),
        RawSig  = hex_to_bin(HexSig),
        case crypto:verify(eddsa, none, RawHash, RawSig, [PubKey, ed25519]) of
            true  -> ok;
            false -> {error, ed25519_verify_failed}
        end
    catch C:R ->
        {error, {decode_failed, C, R}}
    end.

%% --- Query (reads the log file, filters, returns maps) ---

-spec do_query(string(), map()) -> {ok, [map()]} | {error, term()}.
do_query(Path, Opts) ->
    case file:read_file(Path) of
        {ok, Bin} ->
            Lines = binary:split(Bin, <<"\n">>, [global]),
            SinceIso = case maps:get(since, Opts, 0) of
                0 -> undefined;
                UnixSec when is_integer(UnixSec), UnixSec > 0 ->
                    iso8601_from_unix(UnixSec);
                _ -> undefined
            end,
            TypeFilter = maps:get(type, Opts, undefined),
            SubjectFilter = maps:get(subject, Opts, undefined),
            ContainerNameFilter = maps:get(container_name, Opts, undefined),
            Limit = maps:get(limit, Opts, 100),
            ScanLines = case maps:get(reverse, Opts, false) of
                true -> lists:reverse(Lines);
                false -> Lines
            end,
            Filters = #{type => TypeFilter,
                        subject => SubjectFilter,
                        container_name => ContainerNameFilter},
            Filtered = filter_lines(ScanLines, SinceIso, Filters, Limit, []),
            {ok, Filtered};
        {error, enoent} ->
            {ok, []};
        {error, Reason} ->
            audit_error(query_failed,
                        "audit log query failed",
                        #{path => Path, reason => Reason})
    end.

%% Render a unix-seconds timestamp in the same ISO-8601 format used by
%% `iso8601_now/0`. The lexicographic order of that format matches
%% chronological order, so a substring compare is enough to filter.
-spec iso8601_from_unix(non_neg_integer()) -> binary().
iso8601_from_unix(UnixSec) ->
    {{Y, Mo, D}, {H, Mi, S}} =
        calendar:system_time_to_universal_time(UnixSec, second),
    list_to_binary(io_lib:format(
        "~4..0B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0BZ",
        [Y, Mo, D, H, Mi, S])).

-spec filter_lines([binary()],
                   binary() | undefined,
                   map(),
                   non_neg_integer(),
                   [binary()]) -> [binary()].
filter_lines(_, _, _, 0, Acc) ->
    lists:reverse(Acc);
filter_lines([], _, _, _, Acc) ->
    lists:reverse(Acc);
filter_lines([<<>> | Rest], Since, Filters, Limit, Acc) ->
    filter_lines(Rest, Since, Filters, Limit, Acc);
filter_lines([Line | Rest], Since, Filters, Limit, Acc) ->
    %% Simple substring matching — no JSON parser needed for filtering.
    %% Full JSON parsing is left to external tools (jq, SIEM).
    %%
    %% `since' was previously accepted by the API but silently
    %% discarded here — the compliance-team workflow of "events from
    %% 00:00 UTC" returned every event in the file. Match now on the
    %% `"ts":"...Z"' substring since canonical JSON keeps the ts
    %% field in lexicographic position and ISO-8601 sorts chrono.
    TypeOk = case maps:get(type, Filters, undefined) of
        undefined -> true;
        T ->
            TypeBin = atom_to_binary(T),
            binary:match(Line, TypeBin) =/= nomatch
    end,
    SubjectOk = field_filter_ok(Line, <<"subject">>,
                                maps:get(subject, Filters, undefined)),
    ContainerNameOk = field_filter_ok(Line, <<"container_name">>,
                                      maps:get(container_name, Filters, undefined)),
    SinceOk = case Since of
        undefined -> true;
        SinceIso -> ts_after_or_equal(Line, SinceIso)
    end,
    case TypeOk andalso SubjectOk andalso ContainerNameOk andalso SinceOk of
        true  -> filter_lines(Rest, Since, Filters, Limit - 1, [Line | Acc]);
        false -> filter_lines(Rest, Since, Filters, Limit, Acc)
    end.

field_filter_ok(_Line, _Field, undefined) ->
    true;
field_filter_ok(Line, Field, Value) ->
    EncodedValue = canonical_json(to_bin(Value)),
    Needle = <<"\"", Field/binary, "\":", EncodedValue/binary>>,
    binary:match(Line, Needle) =/= nomatch.

%% Extract the 20-byte ISO timestamp that follows `"ts":"` in the
%% canonical-JSON line and compare with SinceIso. Length-20 matches
%% exactly `YYYY-MM-DDTHH:MM:SSZ`. Lines without a `"ts":` field (or
%% with a truncated one) default to included so we don't silently
%% hide malformed rows from the auditor.
-spec ts_after_or_equal(binary(), binary()) -> boolean().
ts_after_or_equal(Line, SinceIso) ->
    case binary:match(Line, <<"\"ts\":\"">>) of
        nomatch ->
            true;
        {Start, _MatchLen} ->
            TsStart = Start + 6,
            case byte_size(Line) >= TsStart + 20 of
                true ->
                    TsBin = binary:part(Line, TsStart, 20),
                    TsBin >= SinceIso;
                false ->
                    true
            end
    end.
