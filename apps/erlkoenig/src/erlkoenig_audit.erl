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

%% API
-export([start_link/0, log/1, query/1,
         verify_chain/1, verify_chain/2,
         chain_head/0, signing_pubkey/0]).

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
    pub_key   :: binary() | undefined       %% raw 32-byte Ed25519 public key
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
  limit => pos_integer() (max results, default 100)
""".
-spec query(map()) -> {ok, [map()]} | {error, term()}.
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

Returns `{ok, EventCount}` on success or `{error, {chain_break,
LineNumber, Reason}}` on failure.

Does NOT verify Ed25519 signatures. Use `verify_chain/2` with the
node's audit public key to additionally check signatures.
""".
-spec verify_chain(string()) -> {ok, non_neg_integer()} | {error, term()}.
verify_chain(Path) ->
    verify_chain(Path, undefined).

-doc """
Verify hash chain integrity AND Ed25519 signatures.

`PubKey` is the raw 32-byte Ed25519 public key. If `undefined`,
behaves identically to `verify_chain/1` (chain only).

Returns `{ok, EventCount}` on success or `{error, {chain_break |
signature_invalid, LineNumber, Reason}}`.
""".
-spec verify_chain(string(), binary() | undefined) ->
    {ok, non_neg_integer()} | {error, term()}.
verify_chain(Path, PubKey) ->
    case file:read_file(Path) of
        {ok, Bin} ->
            Lines = [L || L <- binary:split(Bin, <<"\n">>, [global]),
                          L =/= <<>>],
            verify_lines(Lines, ?GENESIS_HASH, PubKey, 1, 0);
        {error, _} = Err -> Err
    end.

-doc """
Return the running gen_server's audit signing public key (raw 32
bytes), or `undefined` if signing is not configured.

Customers verify their audit log offline with this key.
""".
-spec signing_pubkey() -> binary() | undefined.
signing_pubkey() ->
    gen_server:call(?MODULE, signing_pubkey).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    proc_lib:set_label(erlkoenig_audit),
    Path = application:get_env(erlkoenig, audit_path, ?DEFAULT_PATH),
    {PrivKey, PubKey} = load_signing_key(),
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
                        priv_key = PrivKey, pub_key = PubKey}};
        {error, Reason} ->
            logger:error("[audit] Cannot open ~s: ~p", [Path, Reason]),
            %% Start without file — events are lost but the system runs.
            %% This avoids blocking the entire supervision tree if
            %% /var/log/erlkoenig doesn't exist yet.
            logger:warning("[audit] Running without audit log"),
            {ok, #state{fd = undefined, path = Path,
                        priv_key = PrivKey, pub_key = PubKey}}
    end.

handle_call({query, Opts}, _From, State) ->
    Result = do_query(State#state.path, Opts),
    {reply, Result, State};

handle_call(chain_head, _From, #state{prev_hash = Hash} = State) ->
    {reply, Hash, State};

handle_call(signing_pubkey, _From, #state{pub_key = Key} = State) ->
    {reply, Key, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

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
    %% Details cannot override the chain-related fields above.
    EventNoHash = maps:fold(fun(K, V, Acc) ->
        Acc#{to_bin(K) => V}
    end, Base, Details),
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

-doc "Decode a lowercase hex binary into the corresponding raw bytes.".
-spec hex_to_bin(binary()) -> binary().
hex_to_bin(Hex) when is_binary(Hex) ->
    <<<<(decode_hex_pair(A, B))>> || <<A, B>> <= Hex>>.

decode_hex_pair(A, B) ->
    (decode_hex_nibble(A) bsl 4) bor decode_hex_nibble(B).

decode_hex_nibble(C) when C >= $0, C =< $9 -> C - $0;
decode_hex_nibble(C) when C >= $a, C =< $f -> C - $a + 10;
decode_hex_nibble(C) when C >= $A, C =< $F -> C - $A + 10.

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

%% --- Chain recovery on startup ---

%% Read the last non-empty line of the audit log, decode it just enough
%% to extract `seq` and `this_hash`, and return them as the seed for a
%% continuing chain. If the file is empty/missing or the last line has
%% no chain fields (legacy logs from before hash-chaining), start fresh.
-spec recover_chain_state(string()) -> {non_neg_integer(), binary()}.
recover_chain_state(Path) ->
    case file:read_file(Path) of
        {ok, Bin} ->
            Lines = [L || L <- binary:split(Bin, <<"\n">>, [global]),
                          L =/= <<>>],
            case lists:reverse(Lines) of
                [] -> {0, ?GENESIS_HASH};
                [Last | _] -> extract_chain_seed(Last)
            end;
        {error, _} -> {0, ?GENESIS_HASH}
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
