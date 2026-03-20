%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_sig).
-moduledoc """
Binary signature creation and verification.

Signs static binaries with Ed25519 and verifies them against an
X.509 certificate chain. The .sig file is a PEM-encoded envelope
containing the signature payload, Ed25519 signature, and the
certificate chain.

Signature payload (fixed binary layout, v1):
  Version:8 = 1
  Algorithm:8 = 1 (Ed25519)
  SHA256:256 (32 bytes)
  GitSHA:160 (20 bytes, zero-padded if absent)
  Timestamp:64 (Unix seconds, big-endian)
  SignerCN_Len:16 (big-endian)
  SignerCN:variable (UTF-8)

The .sig file format:
  -----BEGIN ERLKOENIG SIGNATURE-----
  <base64: PayloadLen:32 | Payload | Signature>
  -----END ERLKOENIG SIGNATURE-----
  -----BEGIN CERTIFICATE-----
  <signing certificate>
  -----END CERTIFICATE-----
  -----BEGIN CERTIFICATE-----
  <intermediate CA>
  -----END CERTIFICATE-----
""".

%% API
-export([sign/4, verify/2]).

%% Internal (exported for testing)
-export([encode_payload/1, decode_payload/1, hash_file/1]).

-include_lib("public_key/include/public_key.hrl").

-define(VERSION, 1).
-define(ALG_ED25519, 1).

-type sign_opts() :: #{
    git_sha => binary()   %% 40-char hex string or 20-byte raw
}.

-type sig_meta() :: #{
    sha256    := binary(),   %% hex-encoded
    git_sha   := binary(),   %% hex-encoded or <<>>
    signer    := binary(),   %% CN from signing cert
    timestamp := integer(),  %% Unix seconds
    chain     := [public_key:der_encoded()]  %% DER certs
}.

%%%===================================================================
%%% API
%%%===================================================================

-doc """
Sign a binary file. Returns the .sig file content.

BinaryPath: path to the static binary
CertPath:   path to PEM file with signing certificate
KeyPath:    path to PEM file with Ed25519 private key
Opts:       #{git_sha => <<"abcdef01...">>}
""".
-spec sign(file:filename(), file:filename(), file:filename(), sign_opts()) ->
    {ok, iodata()} | {error, term()}.
sign(BinaryPath, CertPath, KeyPath, Opts) ->
    try
        {ok, SHA256} = hash_file(BinaryPath),
        {ok, PrivKey} = read_private_key(KeyPath),
        {ok, CertChain} = read_cert_chain(CertPath),
        SignerCN = extract_cn(hd(CertChain)),
        GitSHA = parse_git_sha(maps:get(git_sha, Opts, <<>>)),
        Timestamp = erlang:system_time(second),

        Payload = encode_payload(#{
            sha256    => SHA256,
            git_sha   => GitSHA,
            timestamp => Timestamp,
            signer_cn => SignerCN
        }),

        Signature = crypto:sign(eddsa, none, Payload, [PrivKey, ed25519]),

        SigBlock = encode_sig_block(Payload, Signature),
        CertBlocks = [public_key:pem_encode(
            [{cert_entry_type(C), C, not_encrypted}]) || C <- CertChain],

        {ok, [SigBlock | CertBlocks]}
    catch
        error:{badmatch, {error, Reason}} -> {error, Reason};
        Class:Reason:Stack ->
            logger:error("[sig] sign failed: ~p:~p~n~p", [Class, Reason, Stack]),
            {error, {sign_failed, Reason}}
    end.

-doc """
Verify a binary against its .sig file.

BinaryPath: path to the binary
SigPath:    path to the .sig file
Returns metadata on success (sha256, git_sha, signer, chain).
""".
-spec verify(file:filename_all(), file:filename_all()) ->
    {ok, sig_meta()} | {error, term()}.
verify(BinaryPath, SigPath) ->
    try
        {ok, SHA256Actual} = hash_file(BinaryPath),
        {ok, SigBin} = read_file(SigPath),
        {ok, Payload, Signature, CertChain} = parse_sig_file(SigBin),
        {ok, Meta} = decode_payload(Payload),

        %% 1. SHA256 must match
        SHA256Claimed = maps:get(sha256, Meta),
        case SHA256Actual =:= SHA256Claimed of
            true  -> ok;
            false -> throw({error, {sha256_mismatch,
                                    #{claimed => hex(SHA256Claimed),
                                      actual => hex(SHA256Actual)}}})
        end,

        %% 2. Signature must be valid
        PubKey = extract_public_key(hd(CertChain)),
        case crypto:verify(eddsa, none, Payload, Signature, [PubKey, ed25519]) of
            true  -> ok;
            false -> throw({error, signature_invalid})
        end,

        %% 3. Return metadata (chain validation is done by erlkoenig_pki)
        {ok, Meta#{
            sha256 => hex(SHA256Claimed),
            git_sha => hex(maps:get(git_sha, Meta)),
            chain => CertChain
        }}
    catch
        throw:{error, _} = Err -> Err;
        error:{badmatch, {error, Reason}} -> {error, Reason};
        Class:Reason:Stack ->
            logger:error("[sig] verify failed: ~p:~p~n~p", [Class, Reason, Stack]),
            {error, {verify_failed, Reason}}
    end.

%%%===================================================================
%%% Payload encoding/decoding
%%%===================================================================

-spec encode_payload(map()) -> binary().
encode_payload(#{sha256 := SHA256, git_sha := GitSHA,
                 timestamp := Ts, signer_cn := CN}) ->
    CNBin = iolist_to_binary(CN),
    CNLen = byte_size(CNBin),
    <<?VERSION:8, ?ALG_ED25519:8,
      SHA256:32/binary,
      GitSHA:20/binary,
      Ts:64/big,
      CNLen:16/big,
      CNBin/binary>>.

-spec decode_payload(binary()) -> {ok, map()} | {error, term()}.
decode_payload(<<?VERSION:8, ?ALG_ED25519:8,
                 SHA256:32/binary,
                 GitSHA:20/binary,
                 Ts:64/big,
                 CNLen:16/big,
                 CN:CNLen/binary>>) ->
    {ok, #{sha256 => SHA256, git_sha => GitSHA,
           timestamp => Ts, signer_cn => CN}};
decode_payload(<<Version:8, _/binary>>) when Version =/= ?VERSION ->
    {error, {unsupported_version, Version}};
decode_payload(_) ->
    {error, invalid_payload}.

%%%===================================================================
%%% File I/O
%%%===================================================================

-spec hash_file(file:filename()) -> {ok, binary()} | {error, term()}.
hash_file(Path) ->
    case file:read_file(Path) of
        {ok, Bin} ->
            {ok, crypto:hash(sha256, Bin)};
        {error, Reason} ->
            {error, {read_failed, Path, Reason}}
    end.

-spec read_file(file:filename()) -> {ok, binary()} | {error, term()}.
read_file(Path) ->
    case file:read_file(Path) of
        {ok, _} = Ok -> Ok;
        {error, enoent} -> {error, sig_not_found};
        {error, Reason} -> {error, {read_failed, Path, Reason}}
    end.

-spec read_private_key(file:filename()) -> {ok, binary()} | {error, term()}.
read_private_key(Path) ->
    maybe
        {ok, PemBin} ?=
            case file:read_file(Path) of
                {ok, _} = Ok -> Ok;
                {error, Reason} -> {error, {read_failed, Path, Reason}}
            end,
        [{_, DerBin, not_encrypted}] ?= public_key:pem_decode(PemBin),
        %% Ed25519 keys in PKCS#8: the raw 32-byte key is wrapped
        %% in an OCTET STRING inside PrivateKeyInfo.
        %% OTP's pem_entry_decode handles this for us.
        case public_key:pem_entry_decode({'PrivateKeyInfo', DerBin, not_encrypted}) of
            #'ECPrivateKey'{privateKey = RawKey} ->
                {ok, RawKey};
            {_, #'ECPrivateKey'{privateKey = RawKey}} ->
                {ok, RawKey};
            Other ->
                %% Try direct extraction from DER
                extract_ed25519_key(DerBin, Other)
        end
    else
        {error, _} = Err -> Err;
        _ -> {error, {invalid_key_file, Path}}
    end.

-spec extract_ed25519_key(binary(), term()) -> {ok, binary()} | {error, term()}.
extract_ed25519_key(DerBin, _Decoded) ->
    %% Ed25519 PKCS#8 DER contains the 32-byte key in a known position.
    %% The key is wrapped: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING { OCTET STRING { key } } }
    %% We look for the 32-byte key after the Ed25519 OID (1.3.101.112 = 06 03 2b 65 70)
    case binary:match(DerBin, <<16#06, 16#03, 16#2b, 16#65, 16#70>>) of
        {Pos, 5} ->
            %% After OID: 04 22 04 20 <32 bytes>
            Rest = binary:part(DerBin, Pos + 5, byte_size(DerBin) - Pos - 5),
            case Rest of
                <<16#04, _Len1, 16#04, 16#20, Key:32/binary, _/binary>> ->
                    {ok, Key};
                _ ->
                    {error, ed25519_key_extraction_failed}
            end;
        nomatch ->
            {error, not_ed25519_key}
    end.

-spec read_cert_chain(file:filename()) -> {ok, [public_key:der_encoded()]} | {error, term()}.
read_cert_chain(Path) ->
    maybe
        {ok, PemBin} ?=
            case file:read_file(Path) of
                {ok, _} = Ok -> Ok;
                {error, Reason} -> {error, {read_failed, Path, Reason}}
            end,
        Entries = public_key:pem_decode(PemBin),
        Certs = [Der || {'Certificate', Der, _} <- Entries],
        case Certs of
            [] -> {error, {no_certificates, Path}};
            _  -> {ok, Certs}
        end
    else
        {error, _} = Err -> Err
    end.

%%%===================================================================
%%% .sig file format
%%%===================================================================

-spec encode_sig_block(binary(), binary()) -> iodata().
encode_sig_block(Payload, Signature) ->
    PayloadLen = byte_size(Payload),
    Inner = <<PayloadLen:32/big, Payload/binary, Signature/binary>>,
    B64 = base64:encode(Inner),
    [<<"-----BEGIN ERLKOENIG SIGNATURE-----\n">>,
     wrap_base64(B64),
     <<"-----END ERLKOENIG SIGNATURE-----\n">>].

-spec parse_sig_file(binary()) -> {ok, binary(), binary(), [public_key:der_encoded()]} | {error, term()}.
parse_sig_file(PemBin) ->
    %% Split into PEM blocks manually — the first block is our custom type,
    %% the rest are standard X.509 certificates.
    maybe
        {ok, SigB64, CertPem} ?= split_sig_and_certs(PemBin),
        <<PayloadLen:32/big, Rest/binary>> ?= base64:decode(SigB64),
        <<Payload:PayloadLen/binary, Signature/binary>> = Rest,
        Certs = [Der || {'Certificate', Der, _} <- public_key:pem_decode(CertPem)],
        case Certs of
            [] -> {error, no_certificates_in_sig};
            _  -> {ok, Payload, Signature, Certs}
        end
    else
        {error, _} = Err -> Err;
        _ -> {error, invalid_sig_encoding}
    end.

-spec split_sig_and_certs(binary()) -> {ok, binary(), binary()} | {error, term()}.
split_sig_and_certs(Bin) ->
    BeginMarker = <<"-----BEGIN ERLKOENIG SIGNATURE-----">>,
    EndMarker = <<"-----END ERLKOENIG SIGNATURE-----">>,
    case binary:match(Bin, BeginMarker) of
        {Start, Len} ->
            After = Start + Len,
            case binary:match(Bin, EndMarker, [{scope, {After, byte_size(Bin) - After}}]) of
                {EndStart, EndLen} ->
                    SigB64 = strip_whitespace(binary:part(Bin, After, EndStart - After)),
                    CertStart = EndStart + EndLen,
                    CertPem = binary:part(Bin, CertStart, byte_size(Bin) - CertStart),
                    {ok, SigB64, CertPem};
                nomatch ->
                    {error, missing_sig_end_marker}
            end;
        nomatch ->
            {error, missing_sig_begin_marker}
    end.

%%%===================================================================
%%% Helpers
%%%===================================================================

-spec extract_cn(public_key:der_encoded()) -> binary().
extract_cn(DerCert) ->
    OTPCert = public_key:pkix_decode_cert(DerCert, otp),
    #'OTPCertificate'{tbsCertificate = TBS} = OTPCert,
    #'OTPTBSCertificate'{subject = Subject} = TBS,
    {rdnSequence, RDNs} = Subject,
    find_cn(RDNs).

find_cn([]) -> <<"unknown">>;
find_cn([RDN | Rest]) ->
    case find_cn_in_rdn(RDN) of
        undefined -> find_cn(Rest);
        CN -> CN
    end.

find_cn_in_rdn([]) -> undefined;
find_cn_in_rdn([#'AttributeTypeAndValue'{type = ?'id-at-commonName', value = V} | _]) ->
    case V of
        {utf8String, S} -> S;
        {printableString, S} -> list_to_binary(S);
        S when is_list(S) -> list_to_binary(S);
        S when is_binary(S) -> S;
        S -> list_to_binary(io_lib:format("~p", [S]))
    end;
find_cn_in_rdn([_ | Rest]) ->
    find_cn_in_rdn(Rest).

-spec extract_public_key(public_key:der_encoded()) -> binary().
extract_public_key(DerCert) ->
    %% Use 'plain' decoding to get standard records (not OTP-specific)
    Cert = public_key:pkix_decode_cert(DerCert, plain),
    #'Certificate'{tbsCertificate = TBS} = Cert,
    #'TBSCertificate'{subjectPublicKeyInfo = SPKI} = TBS,
    #'SubjectPublicKeyInfo'{subjectPublicKey = PubKeyBits} = SPKI,
    %% For Ed25519, subjectPublicKey is a bitstring containing the raw 32-byte key
    PubKeyBits.

-spec cert_entry_type(public_key:der_encoded()) -> atom().
cert_entry_type(_) -> 'Certificate'.

-spec parse_git_sha(binary()) -> binary().
parse_git_sha(<<>>) ->
    <<0:160>>;
parse_git_sha(Hex) when byte_size(Hex) =:= 40 ->
    hex_to_bin(Hex);
parse_git_sha(Raw) when byte_size(Raw) =:= 20 ->
    Raw;
parse_git_sha(_) ->
    <<0:160>>.

-spec hex(binary()) -> binary().
hex(Bin) ->
    list_to_binary([io_lib:format("~2.16.0b", [B]) || <<B>> <= Bin]).

-spec hex_to_bin(binary()) -> binary().
hex_to_bin(Hex) ->
    << <<(binary_to_integer(<<H, L>>, 16))>> || <<H, L>> <= Hex >>.

-spec strip_whitespace(binary()) -> binary().
strip_whitespace(Bin) ->
    << <<C>> || <<C>> <= Bin, C =/= $\n, C =/= $\r, C =/= $\s, C =/= $\t >>.

-spec wrap_base64(binary()) -> iodata().
wrap_base64(B64) ->
    wrap_base64(B64, []).

wrap_base64(<<Line:64/binary, Rest/binary>>, Acc) ->
    wrap_base64(Rest, [Acc, Line, $\n]);
wrap_base64(<<>>, Acc) ->
    Acc;
wrap_base64(Rest, Acc) ->
    [Acc, Rest, $\n].
