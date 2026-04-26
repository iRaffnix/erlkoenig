%%%-------------------------------------------------------------------
%%% @doc Protocol fuzz — binary-input safety for erlkoenig_proto.
%%%
%%% erlkoenig_proto:decode/1 receives RAW BYTES from the C-runtime
%%% over a Unix socket.  Any crash here is a DoS vector (one bad
%%% message kills the container controller).  Any silent-accept is a
%%% correctness hazard (a malformed reply is interpreted as success).
%%%
%%% Properties:
%%%
%%%   prop_decode_arbitrary_bytes_never_crashes
%%%     Throws any input at decode/1 — must return {ok,_,_} or
%%%     {error,_} or data map, never raise.
%%%
%%%   prop_decode_known_tag_plus_junk_never_crashes
%%%     Prefix each known tag with a random payload of random size.
%%%     The per-tag decoders must handle short/long/misaligned inputs
%%%     without crashing.
%%%
%%%   prop_tlv_roundtrip_recovers_attrs
%%%     Build a well-formed TLV payload from a random attr map, wrap
%%%     in REPLY_ERROR framing, assert decode recovers the errno +
%%%     message fields correctly.
%%%
%%%   prop_encode_cmd_spawn_never_crashes_on_mixed_opts
%%%     build_spawn_opts-shaped maps with random/extra keys — the
%%%     encoder must not blow up on unknown keys (we saw the env-map
%%%     bug earlier; hunt for cousins).
%%%
%%%   prop_encode_then_decode_roundtrip_simple_reply
%%%     For each reply type with an inverse path, build a known-good
%%%     TLV payload, decode, assert shape matches.
%%% @end
%%%-------------------------------------------------------------------

-module(erlkoenig_proto_fuzz_test).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(nowarn_unused_function).

%% ---------------------------------------------------------------
%% eunit entry points — one proper:quickcheck call per property.
%% ---------------------------------------------------------------

decode_arbitrary_bytes_never_crashes_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_decode_arbitrary_bytes_never_crashes(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

decode_known_tag_plus_junk_never_crashes_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_decode_known_tag_plus_junk_never_crashes(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

tlv_roundtrip_recovers_attrs_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_tlv_roundtrip_recovers_attrs(),
                 [{numtests, 200}, {to_file, user}])
    end}.

encode_cmd_spawn_never_crashes_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_encode_cmd_spawn_never_crashes(),
                 [{numtests, 300}, {to_file, user}])
    end}.

encode_then_decode_roundtrip_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_encode_then_decode_roundtrip_simple_reply(),
                 [{numtests, 300}, {to_file, user}])
    end}.

decode_tlv_truncation_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_decode_tlv_truncation_doesnt_silently_accept(),
                 [{numtests, 500}, {to_file, user}])
    end}.

decode_oversized_len_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_decode_tlv_with_oversized_length(),
                 [{numtests, 200}, {to_file, user}])
    end}.

decode_empty_after_header_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_decode_tag_plus_version_no_payload(),
                 [{numtests, 200}, {to_file, user}])
    end}.

encode_determinism_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_encode_cmd_spawn_is_deterministic(),
                 [{numtests, 200}, {to_file, user}])
    end}.

decode_status_short_frames_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_decode_reply_status_short_frames(),
                 [{numtests, 300}, {to_file, user}])
    end}.

%% ---------------------------------------------------------------
%% Properties
%% ---------------------------------------------------------------

prop_decode_arbitrary_bytes_never_crashes() ->
    ?FORALL(Bin, proper_types:binary(),
        try erlkoenig_proto:decode(Bin) of
            {ok, _Tag, Map} when is_map(Map) -> true;
            {error, _Reason} -> true;
            Other ->
                io:format(user, "unexpected decode return: ~p for ~p~n",
                          [Other, Bin]),
                false
        catch
            Class:Err:Stack ->
                io:format(user, "decode raised ~p:~p~n  stack: ~p~n  input: ~p~n",
                          [Class, Err, lists:sublist(Stack, 3), Bin]),
                false
        end).

prop_decode_known_tag_plus_junk_never_crashes() ->
    ?FORALL({Tag, Junk}, {known_tag(), proper_types:binary()},
        begin
            %% Mimic the wire format: Tag + Version + Payload, but
            %% with random payload and no guarantee of structure.
            Bin = <<Tag, 0, Junk/binary>>,
            try erlkoenig_proto:decode(Bin) of
                {ok, _, Map} when is_map(Map) -> true;
                {error, _} -> true;
                _ -> false
            catch
                Class:Err:Stack ->
                    io:format(user, "decode(~p) raised ~p:~p~n  ~p~n",
                              [Bin, Class, Err, lists:sublist(Stack, 3)]),
                    false
            end
        end).

prop_tlv_roundtrip_recovers_attrs() ->
    ?FORALL({Errno, Msg}, {errno_gen(), message_gen()},
        begin
            %% Manually encode a REPLY_ERROR TLV payload and run it
            %% through decode.  The C runtime emits this shape.
            Payload = iolist_to_binary([
                %% Attr 1 = errno (int32)
                <<1:16/big, 4:16/big, Errno:32/big-signed>>,
                %% Attr 2 = message (string)
                <<2:16/big, (byte_size(Msg)):16/big, Msg/binary>>
            ]),
            %% Wire: Tag (REPLY_ERROR=2) + Version + Payload
            Bin = <<2, 0, Payload/binary>>,
            case erlkoenig_proto:decode(Bin) of
                {ok, reply_error, #{code := Errno, message := Msg}} -> true;
                Other ->
                    io:format(user,
                              "TLV roundtrip broke: errno=~p msg=~p -> ~p~n",
                              [Errno, Msg, Other]),
                    false
            end
        end).

prop_encode_cmd_spawn_never_crashes() ->
    ?FORALL(Opts, spawn_opts_gen(),
        try erlkoenig_proto:encode_cmd_spawn(Opts) of
            Bin when is_binary(Bin) -> true;
            Other ->
                io:format(user, "encode_cmd_spawn ~p -> ~p~n", [Opts, Other]),
                false
        catch
            Class:Err:Stack ->
                io:format(user,
                          "encode_cmd_spawn raised ~p:~p on ~p~n  ~p~n",
                          [Class, Err, Opts, lists:sublist(Stack, 3)]),
                false
        end).

prop_encode_then_decode_roundtrip_simple_reply() ->
    ?FORALL({ExitCode, Signal}, {exit_code_gen(), signal_gen()},
        begin
            %% Build REPLY_EXITED TLV
            Payload = iolist_to_binary([
                <<1:16/big, 4:16/big, ExitCode:32/big-signed>>,
                <<2:16/big, 1:16/big, Signal:8>>
            ]),
            Bin = <<5, 0, Payload/binary>>, %% TAG_REPLY_EXITED
            case erlkoenig_proto:decode(Bin) of
                {ok, reply_exited,
                 #{exit_code := ExitCode, term_signal := Signal}} -> true;
                Other ->
                    io:format(user,
                              "REPLY_EXITED roundtrip: ec=~p sig=~p -> ~p~n",
                              [ExitCode, Signal, Other]),
                    false
            end
        end).

%% ---------------------------------------------------------------
%% Aggressive hunts — silent-accept / truncation / determinism
%% ---------------------------------------------------------------

%% TLV with Len > remaining body.  The decoder MUST NOT claim to
%% have successfully decoded an attribute whose value bytes never
%% arrived.  Currently decode_tlv_attrs falls to the `(_, Acc) ->
%% Acc` clause — which silently ACCEPTS the valid prefix and DROPS
%% the truncated tail.  That's fine for "extra" unknown attrs but
%% hides wire corruption: the caller has no way to tell.
prop_decode_tlv_truncation_doesnt_silently_accept() ->
    ?FORALL({Errno, Msg, Trim},
            {errno_gen(), message_gen(), proper_types:choose(1, 10)},
        ?IMPLIES(byte_size(Msg) >= Trim,
        begin
            %% Build REPLY_ERROR payload then chop bytes off the tail.
            FullPayload = iolist_to_binary([
                <<1:16/big, 4:16/big, Errno:32/big-signed>>,
                <<2:16/big, (byte_size(Msg)):16/big, Msg/binary>>
            ]),
            TruncBytes = byte_size(FullPayload) - Trim,
            Truncated = binary:part(FullPayload, 0, TruncBytes),
            Bin = <<2, 0, Truncated/binary>>,
            case erlkoenig_proto:decode(Bin) of
                {ok, reply_error, #{code := Errno, message := Msg}} ->
                    %% Full recovery despite truncation — impossible
                    %% unless the TLV was hiding the truncation.
                    io:format(user,
                              "BUG: truncated TLV decoded as FULL: trim=~p~n",
                              [Trim]),
                    false;
                {ok, reply_error, Ret} ->
                    %% Partial success is acceptable as long as the
                    %% recovered map is missing keys OR flags the
                    %% issue (code=-1 / message=<<"unknown">>).
                    PartialOk =
                        maps:get(code, Ret, undefined) =/= Errno orelse
                        maps:get(message, Ret, undefined) =/= Msg,
                    PartialOk;
                _ -> true
            end
        end)).

%% TLV where Len field declares a gigantic payload but only a few
%% bytes follow.  Must NOT hang or allocate gigantic buffers.
prop_decode_tlv_with_oversized_length() ->
    ?FORALL(TailBytes, proper_types:choose(0, 20),
        begin
            %% Declare Len = 65535, provide only TailBytes bytes.
            Tail = binary:copy(<<"A">>, TailBytes),
            Bin = <<2, 0,
                    1:16/big, 16#ffff:16/big, Tail/binary>>,
            %% Any return is fine — just must not raise/hang.
            Self = self(),
            Pid = spawn_link(fun() ->
                R = (catch erlkoenig_proto:decode(Bin)),
                Self ! {done, R}
            end),
            receive
                {done, _} -> true
            after 2000 ->
                exit(Pid, kill),
                io:format(user, "decode hung on oversized-len TLV~n", []),
                false
            end
        end).

%% Every known reply tag with only Tag+Version and empty payload.
%% Per-tag decoders must handle this cleanly (empty map or error,
%% never crash).
prop_decode_tag_plus_version_no_payload() ->
    ?FORALL(Tag, known_tag(),
        begin
            Bin = <<Tag, 0>>,
            try erlkoenig_proto:decode(Bin) of
                {ok, _, Map} when is_map(Map) -> true;
                {error, _} -> true;
                _ -> false
            catch
                _:_ -> false
            end
        end).

%% encode_cmd_spawn with identical input must produce identical
%% output bytes.  Non-determinism here would break any downstream
%% cache / signature mechanism.
prop_encode_cmd_spawn_is_deterministic() ->
    ?FORALL(Opts, spawn_opts_gen(),
        begin
            A = (catch erlkoenig_proto:encode_cmd_spawn(Opts)),
            B = (catch erlkoenig_proto:encode_cmd_spawn(Opts)),
            C = (catch erlkoenig_proto:encode_cmd_spawn(Opts)),
            A =:= B andalso B =:= C
        end).

%% REPLY_STATUS is now a TLV payload (state u8, pid u32, uptime u64 —
%% each as an independent attribute). Feed random short payloads and
%% assert the decoder never crashes or returns a ghost value. Any
%% subset of missing TLVs must fall back to zero defaults. This is the
%% regression harness for the positional-vs-TLV drift that silently
%% broke the recovery path.
prop_decode_reply_status_short_frames() ->
    ?FORALL(Payload, short_payload_gen(),
        begin
            Bin = <<16#06, 1, Payload/binary>>, %% TAG_REPLY_STATUS, ver=1
            case erlkoenig_proto:decode(Bin) of
                {ok, reply_status, #{state := S, child_pid := P,
                                     uptime_ms := U}}
                  when is_integer(S), is_integer(P), is_integer(U) ->
                    true;
                {error, _} ->
                    true;
                Other ->
                    io:format(user,
                              "BUG: REPLY_STATUS ~p-byte payload -> ~p~n",
                              [byte_size(Payload), Other]),
                    false
            end
        end).

short_payload_gen() ->
    ?LET(N, proper_types:choose(0, 20), proper_types:binary(N)).

%% ---------------------------------------------------------------
%% Generators
%% ---------------------------------------------------------------

known_tag() ->
    proper_types:oneof([
        16#01, 16#02, 16#03, 16#04, 16#05, 16#06, 16#07, 16#08, 16#09,
        16#10, 16#11, 16#12, 16#13, 16#14, 16#15, 16#16, 16#17,
        16#18, 16#19, 16#1A, 16#1B, 16#1C, 16#1D
    ]).

errno_gen() ->
    proper_types:oneof([-32, -13, -1, 0, 1, 255, 65535, -32768, 2147483647]).

message_gen() ->
    sized_binary(0, 80).

exit_code_gen() ->
    proper_types:oneof([-1, 0, 1, 42, 127, 128, 255, 256, -2147483648]).

signal_gen() ->
    proper_types:oneof([0, 1, 9, 15, 31, 64, 128, 255]).

spawn_opts_gen() ->
    ?LET(Fields, proper_types:list(spawn_field_gen()),
         maps:from_list(Fields)).

spawn_field_gen() ->
    proper_types:oneof([
        {args,     proper_types:list(
                     sized_binary(0, 40))},
        {env,      env_gen()},
        {uid,      proper_types:choose(0, 65535)},
        {gid,      proper_types:choose(0, 65535)},
        {seccomp,  proper_types:oneof([0, 1, 2, default, strict])},
        {caps_keep, proper_types:oneof([0, 1, 16#ffffffff])},
        {rootfs_mb, proper_types:choose(0, 1024)},
        {dns_ip,   proper_types:choose(0, 16#ffffffff)},
        {flags,    proper_types:choose(0, 16#ffffffff)},
        {memory_max, proper_types:choose(0, 16#7fffffffffffffff)},
        {pids_max, proper_types:choose(0, 65535)},
        {cpu_weight, proper_types:choose(1, 10000)},
        {image_path, sized_binary(0, 60)},
        %% Intentionally mix in unknown keys that shouldn't crash
        %% the encoder — the build_spawn_opts whitelist is supposed
        %% to filter them out, but the encoder itself should be
        %% defensive too.
        {bogus_key, 42},
        {another,  <<"value">>}
    ]).

sized_binary(Min, Max) ->
    ?LET(N, proper_types:choose(Min, Max), proper_types:binary(N)).

env_gen() ->
    %% Mix map form (new) and list-of-tuples form (old).  The
    %% encoder was crashing on maps before we fixed it — verify
    %% both paths stay happy.
    proper_types:oneof([
        ?LET(L, proper_types:list(
                  {sized_binary(1, 10),
                   sized_binary(0, 20)}),
             L),
        ?LET(L, proper_types:list(
                  {sized_binary(1, 10),
                   sized_binary(0, 20)}),
             maps:from_list(L))
    ]).
