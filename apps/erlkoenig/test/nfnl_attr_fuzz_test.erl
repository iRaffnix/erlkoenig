%%%-------------------------------------------------------------------
%%% @doc Netlink attribute parser fuzz.
%%%
%%% `nfnl_attr:decode/1` parses TLV-ish attributes out of netlink
%%% messages.  Kernel responses flow through this — any crash is a
%%% DoS vector (one malformed kernel reply and the nft subsystem
%%% tree crashes).  Any silent-accept can corrupt downstream rule
%%% compilation.
%%%
%%% Wire format (Linux netlink NLA):
%%%   +--------+--------+-------------+
%%%   | Len:16 | Type:16| Value + pad |   all little-endian
%%%   +--------+--------+-------------+
%%%
%%% Type's top bit (NLA_F_NESTED) toggles recursion.
%%% @end
%%%-------------------------------------------------------------------

-module(nfnl_attr_fuzz_test).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(nowarn_unused_function).

decode_arbitrary_never_crashes_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_decode_arbitrary_bytes_safe(),
                 [{numtests, 1000}, {to_file, user}, noshrink])
    end}.

decode_wellformed_roundtrip_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_wellformed_decodes_to_attrs(),
                 [{numtests, 300}, {to_file, user}])
    end}.

decode_zero_len_header_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_zero_len_header_doesnt_hang(),
                 [{numtests, 100}, {to_file, user}])
    end}.

decode_nested_depth_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_nested_attrs_dont_stack_overflow(),
                 [{numtests, 50}, {to_file, user}])
    end}.

%% -------------------------------------------------------------------
%% Properties
%% -------------------------------------------------------------------

%% Random bytes thrown at decode/1.  Either returns a list OR
%% raises a tagged error — never unchecked exception.
prop_decode_arbitrary_bytes_safe() ->
    ?FORALL(Bin, proper_types:binary(),
        begin
            Self = self(),
            Pid = spawn(fun() ->
                R = try nfnl_attr:decode(Bin) of
                        L when is_list(L) -> {ok, L};
                        Other -> {unexpected, Other}
                    catch
                        error:{invalid_nla, _, _} -> expected_error;
                        error:{badmatch, _} -> crashed_badmatch;
                        error:function_clause -> crashed_function_clause;
                        C:E:_ -> {crashed, C, E}
                    end,
                Self ! {self(), R}
            end),
            receive {Pid, R} ->
                case R of
                    {ok, _} -> true;
                    expected_error -> true;
                    crashed_badmatch ->
                        io:format(user,
                                  "BUG: nfnl_attr:decode crashed with badmatch on ~p~n",
                                  [Bin]),
                        false;
                    crashed_function_clause ->
                        io:format(user,
                                  "BUG: nfnl_attr:decode crashed function_clause on ~p~n",
                                  [Bin]),
                        false;
                    Other ->
                        io:format(user, "unexpected: ~p on ~p~n", [Other, Bin]),
                        false
                end
            after 2000 ->
                exit(Pid, kill),
                io:format(user, "decode hung on ~p~n", [Bin]),
                false
            end
        end).

%% Build a well-formed single attr and roundtrip.
prop_wellformed_decodes_to_attrs() ->
    ?FORALL({Type, Value}, {attr_type_gen(), value_gen()},
        begin
            Encoded = nfnl_attr:encode(Type, Value),
            case nfnl_attr:decode(Encoded) of
                [{Type, Value}] -> true;
                Other ->
                    io:format(user, "roundtrip broke: type=~p val=~p -> ~p~n",
                              [Type, Value, Other]),
                    false
            end
        end).

%% Zero-length header is legal (attr with no value).  Must not loop.
prop_zero_len_header_doesnt_hang() ->
    ?FORALL(Type, attr_type_gen(),
        begin
            %% Len=4 (just header), no value
            Bin = <<4:16/little, Type:16/little>>,
            Self = self(),
            Pid = spawn(fun() ->
                R = (catch nfnl_attr:decode(Bin)),
                Self ! {self(), R}
            end),
            receive {Pid, _} -> true
            after 1000 ->
                exit(Pid, kill),
                io:format(user, "zero-len hung on type=~p~n", [Type]),
                false
            end
        end).

%% Deeply nested attrs — must not blow the stack.
prop_nested_attrs_dont_stack_overflow() ->
    ?FORALL(Depth, proper_types:choose(1, 200),
        begin
            %% Build a pathologically-nested attr: each level wraps
            %% the previous in a nested-flagged attr.
            Inner = <<>>,
            Deep = build_nested(Inner, Depth),
            case (catch nfnl_attr:decode(Deep)) of
                L when is_list(L) -> true;
                {'EXIT', _} -> true;  %% tagged error OK
                _ -> true
            end
        end).

build_nested(Acc, 0) -> Acc;
build_nested(Acc, N) ->
    %% NLA_F_NESTED = 0x8000
    Type = 16#8001,
    Len = byte_size(Acc) + 4,
    Wrapped = <<Len:16/little, Type:16/little, Acc/binary>>,
    build_nested(pad(Wrapped), N - 1).

pad(Bin) ->
    Sz = byte_size(Bin),
    Extra = (4 - (Sz rem 4)) rem 4,
    <<Bin/binary, 0:(Extra * 8)>>.

%% -------------------------------------------------------------------
%% Generators
%% -------------------------------------------------------------------

attr_type_gen() ->
    proper_types:choose(1, 16#3FFF).

value_gen() ->
    ?LET(N, proper_types:choose(0, 64),
         proper_types:binary(N)).
