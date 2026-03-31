%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%

-module(nfnl_response).
-moduledoc """
Netlink response parser.

Parses kernel responses to nf_tables batch operations. The kernel
sends one NLMSG_ERROR per message in the batch. Error code 0 means
success (ACK), negative values are negated errno codes.

Response format:
    nlmsghdr (16 bytes)
      Type = NLMSG_ERROR (2)
      Seq  = sequence number of the original message
    error payload:
      <<ErrorCode:32/signed-little, OriginalHeader:16/binary>>

Common error codes:
    0    Success (ACK)
   -1    EPERM        No permission (need CAP_NET_ADMIN)
   -2    ENOENT       Object not found
  -17    EEXIST       Object already exists
  -22    EINVAL       Invalid argument (malformed message)
  -95    EOPNOTSUPP   Operation not supported
""".

-export([parse/1]).

-export_type([response/0, result/0]).

%% --- Types ---

-type result() :: ok | {error, {integer(), atom()}}.
%% Single message result: ok for ACK, {error, {Code, Name}} for failure.

-type response() :: [result()].
%% List of results, one per message in the batch.

%% --- Constants ---

-define(NLMSG_ERROR, 2).
-define(NLMSG_DONE, 3).

%% --- Public API ---

-doc """
Parse a binary containing one or more netlink response messages.

Returns a list of results in sequence order. Batch begin/end ACKs
are included. NLMSG_DONE messages are silently skipped.
""".
-spec parse(binary()) -> response().
parse(Bin) when is_binary(Bin) ->
    parse_messages(Bin, []).

%% --- Internal ---

-spec parse_messages(binary(), response()) -> response().
parse_messages(<<>>, Acc) ->
    lists:reverse(Acc);
parse_messages(
    <<Len:32/little, ?NLMSG_ERROR:16/little, _Flags:16/little, _Seq:32/little, _Pid:32/little,
        Error:32/signed-little, _Rest/binary>> = Bin,
    Acc
) when Len >= 20 ->
    Result =
        case Error of
            0 -> ok;
            N -> {error, {N, errno_name(N)}}
        end,
    <<_:Len/binary, Tail/binary>> = Bin,
    parse_messages(Tail, [Result | Acc]);
parse_messages(<<Len:32/little, ?NLMSG_DONE:16/little, _/binary>> = Bin, Acc) when
    Len >= 16
->
    <<_:Len/binary, Tail/binary>> = Bin,
    parse_messages(Tail, Acc);
parse_messages(<<Len:32/little, _Type:16/little, _/binary>> = Bin, Acc) when
    Len >= 16
->
    <<_:Len/binary, Tail/binary>> = Bin,
    parse_messages(Tail, Acc);
parse_messages(_Other, Acc) ->
    lists:reverse(Acc).

-spec errno_name(integer()) ->
    eacces | eexist | einval | enoent | enomem | enospc | eopnotsupp | eperm | unknown.
errno_name(-1) -> eperm;
errno_name(-2) -> enoent;
errno_name(-12) -> enomem;
errno_name(-13) -> eacces;
errno_name(-17) -> eexist;
errno_name(-22) -> einval;
errno_name(-28) -> enospc;
errno_name(-95) -> eopnotsupp;
errno_name(_) -> unknown.
