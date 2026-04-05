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

-module(erlkoenig_nft_ip).
-moduledoc """
Shared IP address utility module - single source of truth for
normalize/format/version across the entire codebase.

Handles both IPv4 and IPv6 addresses in all common representations:
tuples, binaries, strings, and binary strings.
""".

-export([normalize/1, format/1, version/1, af/1]).

-doc """
Normalize any IP representation to a fixed-size binary.
Returns {ok, 4-byte binary} for IPv4, {ok, 16-byte binary} for IPv6,
or {error, bad_ip} on failure.

Accepts:
  - 4-byte or 16-byte binary (pass-through)
  - {A,B,C,D} IPv4 tuple
  - {A,B,C,D,E,F,G,H} IPv6 tuple
  - "10.0.0.1" or "2001:db8::1" string
  - <<"10.0.0.1">> or <<"2001:db8::1">> binary string
""".
-spec normalize(term()) -> {ok, binary()} | {error, bad_ip}.
normalize(Bin) when is_binary(Bin), byte_size(Bin) =:= 4 ->
    {ok, Bin};
normalize(Bin) when is_binary(Bin), byte_size(Bin) =:= 16 ->
    {ok, Bin};
normalize({A, B, C, D}) when
    is_integer(A),
    is_integer(B),
    is_integer(C),
    is_integer(D)
->
    {ok, <<A, B, C, D>>};
normalize({A, B, C, D, E, F, G, H}) when
    is_integer(A),
    is_integer(B),
    is_integer(C),
    is_integer(D),
    is_integer(E),
    is_integer(F),
    is_integer(G),
    is_integer(H)
->
    {ok, <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>};
normalize(Str) when is_list(Str) ->
    case inet:parse_address(Str) of
        {ok, {A, B, C, D}} ->
            {ok, <<A, B, C, D>>};
        {ok, {A, B, C, D, E, F, G, H}} ->
            {ok, <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>};
        _ ->
            {error, bad_ip}
    end;
normalize(Str) when is_binary(Str) ->
    normalize(binary_to_list(Str));
normalize(_) ->
    {error, bad_ip}.

-doc """
Format a binary IP address as an iolist.
4-byte -> "A.B.C.D", 16-byte -> inet:ntoa with :: compression.
""".
-spec format(binary()) -> iolist().
format(<<A, B, C, D>>) ->
    io_lib:format("~B.~B.~B.~B", [A, B, C, D]);
format(<<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>) ->
    inet:ntoa({A, B, C, D, E, F, G, H}).

-doc "Return v4 for 4-byte binaries, v6 for 16-byte binaries.".
-spec version(binary()) -> v4 | v6.
version(Bin) when byte_size(Bin) =:= 4 -> v4;
version(Bin) when byte_size(Bin) =:= 16 -> v6.

-doc "Return the kernel address family: 2 (AF_INET) or 10 (AF_INET6).".
-spec af(binary()) -> 2 | 10.
af(Bin) when byte_size(Bin) =:= 4 -> 2;
af(Bin) when byte_size(Bin) =:= 16 -> 10.
