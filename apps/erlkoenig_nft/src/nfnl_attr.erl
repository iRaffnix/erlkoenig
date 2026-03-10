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

-module(nfnl_attr).
-moduledoc """
Netlink Attribute (NLA) encoding and decoding.

This module implements the TLV (Type-Length-Value) format used by Netlink
for attribute serialization. Every nf_tables object (table, chain, rule,
expression) is built from these primitives.

Wire format of a single attribute:

    <<Length:16/little, Type:16/little, Data/binary, Padding/binary>>

Length includes the 4-byte header but not the padding.
Padding aligns to 4-byte boundaries.

Integer attributes use big-endian (network byte order), matching the
htonl()/htobe64() calls in libnftnl's build_payload functions.
""".

-export([encode/2,
         encode_str/2,
         encode_u32/2,
         encode_u64/2,
         encode_nested/2,
         decode/1]).

-export_type([nla_type/0, nla/0]).

%% --- Types ---

-type nla_type() :: 0..16#3FFF.
%% Attribute type, 14-bit range. The upper two bits are flags
%% (NLA_F_NESTED = 0x8000, NLA_F_NET_BYTEORDER = 0x4000).

-type nla() :: {nla_type(), binary()}
             | {nla_type(), nested, [nla()]}.
%% Decoded attribute. Nested attributes carry their children as a list.

%% --- Constants ---

-define(NLA_HEADER_SIZE, 4).
-define(NLA_ALIGNTO, 4).
-define(NLA_F_NESTED, 16#8000).

%% --- Encoding ---

-doc "Encode a raw attribute. Data is written as-is.".
-spec encode(nla_type(), binary()) -> binary().
encode(Type, Data) when is_integer(Type), Type >= 0, is_binary(Data) ->
    Len = ?NLA_HEADER_SIZE + byte_size(Data),
    <<Len:16/little, Type:16/little, Data/binary, (padding(Len))/binary>>.

-doc "Encode a null-terminated string attribute.".
-spec encode_str(nla_type(), binary()) -> binary().
encode_str(Type, Str) when is_binary(Str) ->
    encode(Type, <<Str/binary, 0>>).

-doc "Encode a 32-bit big-endian integer attribute (matches C htonl).".
-spec encode_u32(nla_type(), non_neg_integer()) -> binary().
encode_u32(Type, Val) when is_integer(Val), Val >= 0 ->
    encode(Type, <<Val:32/big>>).

-doc "Encode a 64-bit big-endian integer attribute (matches C htobe64).".
-spec encode_u64(nla_type(), non_neg_integer()) -> binary().
encode_u64(Type, Val) when is_integer(Val), Val >= 0 ->
    encode(Type, <<Val:64/big>>).

-doc "Encode a nested attribute. Sets the NLA_F_NESTED flag on the type.".
-spec encode_nested(nla_type(), binary()) -> binary().
encode_nested(Type, Children) when is_integer(Type), is_binary(Children) ->
    encode(Type bor ?NLA_F_NESTED, Children).

%% --- Decoding ---

-doc """
Decode a binary into a list of attributes.

Nested attributes (NLA_F_NESTED flag set) are recursively decoded.
Returns an empty list for empty input.
""".
-spec decode(binary()) -> [nla()].
decode(<<>>) ->
    [];
decode(<<Len:16/little, _Type:16/little, _/binary>> = Bin)
  when Len < ?NLA_HEADER_SIZE; Len > byte_size(Bin) + 0 ->
    error({invalid_nla, Len, byte_size(Bin)});
decode(<<Len:16/little, Type:16/little, Rest/binary>>) ->
    DataLen = Len - ?NLA_HEADER_SIZE,
    PadLen = pad_size(Len),
    <<Data:DataLen/binary, _Pad:PadLen/binary, Tail/binary>> = Rest,
    Attr = case Type band ?NLA_F_NESTED of
        ?NLA_F_NESTED ->
            {Type band 16#3FFF, nested, decode(Data)};
        0 ->
            {Type, Data}
    end,
    [Attr | decode(Tail)].

%% --- Internal ---

-spec padding(non_neg_integer()) -> binary().
padding(Len) ->
    case pad_size(Len) of
        0 -> <<>>;
        N -> <<0:(N * 8)>>
    end.

-spec pad_size(non_neg_integer()) -> 0..3.
pad_size(Len) ->
    case Len rem ?NLA_ALIGNTO of
        0 -> 0;
        R -> ?NLA_ALIGNTO - R
    end.
