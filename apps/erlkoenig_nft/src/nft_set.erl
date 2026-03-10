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

-module(nft_set).
-moduledoc """
nf_tables set operations.

A set is a collection of elements used for efficient matching.
Instead of creating one rule per IP address, you create a set and
use a lookup expression to check membership.

Set types (from nftables datatypes.h):
    ipv4_addr   (7)   IPv4 addresses, key_len=4
    ipv6_addr   (8)   IPv6 addresses, key_len=16
    ether_addr  (9)   MAC addresses, key_len=6
    inet_proto  (12)  IP protocol numbers, key_len=1
    inet_service(13)  TCP/UDP ports, key_len=2
    mark        (19)  Packet marks, key_len=4

Set flags (NFTA_SET_FLAGS):
    NFT_SET_ANONYMOUS  = 0x01  System-generated name
    NFT_SET_CONSTANT   = 0x02  Elements cannot change
    NFT_SET_INTERVAL   = 0x04  Set contains intervals
    NFT_SET_MAP        = 0x08  Set is a map (key → value)
    NFT_SET_TIMEOUT    = 0x10  Elements have timeouts
    NFT_SET_EVAL       = 0x20  Set contains expressions

The set ID is a client-side identifier used to reference the set
within the same batch before the kernel assigns a handle. It must
be unique within a batch.

Corresponds to libnftnl src/set.c.
""".

-export([add/3]).

-export_type([set_opts/0, set_type/0]).

%% --- Types ---

-type set_type() :: ipv4_addr | ipv6_addr | ether_addr
                  | inet_proto | inet_service | mark
                  | non_neg_integer().

-type set_opts() :: #{
    table    := binary(),
    name     := binary(),
    type     := set_type(),
    flags    => [atom()],
    id       => non_neg_integer(),
    timeout  => non_neg_integer()   %% milliseconds
}.

%% --- Constants ---

-define(NFT_MSG_NEWSET, 9).

-define(NFTA_SET_TABLE,      1).
-define(NFTA_SET_NAME,       2).
-define(NFTA_SET_FLAGS,      3).
-define(NFTA_SET_KEY_TYPE,   4).
-define(NFTA_SET_KEY_LEN,    5).
-define(NFTA_SET_DATA_TYPE,  7).
-define(NFTA_SET_DATA_LEN,   8).
-define(NFTA_SET_ID,        10).
-define(NFTA_SET_TIMEOUT,   11).

%% Set flags
-define(NFT_SET_ANONYMOUS, 16#01).
-define(NFT_SET_CONSTANT,  16#02).
-define(NFT_SET_INTERVAL,  16#04).
-define(NFT_SET_MAP,       16#08).
-define(NFT_SET_TIMEOUT,   16#10).
-define(NFT_SET_EVAL,      16#20).

-define(NLM_F_REQUEST, 16#0001).
-define(NLM_F_ACK,     16#0004).
-define(NLM_F_CREATE,  16#0400).

%% --- Public API ---

-doc """
Build a NEWSET message.

Creates a named set in the given table. The set type determines
the key format and length.

Example:
    Msg = nft_set:add(1, #{
        table => <<"fw">>,
        name  => <<"banned">>,
        type  => ipv4_addr,
        flags => [timeout],
        timeout => 3600000,
        id    => 1
    }, Seq).
""".
-spec add(0..255, set_opts(), non_neg_integer()) -> nfnl_msg:nl_msg().
add(Family, Opts, Seq) when is_map(Opts), is_integer(Seq), Seq >= 0 ->
    Table   = maps:get(table, Opts),
    Name    = maps:get(name, Opts),
    Type    = maps:get(type, Opts),
    Flags   = maps:get(flags, Opts, []),
    Id      = maps:get(id, Opts, 1),
    Timeout = maps:get(timeout, Opts, undefined),

    {KeyType, KeyLen} = type_info(Type),
    FlagVal = encode_flags(Flags),

    Attrs = iolist_to_binary(lists:flatten([
        nfnl_attr:encode_str(?NFTA_SET_TABLE, Table),
        nfnl_attr:encode_str(?NFTA_SET_NAME, Name),
        nfnl_attr:encode_u32(?NFTA_SET_FLAGS, FlagVal),
        nfnl_attr:encode_u32(?NFTA_SET_KEY_TYPE, KeyType),
        nfnl_attr:encode_u32(?NFTA_SET_KEY_LEN, KeyLen),
        nfnl_attr:encode_u32(?NFTA_SET_ID, Id),
        case Timeout of
            undefined -> [];
            Ms -> [nfnl_attr:encode_u64(?NFTA_SET_TIMEOUT, Ms)]
        end
    ])),

    NlFlags = ?NLM_F_REQUEST bor ?NLM_F_ACK bor ?NLM_F_CREATE,
    nfnl_msg:build_hdr(?NFT_MSG_NEWSET, Family, NlFlags, Seq, Attrs).

%% --- Internal ---

-spec type_info(set_type()) -> {non_neg_integer(), non_neg_integer()}.
type_info(ipv4_addr)    -> {7,  4};
type_info(ipv6_addr)    -> {8,  16};
type_info(ether_addr)   -> {9,  6};
type_info(inet_proto)   -> {12, 1};
type_info(inet_service) -> {13, 2};
type_info(mark)         -> {19, 4};
type_info(N) when is_integer(N) -> {N, 4}.

-spec encode_flags([atom()]) -> non_neg_integer().
encode_flags(Flags) ->
    lists:foldl(fun flag_val/2, 0, Flags).

-spec flag_val(atom(), non_neg_integer()) -> non_neg_integer().
flag_val(anonymous, Acc) -> Acc bor ?NFT_SET_ANONYMOUS;
flag_val(constant, Acc)  -> Acc bor ?NFT_SET_CONSTANT;
flag_val(interval, Acc)  -> Acc bor ?NFT_SET_INTERVAL;
flag_val(map, Acc)       -> Acc bor ?NFT_SET_MAP;
flag_val(timeout, Acc)   -> Acc bor ?NFT_SET_TIMEOUT;
flag_val(eval, Acc)      -> Acc bor ?NFT_SET_EVAL.
