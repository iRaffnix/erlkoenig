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

-export([add/3, add_meter/3, add_vmap/4, add_data_map/4, add_concat/3,
         add_concat_vmap/4]).

-export_type([set_opts/0, set_type/0, concat_opts/0]).

%% --- Types ---

-type set_type() ::
    ipv4_addr
    | ipv6_addr
    | ether_addr
    | inet_proto
    | inet_service
    | mark
    | non_neg_integer().

-type set_opts() :: #{
    table := binary(),
    name := binary(),
    type := set_type(),
    flags => [atom()],
    id => non_neg_integer(),
    %% milliseconds
    timeout => non_neg_integer()
}.

-type concat_opts() :: #{
    table := binary(),
    name := binary(),
    %% e.g. [ipv4_addr, inet_service]
    fields := [set_type()],
    flags => [atom()],
    id => non_neg_integer(),
    timeout => non_neg_integer()
}.

-include("nft_constants.hrl").

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
    Table = maps:get(table, Opts),
    Name = maps:get(name, Opts),
    Type = maps:get(type, Opts),
    Flags = maps:get(flags, Opts, []),
    Id = maps:get(id, Opts, 1),
    Timeout = maps:get(timeout, Opts, undefined),

    {KeyType, KeyLen} = type_info(Type),
    FlagVal = encode_flags(Flags),

    Attrs = iolist_to_binary(
        lists:flatten([
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
        ])
    ),

    NlFlags = ?NLM_F_REQUEST bor ?NLM_F_ACK bor ?NLM_F_CREATE,
    nfnl_msg:build_hdr(?NFT_MSG_NEWSET, Family, NlFlags, Seq, Attrs).

-doc """
Build a NEWSET message for a meter (dynamic set with per-element expressions).

Meters are named sets with the NFT_SET_EVAL flag, used for per-key
rate limiting (e.g., per-source-IP). The dynset expression in the rule
adds/updates elements with attached limit expressions.

Example:
    Msg = nft_set:add_meter(1, #{
        table => <<"fw">>,
        name  => <<"ssh_meter">>,
        type  => ipv4_addr,
        id    => 2
    }, Seq).
""".
-spec add_meter(0..255, set_opts(), non_neg_integer()) -> nfnl_msg:nl_msg().
add_meter(Family, Opts, Seq) ->
    Flags0 = maps:get(flags, Opts, []),
    MeterFlags = lists:usort([eval | Flags0]),
    add(Family, Opts#{flags => MeterFlags}, Seq).

-doc """
Build a NEWSET message for a verdict map.

A verdict map maps keys to verdicts (accept/drop/jump/goto).
It has the NFT_SET_MAP flag set and uses NFT_DATA_VERDICT as
the data type.

Example:
    Msg = nft_set:add_vmap(1, #{
        table => <<"fw">>,
        name  => <<"port_dispatch">>,
        type  => inet_service,
        id    => 2
    }, Seq).
""".
-spec add_vmap(0..255, set_opts(), non_neg_integer(), non_neg_integer()) ->
    nfnl_msg:nl_msg().
add_vmap(Family, Opts, Id, Seq) when is_map(Opts), is_integer(Seq), Seq >= 0 ->
    Table = maps:get(table, Opts),
    Name = maps:get(name, Opts),
    Type = maps:get(type, Opts),

    {KeyType, KeyLen} = type_info(Type),
    FlagVal = ?NFT_SET_MAP,

    Attrs = iolist_to_binary(
        lists:flatten([
            nfnl_attr:encode_str(?NFTA_SET_TABLE, Table),
            nfnl_attr:encode_str(?NFTA_SET_NAME, Name),
            nfnl_attr:encode_u32(?NFTA_SET_FLAGS, FlagVal),
            nfnl_attr:encode_u32(?NFTA_SET_KEY_TYPE, KeyType),
            nfnl_attr:encode_u32(?NFTA_SET_KEY_LEN, KeyLen),
            nfnl_attr:encode_u32(?NFTA_SET_DATA_TYPE, ?NFT_DATA_VERDICT),
            nfnl_attr:encode_u32(?NFTA_SET_ID, Id)
        ])
    ),

    NlFlags = ?NLM_F_REQUEST bor ?NLM_F_ACK bor ?NLM_F_CREATE,
    nfnl_msg:build_hdr(?NFT_MSG_NEWSET, Family, NlFlags, Seq, Attrs).

-doc """
Build a NEWSET message for a data map (key → data value).

Unlike verdict maps (key → accept/drop/jump), data maps store
actual values (e.g., IP addresses) that can be loaded into registers
for subsequent expressions like DNAT.

Used for jhash loadbalancing: hash result (integer) → container IP.

Example:
    Msg = nft_set:add_data_map(1, #{
        table     => <<"erlkoenig">>,
        name      => <<"__lb_web_nginx">>,
        key_type  => 0,       %% integer (NFT_TYPE_UNKNOWN works for plain u32)
        key_len   => 4,       %% u32
        data_type => ipv4_addr,
        id        => 3
    }, 3, Seq).
""".
-spec add_data_map(0..255, map(), non_neg_integer(), non_neg_integer()) ->
    nfnl_msg:nl_msg().
add_data_map(Family, Opts, Id, Seq) when is_map(Opts), is_integer(Seq), Seq >= 0 ->
    Table = maps:get(table, Opts),
    Name = maps:get(name, Opts),
    KeyType = maps:get(key_type, Opts, 0),
    KeyLen = maps:get(key_len, Opts, 4),
    DataType = maps:get(data_type, Opts),
    {DataTypeVal, DataLen} = type_info(DataType),

    FlagVal = ?NFT_SET_MAP,

    Attrs = iolist_to_binary(
        lists:flatten([
            nfnl_attr:encode_str(?NFTA_SET_TABLE, Table),
            nfnl_attr:encode_str(?NFTA_SET_NAME, Name),
            nfnl_attr:encode_u32(?NFTA_SET_FLAGS, FlagVal),
            nfnl_attr:encode_u32(?NFTA_SET_KEY_TYPE, KeyType),
            nfnl_attr:encode_u32(?NFTA_SET_KEY_LEN, KeyLen),
            nfnl_attr:encode_u32(?NFTA_SET_DATA_TYPE, DataTypeVal),
            nfnl_attr:encode_u32(?NFTA_SET_DATA_LEN, DataLen),
            nfnl_attr:encode_u32(?NFTA_SET_ID, Id)
        ])
    ),

    NlFlags = ?NLM_F_REQUEST bor ?NLM_F_ACK bor ?NLM_F_CREATE,
    nfnl_msg:build_hdr(?NFT_MSG_NEWSET, Family, NlFlags, Seq, Attrs).

-doc """
Build a NEWSET message for a concatenated set.

Concatenated sets allow composite keys: e.g., ip saddr . tcp dport.
A single O(1) lookup matches multiple fields simultaneously.

Fields is a list of set types whose key lengths are summed to form
the total key length. The NFTA_SET_DESC_CONCAT attribute describes
each field's length for the kernel.

Example:
    Msg = nft_set:add_concat(1, #{
        table  => <<"fw">>,
        name   => <<"allowpairs">>,
        fields => [ipv4_addr, inet_service],
        id     => 2
    }, Seq).
""".
-spec add_concat(0..255, concat_opts(), non_neg_integer()) -> nfnl_msg:nl_msg().
add_concat(Family, Opts, Seq) when is_map(Opts), is_integer(Seq), Seq >= 0 ->
    Table = maps:get(table, Opts),
    Name = maps:get(name, Opts),
    Fields = maps:get(fields, Opts),
    Flags = maps:get(flags, Opts, []),
    Id = maps:get(id, Opts, 1),
    Timeout = maps:get(timeout, Opts, undefined),

    %% Compute total key length and concat key type
    FieldInfos = [type_info(F) || F <- Fields],
    %% Kernel requires 4-byte aligned field lengths for concat keys
    TotalKeyLen = lists:sum([align4(Len) || {_Type, Len} <- FieldInfos]),
    %% For concat sets, key type is a hash of the field types.
    %% The kernel uses a composite type: we concatenate the type IDs.
    %% In practice, nftables uses a hash, but setting 0 works for named sets.
    KeyType = concat_key_type(FieldInfos),

    FlagVal = encode_flags(Flags) bor ?NFT_SET_CONCAT,

    %% Build NFTA_SET_DESC_CONCAT: NFTA_LIST_ELEM entries wrapping field lengths
    ConcatFields = iolist_to_binary([
        nfnl_attr:encode_nested(
            1,  %% NFTA_LIST_ELEM
            nfnl_attr:encode_u32(?NFTA_SET_FIELD_LEN, Len)
        )
     || {_Type, Len} <- FieldInfos
    ]),
    DescAttrs = nfnl_attr:encode_nested(?NFTA_SET_DESC_CONCAT, ConcatFields),
    SetDesc = nfnl_attr:encode_nested(?NFTA_SET_DESC, DescAttrs),

    Attrs = iolist_to_binary(
        lists:flatten([
            nfnl_attr:encode_str(?NFTA_SET_TABLE, Table),
            nfnl_attr:encode_str(?NFTA_SET_NAME, Name),
            nfnl_attr:encode_u32(?NFTA_SET_FLAGS, FlagVal),
            nfnl_attr:encode_u32(?NFTA_SET_KEY_TYPE, KeyType),
            nfnl_attr:encode_u32(?NFTA_SET_KEY_LEN, TotalKeyLen),
            nfnl_attr:encode_u32(?NFTA_SET_ID, Id),
            SetDesc,
            case Timeout of
                undefined -> [];
                Ms -> [nfnl_attr:encode_u64(?NFTA_SET_TIMEOUT, Ms)]
            end
        ])
    ),

    NlFlags = ?NLM_F_REQUEST bor ?NLM_F_ACK bor ?NLM_F_CREATE,
    nfnl_msg:build_hdr(?NFT_MSG_NEWSET, Family, NlFlags, Seq, Attrs).

-doc """
Build a NEWSET message for a concatenated verdict map.

Combines concatenated keys (e.g., ip saddr . ip daddr . tcp dport)
with verdict values (accept/drop/jump/goto). This replaces long chains
of individual rules with a single O(1) lookup.

Example:
    Msg = nft_set:add_concat_vmap(1, #{
        table  => <<"erlkoenig">>,
        name   => <<"fwd_policy">>,
        fields => [ipv4_addr, ipv4_addr, inet_service],
        id     => 50
    }, 50, Seq).
""".
-spec add_concat_vmap(0..255, concat_opts(), non_neg_integer(), non_neg_integer()) ->
    nfnl_msg:nl_msg().
add_concat_vmap(Family, Opts, Id, Seq) when is_map(Opts), is_integer(Seq), Seq >= 0 ->
    Table = maps:get(table, Opts),
    Name = maps:get(name, Opts),
    Fields = maps:get(fields, Opts),

    FieldInfos = [type_info(F) || F <- Fields],
    TotalKeyLen = lists:sum([align4(Len) || {_Type, Len} <- FieldInfos]),
    KeyType = concat_key_type(FieldInfos),

    FlagVal = ?NFT_SET_MAP,

    %% Kernel 6.12 + nft CLI 1.1.x: concat field descriptors are encoded
    %% as NFTA_SET_USERDATA (type 13), NOT as NFTA_SET_DESC + DESC_CONCAT.
    %% The DESC_CONCAT format exists only in nf-next (bleeding edge).
    %% USERDATA uses a libnftnl-specific TLV format: 1-byte type, 1-byte len.
    UserData = build_concat_userdata(FieldInfos),

    Attrs = iolist_to_binary(
        lists:flatten([
            nfnl_attr:encode_str(?NFTA_SET_TABLE, Table),
            nfnl_attr:encode_str(?NFTA_SET_NAME, Name),
            nfnl_attr:encode_u32(?NFTA_SET_FLAGS, FlagVal),
            nfnl_attr:encode_u32(?NFTA_SET_KEY_TYPE, KeyType),
            nfnl_attr:encode_u32(?NFTA_SET_KEY_LEN, TotalKeyLen),
            nfnl_attr:encode_u32(?NFTA_SET_DATA_TYPE, ?NFT_DATA_VERDICT),
            nfnl_attr:encode_u32(7, 0),  %% NFTA_SET_DATA_LEN
            nfnl_attr:encode_u32(?NFTA_SET_ID, Id),
            nfnl_attr:encode(13, UserData)  %% NFTA_SET_USERDATA
        ])
    ),

    NlFlags = ?NLM_F_REQUEST bor ?NLM_F_ACK bor ?NLM_F_CREATE,
    nfnl_msg:build_hdr(?NFT_MSG_NEWSET, Family, NlFlags, Seq, Attrs).

%% --- Internal ---

-spec type_info(set_type()) -> {non_neg_integer(), non_neg_integer()}.
type_info(ipv4_addr) -> {7, 4};
type_info(ipv6_addr) -> {8, 16};
type_info(ether_addr) -> {9, 6};
type_info(inet_proto) -> {12, 1};
type_info(inet_service) -> {13, 2};
type_info(mark) -> {19, 4};
type_info(N) when is_integer(N) -> {N, 4}.

-spec encode_flags([atom()]) -> non_neg_integer().
encode_flags(Flags) ->
    lists:foldl(fun flag_val/2, 0, Flags).

-spec flag_val(atom(), non_neg_integer()) -> non_neg_integer().
flag_val(anonymous, Acc) -> Acc bor ?NFT_SET_ANONYMOUS;
flag_val(constant, Acc) -> Acc bor ?NFT_SET_CONSTANT;
flag_val(interval, Acc) -> Acc bor ?NFT_SET_INTERVAL;
flag_val(map, Acc) -> Acc bor ?NFT_SET_MAP;
flag_val(timeout, Acc) -> Acc bor ?NFT_SET_TIMEOUT;
flag_val(eval, Acc) -> Acc bor ?NFT_SET_EVAL;
flag_val(concat, Acc) -> Acc bor ?NFT_SET_CONCAT.

%% Build a composite key type for concatenated sets.
%% The kernel uses: key_type = type1 | (type2 << 8) | (type3 << 16) ...
%% This matches libnftnl's nftnl_set_concat_hash().
-spec concat_key_type([{non_neg_integer(), 1 | 2 | 4 | 6 | 16}]) -> non_neg_integer().
concat_key_type(FieldInfos) ->
    concat_key_type(FieldInfos, 0, 0).

concat_key_type([], _Shift, Acc) ->
    Acc;
concat_key_type([{Type, _Len} | Rest], Shift, Acc) ->
    concat_key_type(Rest, Shift + 8, Acc bor (Type bsl Shift)).

-spec align4(non_neg_integer()) -> non_neg_integer().
align4(N) -> ((N + 3) div 4) * 4.

%% Build libnftnl USERDATA for concatenated verdict maps.
%%
%% nft CLI + libnftnl 1.2.9 encode concat field descriptors as
%% NFTA_SET_USERDATA (attribute 13) using a TLV format (1-byte type,
%% 1-byte len). The nft CLI source (libnftnl/src/set.c) generates
%% this via nftnl_set_nlmsg_build_payload → NFTA_SET_USERDATA.
%%
%% The USERDATA contains typeof information that allows nft to
%% reconstruct the field types when listing the set.
%%
%% Verified by reading libnftnl 1.2.9 source and strace capture.
-spec build_concat_userdata([{non_neg_integer(), non_neg_integer()}]) -> binary().
build_concat_userdata(FieldInfos) ->
    %% Build the typeof expression chain from libnftnl udata format.
    %% Source: libnftnl/src/udata.c, nftnl_udata_put()
    %% Each entry: <<Type:8, Len:8, Data:Len/binary>>
    KeyTypeof = build_key_typeof(FieldInfos),
    DataTypeof = build_data_typeof_verdict(),
    iolist_to_binary([
        udata_entry(0, <<0:32/little>>),       %% KEYBYTEORDER = host
        udata_entry(1, <<0:32/little>>),        %% DATABYTEORDER = host
        udata_entry(3, KeyTypeof),              %% KEY_TYPEOF
        udata_entry(4, DataTypeof),             %% DATA_TYPEOF
        udata_entry(6, <<0:32/little>>)         %% MERGE_ELEMENTS = 0
    ]).

udata_entry(Type, Data) ->
    <<Type:8, (byte_size(Data)):8, Data/binary>>.

%% Build KEY_TYPEOF from libnftnl typeof serialization.
%% Source: libnftnl/src/set.c → set_build_udata_key()
%% Uses nftnl_udata_put for each expression in the typeof chain.
%% For concat: one expression per field, each with:
%%   type=0: expr_name hash (4 bytes LE)
%%   type=1: serialized expression attributes
build_key_typeof(FieldInfos) ->
    iolist_to_binary([typeof_field_entry(F) || F <- FieldInfos]).

typeof_field_entry({ipv4_addr, _}) ->
    <<(udata_entry(0, <<16#0d:32/little>>))/binary,
      (udata_entry(1, <<0, 0, 0, 4>>))/binary>>;
typeof_field_entry({ipv6_addr, _}) ->
    <<(udata_entry(0, <<16#0d:32/little>>))/binary,
      (udata_entry(1, <<0, 0, 0, 16>>))/binary>>;
typeof_field_entry({inet_service, _}) ->
    <<(udata_entry(0, <<16#04:32/little>>))/binary,
      (udata_entry(1, <<0, 0, 0, 0, 1, 0>>))/binary>>;
typeof_field_entry({mark, _}) ->
    <<(udata_entry(0, <<16#04:32/little>>))/binary,
      (udata_entry(1, <<0, 0, 0, 4>>))/binary>>;
typeof_field_entry({_Type, Len}) ->
    <<(udata_entry(0, <<16#04:32/little>>))/binary,
      (udata_entry(1, <<0, 0, 0, Len>>))/binary>>.

build_data_typeof_verdict() ->
    <<(udata_entry(0, <<16#04:32/little>>))/binary,
      (udata_entry(1, <<>>))/binary>>.
