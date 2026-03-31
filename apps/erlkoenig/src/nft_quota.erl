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

-module(nft_quota).
-moduledoc """
nf_tables named quota object operations.

Creates named quota objects at the table level. Quotas enforce
byte-count thresholds — either "until" (match while under the
limit) or "over" (match when the limit has been exceeded).

Named quotas are independent of rules and can be referenced by
multiple rules simultaneously via objref expressions.

Usage:
    %% Create a named quota (1 GB, mode=until)
    nft_quota:add(1, <<"fw">>, <<"bandwidth">>,
        #{bytes => 1073741824, flags => 0}, Seq)

    %% Create a named quota (500 MB, mode=over)
    nft_quota:add(1, <<"fw">>, <<"excess">>,
        #{bytes => 524288000, flags => 1}, Seq)
""".

-export([add/5]).

-include("nft_constants.hrl").

%% --- Public API ---

-doc """
Create a named quota object.

Opts must contain:
  - bytes: non_neg_integer() — byte threshold
  - flags: 0 = until (match while under), 1 = over (match when exceeded)

Example:
    Msg = nft_quota:add(1, <<"fw">>, <<"bandwidth">>,
        #{bytes => 1073741824, flags => 0}, Seq)
""".
-spec add(
    0..255,
    binary(),
    binary(),
    #{bytes := non_neg_integer(), flags := non_neg_integer()},
    non_neg_integer()
) ->
    nfnl_msg:nl_msg().
add(Family, Table, Name, #{bytes := Bytes, flags := Flags}, Seq) ->
    QuotaData = iolist_to_binary([
        nfnl_attr:encode_u64(?NFTA_QUOTA_BYTES, Bytes),
        nfnl_attr:encode_u32(?NFTA_QUOTA_FLAGS, Flags)
    ]),
    Attrs = iolist_to_binary([
        nfnl_attr:encode_str(?NFTA_OBJ_TABLE, Table),
        nfnl_attr:encode_str(?NFTA_OBJ_NAME, Name),
        nfnl_attr:encode_u32(?NFTA_OBJ_TYPE, ?NFT_OBJECT_QUOTA),
        nfnl_attr:encode_nested(?NFTA_OBJ_DATA, QuotaData)
    ]),
    NlFlags = ?NLM_F_REQUEST bor ?NLM_F_ACK bor ?NLM_F_CREATE,
    nfnl_msg:build_hdr(?NFT_MSG_NEWOBJ, Family, NlFlags, Seq, Attrs).
