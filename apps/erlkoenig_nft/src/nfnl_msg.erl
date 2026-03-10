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

-module(nfnl_msg).
-moduledoc """
Netlink message header construction for nf_tables.

Builds the two-part header that precedes every nf_tables message:

    nlmsghdr (16 bytes):
        <<Length:32/little, Type:16/little, Flags:16/little,
          Seq:32/little, PortId:32/little>>

    nfgenmsg (4 bytes):
        <<Family:8, Version:8, ResourceId:16/big>>

The message type encodes the subsystem in the upper 8 bits:
    Type = (NFNL_SUBSYS_NFTABLES bsl 8) bor MsgType

Batch begin/end are special control messages from subsystem 0
that tell the kernel to process enclosed messages atomically.
""".

-export([build_hdr/5,
         batch_begin/1,
         batch_end/1]).

-export_type([nl_msg/0]).

%% --- Types ---

-type nl_msg() :: binary().
%% A complete netlink message: nlmsghdr + nfgenmsg + attributes.

%% --- Constants ---

-define(NLMSGHDR_SIZE, 16).
-define(NFGENMSG_SIZE, 4).

-define(NFNL_SUBSYS_NFTABLES, 10).
-define(NFNL_SUBSYS_NONE,      0).

-define(NFNL_MSG_BATCH_BEGIN, 16).
-define(NFNL_MSG_BATCH_END,   17).

-define(NLM_F_REQUEST, 16#0001).

-define(NFNETLINK_V0, 0).

%% --- Public API ---

-doc """
Build a complete nf_tables netlink message.

MsgType is the NFT_MSG_* value (0=NEWTABLE, 3=NEWCHAIN, 6=NEWRULE, ...).
Family is the protocol family (1=inet, 2=ipv4, 10=ipv6).
Flags is a bitmask of NLM_F_* values.
Attrs is the pre-encoded attribute binary from nfnl_attr.
""".
-spec build_hdr(0..255, 0..255, non_neg_integer(), non_neg_integer(), binary()) -> nl_msg().
build_hdr(MsgType, Family, Flags, Seq, Attrs)
  when is_integer(MsgType), is_integer(Family),
       is_integer(Flags), is_integer(Seq), is_binary(Attrs) ->
    Type = (?NFNL_SUBSYS_NFTABLES bsl 8) bor MsgType,
    NfGenMsg = <<Family:8, ?NFNETLINK_V0:8, 0:16/big>>,
    Len = ?NLMSGHDR_SIZE + ?NFGENMSG_SIZE + byte_size(Attrs),
    <<Len:32/little, Type:16/little, Flags:16/little,
      Seq:32/little, 0:32/little, NfGenMsg/binary, Attrs/binary>>.

-doc """
Build a batch begin control message.

Must precede any group of nf_tables messages. The kernel processes
all messages between batch_begin and batch_end atomically.
""".
-spec batch_begin(non_neg_integer()) -> nl_msg().
batch_begin(Seq) ->
    batch_ctrl(?NFNL_MSG_BATCH_BEGIN, Seq).

-doc "Build a batch end control message.".
-spec batch_end(non_neg_integer()) -> nl_msg().
batch_end(Seq) ->
    batch_ctrl(?NFNL_MSG_BATCH_END, Seq).

%% --- Internal ---

-spec batch_ctrl(0..255, non_neg_integer()) -> nl_msg().
batch_ctrl(MsgType, Seq) ->
    Type = (?NFNL_SUBSYS_NONE bsl 8) bor MsgType,
    NfGenMsg = <<0:8, ?NFNETLINK_V0:8, ?NFNL_SUBSYS_NFTABLES:16/big>>,
    Len = ?NLMSGHDR_SIZE + ?NFGENMSG_SIZE,
    <<Len:32/little, Type:16/little, ?NLM_F_REQUEST:16/little,
      Seq:32/little, 0:32/little, NfGenMsg/binary>>.
