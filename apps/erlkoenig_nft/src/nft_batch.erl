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

-module(nft_batch).
-moduledoc """
Netlink batch wrapping for atomic nf_tables operations.

The kernel processes all messages between batch_begin and batch_end
as a single atomic transaction. If any message fails, the entire
batch is rolled back.

Usage:
    Msgs = [nft_table:add(...), nft_chain:add(...), nft_rule:add(...)],
    Batch = nft_batch:wrap(Msgs, Seq),
    ok = nfnl_socket:send(Sock, Batch).
""".

-export([wrap/2]).

%% --- Public API ---

-doc """
Wrap a list of nf_tables messages in batch begin/end.

Seq is the starting sequence number. Each message should already
carry its own sequence number. The batch_begin gets Seq and
batch_end gets Seq + length(Messages) + 1 to avoid collisions.
""".
-spec wrap([nfnl_msg:nl_msg()], non_neg_integer()) -> binary().
wrap(Messages, Seq) when is_list(Messages), is_integer(Seq), Seq >= 0 ->
    iolist_to_binary([
        nfnl_msg:batch_begin(Seq),
        Messages,
        nfnl_msg:batch_end(Seq + length(Messages) + 1)
    ]).
