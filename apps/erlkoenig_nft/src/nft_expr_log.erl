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

-module(nft_expr_log).
-moduledoc """
nf_tables log expression.

Logs packet information to the kernel log (dmesg/syslog) or
to nflog for userspace consumption. Typically placed before a
drop verdict to record what was blocked.

    tcp dport 22 counter log prefix "SSH: " drop

Log attributes:
    prefix    Free-form string prepended to log entries (max 127 chars)
    group     NFLOG group number for userspace logging (0 = kernel log)
    snaplen   Bytes of packet to include in log
    level     Syslog level (0=emerg..7=debug), default 4=warning

When group > 0, packets are sent to NFLOG which can be captured
by userspace tools (ulogd2, or our own Erlang receiver later).

Corresponds to libnftnl src/expr/log.c.
""".

-export([new/1, new/0]).

-export_type([log_opts/0]).

%% --- Types ---

-type log_opts() :: #{
    prefix  => binary(),
    group   => non_neg_integer(),
    snaplen => non_neg_integer(),
    level   => 0..7
}.

%% --- Constants ---

-define(NFTA_LOG_GROUP,      1).
-define(NFTA_LOG_PREFIX,     2).
-define(NFTA_LOG_SNAPLEN,    3).
-define(NFTA_LOG_QTHRESHOLD, 4).
-define(NFTA_LOG_LEVEL,      5).
-define(NFTA_LOG_FLAGS,      6).

%% --- Public API ---

-doc "Add a log expression with default settings (kernel log, no prefix).".
-spec new() -> binary().
new() ->
    new(#{}).

-doc """
Add a log expression with options.

Example:
    %% Log to kernel with prefix
    nft_expr_log:new(#{prefix => <<"DROPPED: ">>})

    %% Log to NFLOG group 1 for userspace capture
    nft_expr_log:new(#{prefix => <<"FW: ">>, group => 1})
""".
-spec new(log_opts()) -> binary().
new(Opts) when is_map(Opts) ->
    Attrs = iolist_to_binary(lists:flatten([
        case maps:get(group, Opts, undefined) of
            undefined -> [];
            Group -> [nfnl_attr:encode(?NFTA_LOG_GROUP, <<Group:16/big>>)]
        end,
        case maps:get(prefix, Opts, undefined) of
            undefined -> [];
            Prefix -> [nfnl_attr:encode_str(?NFTA_LOG_PREFIX, Prefix)]
        end,
        case maps:get(snaplen, Opts, undefined) of
            undefined -> [];
            Snap -> [nfnl_attr:encode_u32(?NFTA_LOG_SNAPLEN, Snap)]
        end,
        case maps:get(level, Opts, undefined) of
            undefined -> [];
            Level -> [nfnl_attr:encode_u32(?NFTA_LOG_LEVEL, Level)]
        end
    ])),
    nft_expr:build(<<"log">>, Attrs).
