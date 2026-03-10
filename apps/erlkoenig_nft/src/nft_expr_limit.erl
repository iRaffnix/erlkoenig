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

-module(nft_expr_limit).
-moduledoc """
nf_tables limit expression.

Implements token-bucket rate limiting in the kernel. The kernel
drops (or accepts, with NFT_LIMIT_F_INV) packets that exceed the
configured rate.

Two limit types:
  - pkts:  rate is packets per unit time
  - bytes: rate is bytes per unit time

The unit is specified in seconds:
  - 1     = per second
  - 60    = per minute
  - 3600  = per hour
  - 86400 = per day

Usage:
    %% Accept up to 25 packets/second, burst 5
    nft_expr_limit:pps(25, 5)

    %% Accept up to 1024 bytes/second, burst 512
    nft_expr_limit:bps(1024, 512)

    %% Drop if exceeding 100 pps (inverted — match means "over limit")
    nft_expr_limit:over_pps(100, 5)

    %% Full control: 50 packets per minute, burst 10
    nft_expr_limit:new(#{rate => 50, unit => 60, burst => 10,
                         type => pkts})

Corresponds to libnftnl src/expr/limit.c.
""".

-export([new/1,
         pps/2,
         bps/2,
         over_pps/2,
         over_bps/2]).

-include("nft_constants.hrl").

%% --- Local attribute constants ---

-define(NFTA_LIMIT_RATE,  1).
-define(NFTA_LIMIT_UNIT,  2).
-define(NFTA_LIMIT_BURST, 3).
-define(NFTA_LIMIT_TYPE,  4).
-define(NFTA_LIMIT_FLAGS, 5).

%% --- Public API ---

-doc """
Build a limit expression with full control.

Options:
    #{rate  => 25,         %% tokens per unit (required)
      unit  => 1,          %% seconds (default: 1 = per second)
      burst => 5,          %% burst allowance (default: 5)
      type  => pkts,       %% pkts | bytes (default: pkts)
      inv   => false}      %% true = match when OVER limit
""".
-spec new(map()) -> binary().
new(Opts) ->
    Rate  = maps:get(rate, Opts),
    Unit  = maps:get(unit, Opts, 1),
    Burst = maps:get(burst, Opts, 5),
    Type  = limit_type(maps:get(type, Opts, pkts)),
    Inv   = maps:get(inv, Opts, false),
    Flags = case Inv of true -> ?NFT_LIMIT_F_INV; false -> 0 end,

    Attrs = iolist_to_binary([
        nfnl_attr:encode_u64(?NFTA_LIMIT_RATE, Rate),
        nfnl_attr:encode_u64(?NFTA_LIMIT_UNIT, Unit),
        nfnl_attr:encode_u32(?NFTA_LIMIT_BURST, Burst),
        nfnl_attr:encode_u32(?NFTA_LIMIT_TYPE, Type),
        nfnl_attr:encode_u32(?NFTA_LIMIT_FLAGS, Flags)
    ]),
    nft_expr:build(<<"limit">>, Attrs).

-doc """
Accept up to Rate packets per second with Burst allowance.

    nft_expr_limit:pps(25, 5)
    %% => "limit rate 25/second burst 5 packets"
""".
-spec pps(pos_integer(), non_neg_integer()) -> binary().
pps(Rate, Burst) ->
    new(#{rate => Rate, unit => 1, burst => Burst, type => pkts}).

-doc """
Accept up to Rate bytes per second with Burst allowance.

    nft_expr_limit:bps(10240, 1024)
    %% => "limit rate 10240 bytes/second burst 1024 bytes"
""".
-spec bps(pos_integer(), non_neg_integer()) -> binary().
bps(Rate, Burst) ->
    new(#{rate => Rate, unit => 1, burst => Burst, type => bytes}).

-doc """
Match when exceeding Rate packets/second (inverted limit).

Use this before a drop verdict to drop excess traffic:
    [nft_expr_limit:over_pps(100, 5), nft_expr_immediate:drop()]
""".
-spec over_pps(pos_integer(), non_neg_integer()) -> binary().
over_pps(Rate, Burst) ->
    new(#{rate => Rate, unit => 1, burst => Burst, type => pkts, inv => true}).

-doc """
Match when exceeding Rate bytes/second (inverted limit).
""".
-spec over_bps(pos_integer(), non_neg_integer()) -> binary().
over_bps(Rate, Burst) ->
    new(#{rate => Rate, unit => 1, burst => Burst, type => bytes, inv => true}).

%% --- Internal ---

-spec limit_type(pkts | bytes) -> non_neg_integer().
limit_type(pkts)  -> ?NFT_LIMIT_PKTS;
limit_type(bytes) -> ?NFT_LIMIT_PKT_BYTES.
