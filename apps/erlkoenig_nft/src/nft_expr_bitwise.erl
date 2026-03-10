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

-module(nft_expr_bitwise).
-moduledoc """
nf_tables bitwise expression.

Performs bitwise operations on register contents:

    reg_dreg = (reg_sreg & mask) ^ xor

The most common use is masking bits for conntrack state matching:

    bitwise reg 1 = (reg 1 & 0x06) ^ 0x00

This masks the state register to only keep the ESTABLISHED and
RELATED bits, then XORs with 0 (no-op). A subsequent cmp neq 0x00
checks if either bit was set.

Corresponds to libnftnl src/expr/bitwise.c.
""".

-export([mask/4]).

%% --- Constants ---

-define(NFTA_BITWISE_SREG, 1).
-define(NFTA_BITWISE_DREG, 2).
-define(NFTA_BITWISE_LEN,  3).
-define(NFTA_BITWISE_MASK, 4).
-define(NFTA_BITWISE_XOR,  5).

-define(NFTA_DATA_VALUE, 1).

%% --- Public API ---

-doc """
Build a bitwise mask expression: dreg = (sreg & Mask) ^ Xor.

Mask and Xor must be binaries of the same length.

Example:
    %% Mask register 1 with 0x06 (established|related), no xor
    nft_expr_bitwise:mask(1, 1, <<0, 0, 0, 6>>, <<0, 0, 0, 0>>)
""".
-spec mask(non_neg_integer(), non_neg_integer(), binary(), binary()) -> binary().
mask(SReg, DReg, Mask, Xor)
  when is_integer(SReg), SReg >= 0,
       is_integer(DReg), DReg >= 0,
       is_binary(Mask), is_binary(Xor),
       byte_size(Mask) =:= byte_size(Xor) ->
    Len = byte_size(Mask),
    MaskNest = nfnl_attr:encode_nested(?NFTA_BITWISE_MASK,
        nfnl_attr:encode(?NFTA_DATA_VALUE, Mask)),
    XorNest = nfnl_attr:encode_nested(?NFTA_BITWISE_XOR,
        nfnl_attr:encode(?NFTA_DATA_VALUE, Xor)),
    Attrs = iolist_to_binary([
        nfnl_attr:encode_u32(?NFTA_BITWISE_SREG, SReg),
        nfnl_attr:encode_u32(?NFTA_BITWISE_DREG, DReg),
        nfnl_attr:encode_u32(?NFTA_BITWISE_LEN, Len),
        MaskNest,
        XorNest
    ]),
    nft_expr:build(<<"bitwise">>, Attrs).
