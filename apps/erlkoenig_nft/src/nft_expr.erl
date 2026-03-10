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

-module(nft_expr).
-export([build/2]).

-define(NFTA_EXPR_NAME, 1).
-define(NFTA_EXPR_DATA, 2).

-spec build(binary(), binary()) -> binary().
build(Name, Attrs) when is_binary(Name), is_binary(Attrs) ->
    iolist_to_binary([
        nfnl_attr:encode_str(?NFTA_EXPR_NAME, Name),
        nfnl_attr:encode_nested(?NFTA_EXPR_DATA, Attrs)
    ]).
