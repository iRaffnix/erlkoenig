%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%

%% Go binary analysis records
%% Reference: src/debug/buildinfo, src/internal/goarch in Go source

-ifndef(ELF_LANG_GO_HRL).
-define(ELF_LANG_GO_HRL, true).

-record(go_func, {
    %% e.g. <<"github.com/user/pkg.Function">>
    name :: binary(),
    %% absolute address
    entry :: non_neg_integer(),
    %% e.g. <<"github.com/user/pkg">>
    package :: binary()
}).

-record(go_dep, {
    %% e.g. <<"github.com/lib/pq">>
    path :: binary(),
    %% e.g. <<"v1.10.9">>
    version :: binary(),
    %% e.g. <<"h1:abc...">>
    hash :: binary()
}).

-record(go_info, {
    %% e.g. <<"go1.22.1">>
    version :: binary(),
    main_module :: binary() | undefined,
    mod_version :: binary() | undefined,
    deps :: [#go_dep{}],
    functions :: [#go_func{}],
    %% key-value from build lines
    build_settings :: [{binary(), binary()}],
    go_version_raw :: binary()
}).

-endif.
