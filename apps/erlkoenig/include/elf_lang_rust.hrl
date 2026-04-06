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

%% Rust binary analysis records

-ifndef(ELF_LANG_RUST_HRL).
-define(ELF_LANG_RUST_HRL, true).

-record(rust_crate, {
    name :: binary(),
    version :: binary() | unknown,
    source :: symtab | panic_strings | comment
}).

-record(rust_info, {
    crates :: [#rust_crate{}],
    compiler :: binary() | unknown
}).

-endif.
