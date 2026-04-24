%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%

-module(erlkoenig_ct_rt_discover).
-moduledoc """
Locate the external `erlkoenig_rt' C-runtime binary at spawn time.

Separated from `erlkoenig_ct_rt' because the change frequency is
completely different: socket I/O is on the hot path and gets
touched for protocol changes; path discovery only matters on
package layout or dev-build directory shuffles.

Search order (first match wins, via `find_first/1'):

  1. `application:get_env(erlkoenig, rt_path, auto)' — operator
     override.
  2. `os:find_executable/1' — anything on `$PATH'.
  3. `/usr/lib/erlkoenig/erlkoenig_rt' — Debian/RPM package layout.
  4. `/opt/erlkoenig/rt/erlkoenig_rt' — bundled release.
  5. `code:priv_dir(erlkoenig)/erlkoenig_rt' — rebar3 priv layout.
  6. `$(project_root)/build/release/erlkoenig_rt' — dev `make'
     output.

Raises `erlkoenig_rt_not_found' when no candidate exists; the
gen_statem turns that into a `creating → failed' transition with
an explicit error reason.
""".

-export([rt_path/0, find_rt/0, find_first/1,
         check_path/1, check_priv_dir/0, check_build_dir/0]).

-spec rt_path() -> string().
rt_path() ->
    case application:get_env(erlkoenig, rt_path, auto) of
        auto -> find_rt();
        Path -> Path
    end.

-spec find_rt() -> string().
find_rt() ->
    Candidates = [
        fun() -> os:find_executable("erlkoenig_rt") end,
        fun() -> check_path("/usr/lib/erlkoenig/erlkoenig_rt") end,
        fun() -> check_path("/opt/erlkoenig/rt/erlkoenig_rt") end,
        fun() -> check_priv_dir() end,
        fun() -> check_build_dir() end
    ],
    find_first(Candidates).

-spec find_first([fun(() -> false | string())]) -> string().
find_first([]) ->
    error(erlkoenig_rt_not_found);
find_first([F | Rest]) ->
    case F() of
        false -> find_first(Rest);
        Path  -> Path
    end.

-spec check_path(string()) -> false | string().
check_path(Path) ->
    case filelib:is_regular(Path) of
        true  -> Path;
        false -> false
    end.

-spec check_priv_dir() -> false | string().
check_priv_dir() ->
    try code:priv_dir(erlkoenig) of
        Dir ->
            Path = filename:join(Dir, "erlkoenig_rt"),
            check_path(Path)
    catch
        error:bad_name -> false
    end.

%% Dev-build fallback: walk five levels up from `ebin' to the project
%% root (apps/erlkoenig/_build/<profile>/lib/erlkoenig/ebin →
%% project root) and look for `build/release/erlkoenig_rt'.
-spec check_build_dir() -> false | string().
check_build_dir() ->
    Ebin = filename:dirname(code:which(erlkoenig_ct)),
    ProjectRoot = filename:join([Ebin, "..", "..", "..", "..", ".."]),
    Path = filename:absname(
            filename:join(ProjectRoot, "build/release/erlkoenig_rt")),
    check_path(Path).
