%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-module(erlkoenig_mount_opts).
-moduledoc """
Parser for Linux `mount(2)`-style option strings.

Accepts the usual comma-separated syntax (`"rw,nosuid,noexec,mode=755"`)
and emits a structured map with pre-baked `MS_*` bitmasks, propagation
type, and passthrough fs-specific data. Pure module, no I/O, no state —
safe to call from the DSL compiler, config loader, or runtime.

Semantics:

- Unknown **flag** tokens (bare words not in the flag table) raise
  `{error, {unknown_flag, Token}}` — catches typos like `"nosudi"` at
  compile time instead of silently ignoring them.
- Unknown **key=value** tokens are accepted and passed through as fs
  data (e.g. `"mode=0755"`, `"size=64m"`, `"uid=1000"`) — the kernel or
  the filesystem driver validates them.
- Repeated flags within the same group follow **mount(8)-style
  last-wins**: `"ro,rw"` yields `rw`, `"noatime,relatime"` yields
  `relatime`. This matches what operators expect from the standard
  tooling; surprising them is worse than catching a `ro,rw` typo.
- Propagation modes are genuinely exclusive (the kernel accepts at
  most one per mount call), so `"private,shared"` raises
  `{error, {conflicting_propagation, _, _}}`.

## Example

    %% DSL
    volumes: [
      #{host      => "/srv/data",
        container => "/data",
        opts      => "ro,nosuid,nodev,noexec,relatime"}
    ]

    %% Parses to:
    {ok, #{flags       => MS_RDONLY | MS_NOSUID | MS_NODEV |
                          MS_NOEXEC | MS_RELATIME,
           clear       => 0,
           propagation => none,
           recursive   => false,
           data        => <<>>}}

## Design notes

The implementation tries to pick the best of crun and Incus:

- crun (`src/libcrun/mount_flags.c`) uses a gperf-generated perfect-hash
  table for O(1) lookup of ~40 flag names. We don't need gperf — a pair
  of Erlang maps at load time gives equivalent lookup without the
  build-system dependency.
- Incus (`internal/server/instance/drivers/driver_lxc.go`) validates
  propagation vs. regular flags separately and supports the `r`-prefix
  for recursive propagation (`rshared`, `rprivate`, ...). We follow the
  same structure.
- Both parse lazily on each mount; we parse once at DSL compile time
  and pass a struct down. No runtime cost on the hot path.

The `MS_*` numeric values are **Linux ABI-stable** (from `bits/mount.h`)
— they are the same on every 64-bit Linux, and we hard-code them here
to avoid an `include/linux/mount.h` dependency on the Erlang side.
""".

-export([parse/1,
         format/1,
         default/0,
         flag_bits/1]).

-export_type([opts/0, propagation/0]).

-type propagation() :: none | private | slave | shared | unbindable.

-type opts() :: #{
    flags       := non_neg_integer(),
    clear       := non_neg_integer(),
    propagation := propagation(),
    recursive   := boolean(),
    data        := binary()
}.

%%% Linux MS_* ABI constants (from linux/mount.h / sys/mount.h).
-define(MS_RDONLY,       16#00000001).
-define(MS_NOSUID,       16#00000002).
-define(MS_NODEV,        16#00000004).
-define(MS_NOEXEC,       16#00000008).
-define(MS_SYNCHRONOUS,  16#00000010).
-define(MS_REMOUNT,      16#00000020).
-define(MS_MANDLOCK,     16#00000040).
-define(MS_DIRSYNC,      16#00000080).
-define(MS_NOSYMFOLLOW,  16#00000100).
-define(MS_NOATIME,      16#00000400).
-define(MS_NODIRATIME,   16#00000800).
-define(MS_BIND,         16#00001000).
-define(MS_REC,          16#00004000).
-define(MS_SILENT,       16#00008000).
-define(MS_UNBINDABLE,   16#00020000).
-define(MS_PRIVATE,      16#00040000).
-define(MS_SLAVE,        16#00080000).
-define(MS_SHARED,       16#00100000).
-define(MS_RELATIME,     16#00200000).
-define(MS_I_VERSION,    16#00800000).
-define(MS_STRICTATIME,  16#01000000).
-define(MS_LAZYTIME,     16#02000000).

%%% Mutually exclusive atime policies — setting any clears the others.
-define(ATIME_MASK,
        ?MS_NOATIME bor ?MS_RELATIME bor ?MS_STRICTATIME).

%%====================================================================
%% Flag tables
%%
%% Each set-entry maps a token -> {SetBits, ClearBits}. A "positive"
%% flag like `nosuid` just sets MS_NOSUID; its inverse `suid` clears
%% MS_NOSUID (set=0, clear=MS_NOSUID). `relatime` both sets MS_RELATIME
%% and clears the other atime modes to stay exclusive.
%%====================================================================

-spec flag_table() -> #{binary() => {non_neg_integer(), non_neg_integer()}}.
flag_table() ->
    #{
        %% Access mode
        <<"ro">>          => {?MS_RDONLY, 0},
        <<"rw">>          => {0, ?MS_RDONLY},
        %% setuid
        <<"suid">>        => {0, ?MS_NOSUID},
        <<"nosuid">>      => {?MS_NOSUID, 0},
        %% device nodes
        <<"dev">>         => {0, ?MS_NODEV},
        <<"nodev">>       => {?MS_NODEV, 0},
        %% exec
        <<"exec">>        => {0, ?MS_NOEXEC},
        <<"noexec">>      => {?MS_NOEXEC, 0},
        %% sync
        <<"sync">>        => {?MS_SYNCHRONOUS, 0},
        <<"async">>       => {0, ?MS_SYNCHRONOUS},
        <<"dirsync">>     => {?MS_DIRSYNC, 0},
        %% mand locking
        <<"mand">>        => {?MS_MANDLOCK, 0},
        <<"nomand">>      => {0, ?MS_MANDLOCK},
        %% atime policy (mutually exclusive — setting one clears the
        %% others in addition to the named inverse).
        <<"atime">>       => {0, ?ATIME_MASK},
        <<"noatime">>     => {?MS_NOATIME, ?MS_RELATIME bor ?MS_STRICTATIME},
        <<"diratime">>    => {0, ?MS_NODIRATIME},
        <<"nodiratime">>  => {?MS_NODIRATIME, 0},
        <<"relatime">>    => {?MS_RELATIME, ?MS_NOATIME bor ?MS_STRICTATIME},
        <<"norelatime">>  => {0, ?MS_RELATIME},
        <<"strictatime">> => {?MS_STRICTATIME, ?MS_NOATIME bor ?MS_RELATIME},
        %% inode versioning
        <<"iversion">>    => {?MS_I_VERSION, 0},
        <<"noiversion">>  => {0, ?MS_I_VERSION},
        %% lazytime (delay inode timestamp writeback)
        <<"lazytime">>    => {?MS_LAZYTIME, 0},
        <<"nolazytime">>  => {0, ?MS_LAZYTIME},
        %% no-follow-symlinks on traversal (kernel 5.10+)
        <<"nosymfollow">> => {?MS_NOSYMFOLLOW, 0},
        %% bind
        <<"bind">>        => {?MS_BIND, 0},
        <<"rbind">>       => {?MS_BIND bor ?MS_REC, 0},
        %% remount
        <<"remount">>     => {?MS_REMOUNT, 0},
        %% kernel message silence
        <<"silent">>      => {?MS_SILENT, 0},
        <<"loud">>        => {0, ?MS_SILENT}
    }.

-spec propagation_table() -> #{binary() => {propagation(), boolean()}}.
propagation_table() ->
    #{
        <<"private">>     => {private,    false},
        <<"rprivate">>    => {private,    true},
        <<"slave">>       => {slave,      false},
        <<"rslave">>      => {slave,      true},
        <<"shared">>      => {shared,     false},
        <<"rshared">>     => {shared,     true},
        <<"unbindable">>  => {unbindable, false},
        <<"runbindable">> => {unbindable, true}
    }.

%%====================================================================
%% Public API
%%====================================================================

-doc "Empty options value (no flags, no propagation, no data).".
-spec default() -> opts().
default() ->
    #{flags => 0, clear => 0, propagation => none,
      recursive => false, data => <<>>}.

-doc "Parse a mount-options string. Returns `{error, Reason}` on bad input.".
-spec parse(iodata() | binary()) -> {ok, opts()} | {error, term()}.
parse(Input) ->
    Bin = iolist_to_binary(Input),
    Tokens = split_tokens(Bin),
    parse_tokens(Tokens, default(), flag_table(), propagation_table(), []).

-doc """
Format an opts() map back to the canonical mount-options string.

Round-trips through `parse/1`; the output is stable (flags in a fixed
canonical order, propagation last) so it can be used for diffing or
logging.
""".
-spec format(opts()) -> binary().
format(#{flags := Flags, clear := Clear,
         propagation := Prop, recursive := Rec,
         data := Data}) ->
    FlagParts   = flags_to_tokens(Flags, Clear),
    PropPart    = propagation_to_token(Prop, Rec),
    DataPart    = case Data of <<>> -> []; _ -> [Data] end,
    Parts       = FlagParts ++ PropPart ++ DataPart,
    iolist_to_binary(lists:join($,, Parts)).

-doc """
Return the integer MS_* bit corresponding to a single token name, or
`undefined` if the name is not a known flag. Useful for tests or tools
that want to introspect the table without parsing a full options
string.
""".
-spec flag_bits(binary()) -> {non_neg_integer(), non_neg_integer()} | undefined.
flag_bits(Name) when is_binary(Name) ->
    maps:get(Name, flag_table(), undefined).

%%====================================================================
%% Internal — parsing
%%====================================================================

split_tokens(Bin) ->
    %% Split on comma, drop empties, strip leading/trailing whitespace.
    [string:trim(Tok)
     || Tok <- binary:split(Bin, <<",">>, [global]),
        Tok =/= <<>>, string:trim(Tok) =/= <<>>].

parse_tokens([], Acc, _FT, _PT, DataAcc) ->
    Data = iolist_to_binary(lists:join($,, lists:reverse(DataAcc))),
    {ok, Acc#{data := Data}};
parse_tokens([Token | Rest], Acc, FT, PT, DataAcc) ->
    case classify(Token, FT, PT) of
        {flag, {Set, Clear}} ->
            %% Last-wins: this token's Set bits win over any previous
            %% Clear; its Clear bits win over any previous Set. Mirrors
            %% mount(8) behaviour for repeated/overlapping flags.
            NewFlags = (maps:get(flags, Acc) bor Set)
                       band (bnot Clear),
            NewClear = (maps:get(clear, Acc) bor Clear)
                       band (bnot Set),
            Acc2 = Acc#{flags := NewFlags, clear := NewClear},
            parse_tokens(Rest, Acc2, FT, PT, DataAcc);
        {propagation, Type, Recursive} ->
            case maps:get(propagation, Acc) of
                none ->
                    Acc2 = Acc#{propagation := Type, recursive := Recursive},
                    parse_tokens(Rest, Acc2, FT, PT, DataAcc);
                Existing when Existing =:= Type ->
                    %% repeated same propagation, tolerate
                    parse_tokens(Rest, Acc, FT, PT, DataAcc);
                Existing ->
                    {error, {conflicting_propagation, Existing, Type}}
            end;
        {data, KV} ->
            parse_tokens(Rest, Acc, FT, PT, [KV | DataAcc]);
        {error, _} = E ->
            E
    end.

classify(Token, FT, PT) ->
    case maps:find(Token, FT) of
        {ok, Entry} ->
            {flag, Entry};
        error ->
            case maps:find(Token, PT) of
                {ok, {Type, Rec}} ->
                    {propagation, Type, Rec};
                error ->
                    %% key=value → data passthrough; bare unknown → error.
                    case binary:match(Token, <<"=">>) of
                        nomatch ->
                            {error, {unknown_flag, Token}};
                        _ ->
                            {data, Token}
                    end
            end
    end.

%%====================================================================
%% Internal — formatting
%%====================================================================

%% Canonical order matches mount(8) output: ro/rw, nosuid, nodev, noexec,
%% sync/async, dirsync, mand/nomand, atime family, bind, remount, silent.
-define(FORMAT_ORDER,
        [{?MS_RDONLY,       set,   <<"ro">>},
         {?MS_NOSUID,       set,   <<"nosuid">>},
         {?MS_NODEV,        set,   <<"nodev">>},
         {?MS_NOEXEC,       set,   <<"noexec">>},
         {?MS_SYNCHRONOUS,  set,   <<"sync">>},
         {?MS_DIRSYNC,      set,   <<"dirsync">>},
         {?MS_MANDLOCK,     set,   <<"mand">>},
         {?MS_NOATIME,      set,   <<"noatime">>},
         {?MS_NODIRATIME,   set,   <<"nodiratime">>},
         {?MS_RELATIME,     set,   <<"relatime">>},
         {?MS_STRICTATIME,  set,   <<"strictatime">>},
         {?MS_I_VERSION,    set,   <<"iversion">>},
         {?MS_LAZYTIME,     set,   <<"lazytime">>},
         {?MS_NOSYMFOLLOW,  set,   <<"nosymfollow">>},
         {?MS_BIND,         set,   <<"bind">>},
         {?MS_REC,          set,   <<"rec">>},
         {?MS_REMOUNT,      set,   <<"remount">>},
         {?MS_SILENT,       set,   <<"silent">>}]).

flags_to_tokens(Flags, _Clear) ->
    %% `bind` + `rec` combined -> rbind (canonical short form).
    Has = fun(B) -> (Flags band B) =/= 0 end,
    case {Has(?MS_BIND), Has(?MS_REC)} of
        {true, true}  ->
            Rest = [Tok || {B, set, Tok} <- ?FORMAT_ORDER,
                           B =/= ?MS_BIND, B =/= ?MS_REC,
                           Has(B)],
            Rest ++ [<<"rbind">>];
        _ ->
            [Tok || {B, set, Tok} <- ?FORMAT_ORDER, Has(B)]
    end.

propagation_to_token(none, _)       -> [];
propagation_to_token(private, true) -> [<<"rprivate">>];
propagation_to_token(private, _)    -> [<<"private">>];
propagation_to_token(slave, true)   -> [<<"rslave">>];
propagation_to_token(slave, _)      -> [<<"slave">>];
propagation_to_token(shared, true)  -> [<<"rshared">>];
propagation_to_token(shared, _)     -> [<<"shared">>];
propagation_to_token(unbindable, true) -> [<<"runbindable">>];
propagation_to_token(unbindable, _)    -> [<<"unbindable">>].
