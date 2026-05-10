%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%

-module(erlkoenig_nft_nflog_registry).
-moduledoc """
Explicit NFLOG group metadata registry.

The registry is populated from DSL/IR surfaces that declare which
NFLOG group belongs to which nft owner table. Packet parsing must not
infer ownership from chain names, prefixes, or numeric conventions.
""".

-export([register_table/1, register_group/3, lookup/1, all/0, clear/0]).

-include("nft_tables.hrl").

-define(KEY, erlkoenig_nft_nflog_groups).

-spec register_table(map()) -> ok.
register_table(#{name := TableName, owner := Owner} = Table) ->
    TableBin = iolist_to_binary(TableName),
    Groups = maps:get(nflog_groups, Table, []),
    lists:foreach(
      fun(GroupSpec) ->
          register_group(group_number(GroupSpec), TableBin, Owner)
      end,
      Groups),
    ok;
register_table(_Table) ->
    ok.

-spec register_group(non_neg_integer(), binary(), atom()) -> ok.
register_group(Group, Table, Owner)
  when is_integer(Group), Group >= 0, is_binary(Table), is_atom(Owner) ->
    Meta = #{
        table => Table,
        table_owner => Owner
    },
    Current = persistent_term:get(?KEY, #{}),
    persistent_term:put(?KEY, Current#{Group => Meta}),
    ok.

-spec lookup(non_neg_integer() | unknown) -> {ok, map()} | error.
lookup(Group) when is_integer(Group), Group >= 0 ->
    case maps:get(Group, persistent_term:get(?KEY, #{}), undefined) of
        undefined -> error;
        Meta -> {ok, Meta}
    end;
lookup(_) ->
    error.

-spec all() -> map().
all() ->
    persistent_term:get(?KEY, #{}).

-spec clear() -> ok.
clear() ->
    persistent_term:erase(?KEY),
    ok.

group_number(#{group := Group}) -> Group;
group_number(Group) when is_integer(Group) -> Group.
