#!/usr/bin/env escript
%%! -sname render_error_catalog
%%
%% Render apps/erlkoenig/priv/error_catalog.term to a Markdown
%% reference document. Stdout = the rendered markdown.
%%
%% Used by `make docs/ERROR_CODES.md` to keep the doc in sync with
%% the live catalog without hand-editing.
%%
%% Usage:
%%   escript tools/render-error-catalog.escript > docs/ERROR_CODES.md

-mode(compile).

main(_Args) ->
    Catalog = "apps/erlkoenig/priv/error_catalog.term",
    case file:consult(Catalog) of
        {ok, [Entries]} when is_list(Entries) ->
            render(Entries);
        {error, Reason} ->
            io:format(standard_error,
                      "render-error-catalog: cannot read ~s: ~p~n",
                      [Catalog, Reason]),
            halt(1)
    end.

render(Entries) ->
    %% Group by component, sorted within group, components alphabetic
    ByComponent = group_by_component(Entries),
    Components = lists:sort(maps:keys(ByComponent)),

    header(length(Entries), Components),
    toc(ByComponent, Components),
    body(ByComponent, Components).

group_by_component(Entries) ->
    lists:foldl(fun({Code, Meta}, Acc) ->
        Comp = maps:get(component, Meta, undefined),
        Existing = maps:get(Comp, Acc, []),
        maps:put(Comp, [{Code, Meta} | Existing], Acc)
    end, #{}, Entries).

header(Total, Components) ->
    io:format("# Erlkoenig Error Code Reference~n~n", []),
    io:format("Auto-generated from `apps/erlkoenig/priv/error_catalog.term`. "
              "Do not hand-edit. Re-run `make docs/ERROR_CODES.md` after "
              "any catalog change.~n~n", []),
    io:format("**~p codes across ~p components.**~n~n",
              [Total, length(Components)]),
    io:format("Codes are part of the public contract. They follow the "
              "stability rules in CONTRIBUTING.md (Error Handling Contract): "
              "stable identifiers, deprecation over removal, "
              "structured `{error, ErrorMap}` returns at module boundaries.~n~n",
              []),
    io:format("Operator usage:~n~n", []),
    io:format("```sh~n", []),
    io:format("ek explain EK_AUDIT_CHAIN_BROKEN     # detailed view~n", []),
    io:format("ek explain --component nft           # filter by component~n", []),
    io:format("ek explain --list                    # all codes~n", []),
    io:format("ek --format json explain EK_FOO      # for tooling~n", []),
    io:format("```~n~n", []).

toc(ByComponent, Components) ->
    io:format("## Table of Contents~n~n", []),
    lists:foreach(fun(C) ->
        Codes = maps:get(C, ByComponent),
        io:format("- [`~s`](#~s) (~p codes)~n",
                  [C, anchor(C), length(Codes)])
    end, Components),
    io:format("~n", []).

body(ByComponent, Components) ->
    render_components(ByComponent, Components).

render_components(_ByComponent, []) ->
    ok;
render_components(ByComponent, [Comp]) ->
    render_component(ByComponent, Comp, last);
render_components(ByComponent, [Comp | Rest]) ->
    render_component(ByComponent, Comp, more),
    render_components(ByComponent, Rest).

render_component(ByComponent, Comp, More) ->
    io:format("## ~s~n~n", [Comp]),
    Codes = lists:sort(maps:get(Comp, ByComponent)),
    case More of
        more -> lists:foreach(fun(Entry) -> render_entry(Entry, more) end, Codes);
        last -> render_entries(Codes)
    end.

render_entries([]) ->
    ok;
render_entries([Entry]) ->
    render_entry(Entry, last);
render_entries([Entry | Rest]) ->
    render_entry(Entry, more),
    render_entries(Rest).

render_entry({Code, Meta}, More) ->
    io:format("### `~s`~n~n", [Code]),
    io:format("- **Severity:** `~s`~n",
              [atom_to_list(maps:get(severity, Meta, error))]),
    io:format("- **Since:** `~ts`~n", [text(maps:get(since, Meta, "unknown"))]),
    io:format("- **Description:** ~ts~n",
              [text(maps:get(description, Meta, "(none)"))]),
    io:format("~n", []),
    io:format("**Operator action:** ~ts~n~n",
              [text(maps:get(operator_action, Meta, "(none documented)"))]),
    case maps:get(evidence_fields, Meta, []) of
        [] -> ok;
        Fields ->
            io:format("**Evidence fields:** ~s~n~n",
                      [string:join([atom_to_list(F) || F <- Fields], ", ")])
    end,
    case maps:find(iron_rule, Meta) of
        {ok, Rule} ->
            io:format("**Iron rule:** _~s_~n~n", [Rule]);
        error -> ok
    end,
    case maps:get(related_specs, Meta, []) of
        [] -> ok;
        Specs ->
            io:format("**Related:** ~s~n~n",
                      [string:join(Specs, ", ")])
    end,
    case More of
        more -> io:format("---~n~n", []);
        last -> io:format("---~n", [])
    end.

anchor(Atom) when is_atom(Atom) ->
    atom_to_list(Atom).

text(Value) when is_binary(Value) ->
    unicode:characters_to_list(Value);
text(Value) when is_atom(Value) ->
    atom_to_list(Value);
text(Value) ->
    Value.
