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

-module(elf_report).
-moduledoc """
Report formatting for erlkoenig_elf analysis results.

Converts analysis maps (from erlkoenig_elf:analyze/1) into
human-readable text or JSON output.
""".

-include("elf_lang_go.hrl").
-include("elf_lang_rust.hrl").

-export([to_json/1, to_text/1]).

%% ---------------------------------------------------------------------------
%% JSON output
%% ---------------------------------------------------------------------------

-spec to_json(map()) -> binary().
to_json(Report) when is_map(Report) ->
    iolist_to_binary(json:encode(prepare_for_json(Report))).

%% ---------------------------------------------------------------------------
%% Text output
%% ---------------------------------------------------------------------------

-spec to_text(map()) -> [[[any()]], ...].
to_text(Report) when is_map(Report) ->
    [
        header_section(Report),
        syscall_section(Report),
        dep_section(Report),
        anomaly_section(Report)
    ].

%% ---------------------------------------------------------------------------
%% Text sections
%% ---------------------------------------------------------------------------

header_section(Report) ->
    Arch = format_atom(maps:get(arch, Report, unknown)),
    Type = format_type(
        maps:get(type, Report, unknown),
        maps:get(is_static, Report, false)
    ),
    Lang = format_language(
        maps:get(language, Report, unknown),
        maps:get(language_info, Report, undefined)
    ),
    Entry = format_hex(maps:get(entry_point, Report, 0)),
    Sections = integer_to_list(length(maps:get(sections, Report, []))),
    TextSize = format_bytes(maps:get(text_size, Report, 0)),
    TotalSize = format_bytes(maps:get(total_size, Report, 0)),
    [
        "=== erlkoenig_elf Analysis ===\n",
        "Architecture: ",
        Arch,
        "\n",
        "Type:         ",
        Type,
        "\n",
        "Language:     ",
        Lang,
        "\n",
        "Entry:        ",
        Entry,
        "\n",
        "Sections:     ",
        Sections,
        "\n",
        "Text size:    ",
        TextSize,
        " bytes\n",
        "Total size:   ",
        TotalSize,
        " bytes\n"
    ].

syscall_section(Report) ->
    case maps:get(syscalls, Report, undefined) of
        {error, _} ->
            [];
        undefined ->
            [];
        Info when is_map(Info) ->
            Resolved = maps:get(resolved, Info, #{}),
            Names = lists:sort(maps:values(Resolved)),
            Count = length(Names),
            Cats = maps:get(categories, Info, #{}),
            [
                "\n=== Syscalls (",
                integer_to_list(Count),
                " detected) ===\n",
                "  ",
                format_name_list(Names),
                "\n",
                format_categories(Cats)
            ]
    end.

dep_section(Report) ->
    case maps:get(language_info, Report, undefined) of
        {error, _} ->
            [];
        undefined ->
            [];
        LangInfo when is_map(LangInfo) ->
            format_deps_from_lang_info(LangInfo);
        _ ->
            []
    end.

anomaly_section(_Report) ->
    %% Anomaly formatting is handled externally via dep_anomalies
    [].

%% ---------------------------------------------------------------------------
%% Text formatting helpers
%% ---------------------------------------------------------------------------

format_atom(A) when is_atom(A) -> atom_to_list(A);
format_atom({unknown, N}) -> io_lib:format("unknown(~B)", [N]);
format_atom(Other) -> io_lib:format("~p", [Other]).

format_type(Type, IsStatic) ->
    TypeStr = format_atom(Type),
    case IsStatic of
        true -> [TypeStr, " (static)"];
        false -> TypeStr
    end.

format_language(Lang, LangInfo) when is_map(LangInfo) ->
    Base = atom_to_list(Lang),
    case maps:get(info, LangInfo, undefined) of
        undefined -> Base;
        Info -> format_lang_detail(Lang, Base, Info)
    end;
format_language(Lang, _) ->
    atom_to_list(Lang).

format_lang_detail(go, Base, #go_info{version = <<>>}) ->
    Base;
format_lang_detail(go, Base, #go_info{version = Ver}) when is_binary(Ver) ->
    [Base, " (", binary_to_list(Ver), ")"];
format_lang_detail(rust, Base, #rust_info{compiler = unknown}) ->
    Base;
format_lang_detail(rust, Base, #rust_info{compiler = Ver}) when is_binary(Ver) ->
    [Base, " (rustc ", binary_to_list(Ver), ")"];
format_lang_detail(_, Base, _) ->
    Base.

format_hex(N) ->
    io_lib:format("0x~.16B", [N]).

format_bytes(N) ->
    format_with_commas(integer_to_list(N)).

format_with_commas(Str) ->
    %% Insert commas for thousands separators
    Len = length(Str),
    case Len =< 3 of
        true ->
            Str;
        false ->
            R = Len rem 3,
            {First, Rest} =
                case R of
                    0 -> lists:split(3, Str);
                    _ -> lists:split(R, Str)
                end,
            [First | insert_commas(Rest)]
    end.

insert_commas([]) ->
    [];
insert_commas(Str) when length(Str) =< 3 -> [$, | Str];
insert_commas(Str) ->
    {Chunk, Rest} = lists:split(3, Str),
    [$, | Chunk] ++ insert_commas(Rest).

format_name_list([]) ->
    "(none)";
format_name_list(Names) when length(Names) > 10 ->
    First10 = lists:sublist(Names, 10),
    Strs = [binary_to_list(N) || N <- First10],
    [lists:join(", ", Strs), ", ..."];
format_name_list(Names) ->
    Strs = [binary_to_list(N) || N <- Names],
    lists:join(", ", Strs).

format_categories(Cats) when map_size(Cats) =:= 0 -> [];
format_categories(Cats) ->
    Entries = lists:sort(maps:to_list(Cats)),
    Formatted = lists:map(
        fun({Cat, Names}) ->
            [atom_to_list(Cat), "(", integer_to_list(length(Names)), ")"]
        end,
        Entries
    ),
    ["  Categories: ", lists:join(", ", Formatted), "\n"].

format_deps_from_lang_info(#{language := go, info := #go_info{deps = Deps}}) ->
    case Deps of
        [] ->
            [];
        _ ->
            Lines = lists:map(
                fun(#go_dep{path = Path, version = Ver}) ->
                    ["  ", binary_to_list(Path), " ", binary_to_list(Ver), "\n"]
                end,
                Deps
            ),
            [
                "\n=== Dependencies (",
                integer_to_list(length(Deps)),
                " found) ===\n"
                | Lines
            ]
    end;
format_deps_from_lang_info(#{language := rust, info := #rust_info{crates = Crates}}) ->
    case Crates of
        [] ->
            [];
        _ ->
            Lines = lists:map(
                fun(#rust_crate{name = Name, version = Ver}) ->
                    VerStr =
                        case Ver of
                            unknown -> "unknown";
                            V when is_binary(V) -> binary_to_list(V)
                        end,
                    ["  ", binary_to_list(Name), " ", VerStr, "\n"]
                end,
                Crates
            ),
            [
                "\n=== Dependencies (",
                integer_to_list(length(Crates)),
                " found) ===\n"
                | Lines
            ]
    end;
format_deps_from_lang_info(_) ->
    [].

%% ---------------------------------------------------------------------------
%% JSON helpers
%% ---------------------------------------------------------------------------

prepare_for_json(Report) ->
    maps:map(fun(_K, V) -> to_json_value(V) end, Report).

to_json_value(V) when is_atom(V) -> atom_to_binary(V, utf8);
to_json_value(V) when is_integer(V) -> V;
to_json_value(V) when is_binary(V) -> V;
to_json_value(V) when is_boolean(V) -> V;
to_json_value({unknown, N}) ->
    iolist_to_binary(io_lib:format("unknown(~B)", [N]));
to_json_value({error, Reason}) ->
    [{<<"error">>, iolist_to_binary(io_lib:format("~p", [Reason]))}];
to_json_value(V) when is_list(V) ->
    [to_json_value(E) || E <- V];
to_json_value(V) when is_map(V) ->
    maps:map(fun(_K, Val) -> to_json_value(Val) end, V);
to_json_value(V) when is_tuple(V) ->
    iolist_to_binary(io_lib:format("~p", [V]));
to_json_value(V) ->
    iolist_to_binary(io_lib:format("~p", [V])).
