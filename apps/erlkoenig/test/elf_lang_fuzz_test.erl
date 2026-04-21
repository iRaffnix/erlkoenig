%%%-------------------------------------------------------------------
%%% @doc ELF-language-detection parser fuzz.
%%%
%%% These parsers operate on attacker-controlled ELF section content
%%% (Go buildinfo, Rust crate metadata, DWARF debug_line).  A crash
%%% here during container-binary analysis aborts signature
%%% verification / language detection with a confusing error.
%%% @end
%%%-------------------------------------------------------------------

-module(elf_lang_fuzz_test).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(nowarn_unused_function).

dwarf_line_units_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_dwarf_line_units_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

dwarf_line_unit_files_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_dwarf_line_unit_files_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

go_mod_info_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_go_mod_info_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

rust_crate_version_test_() ->
    {timeout, 60, fun() ->
        true = proper:quickcheck(
                 prop_rust_crate_version_safe(),
                 [{numtests, 500}, {to_file, user}, noshrink])
    end}.

prop_dwarf_line_units_safe() ->
    ?FORALL({Bin, Endian},
            {?LET(N, proper_types:choose(0, 256),
                  proper_types:binary(N)),
             proper_types:oneof([little, big])},
        run_safely(fun() ->
            elf_lang_dwarf:parse_line_units(Bin, Endian, [])
        end, {Bin, Endian})).

prop_dwarf_line_unit_files_safe() ->
    ?FORALL({Bin, Endian},
            {?LET(N, proper_types:choose(0, 256),
                  proper_types:binary(N)),
             proper_types:oneof([little, big])},
        run_safely(fun() ->
            elf_lang_dwarf:parse_line_unit_files(Bin, Endian)
        end, {Bin, Endian})).

prop_go_mod_info_safe() ->
    ?FORALL(Bin, ?LET(N, proper_types:choose(0, 512),
                      proper_types:binary(N)),
        run_safely(fun() -> elf_lang_go:parse_mod_info(Bin) end, Bin)).

prop_rust_crate_version_safe() ->
    ?FORALL(Bin, ?LET(N, proper_types:choose(0, 128),
                      proper_types:binary(N)),
        run_safely(fun() ->
            elf_lang_rust:parse_crate_version(Bin)
        end, Bin)).

%% -------------------------------------------------------------------

run_safely(F, Label) ->
    Self = self(),
    Pid = spawn(fun() ->
        R = try F() of V -> {ok, V}
            catch C:E:_ -> {crash, C, E}
            end,
        Self ! {self(), R}
    end),
    receive
        {Pid, {ok, _}} -> true;
        {Pid, {crash, C, E}} ->
            io:format(user, "CRASH ~p:~p on ~p~n", [C, E, Label]),
            false
    after 2000 ->
        exit(Pid, kill),
        io:format(user, "TIMEOUT on ~p~n", [Label]),
        false
    end.
