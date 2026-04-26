%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0
%%

-ifndef(ERLKOENIG_ERROR_TEST_HRL).
-define(ERLKOENIG_ERROR_TEST_HRL, 1).

-define(assertErrorCode(Code, Expr),
        ?assertMatch({error, #{code := Code}}, Expr)).

-endif.
