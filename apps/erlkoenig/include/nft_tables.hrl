%%
%% Copyright 2026 Erlkoenig Contributors
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%

-ifndef(NFT_TABLES_HRL).
-define(NFT_TABLES_HRL, 1).

%% Per-owner table names from SPEC-NFT-OWNERSHIP-SPLIT §3. Phase 6g
%% removed the legacy compat bridge; production writers use these
%% constants directly. The §6.1 spike rejected a fourth
%% `erlkoenig_shared` table — kernel wire format has no
%% `NFTA_LOOKUP_TABLE` attribute — so this list is final at three.
-define(EK_NFT_TABLE_HOST, <<"erlkoenig_host">>).
-define(EK_NFT_TABLE_ZONE, <<"erlkoenig_zone">>).
-define(EK_NFT_TABLE_CT,   <<"erlkoenig_ct">>).

-endif.
