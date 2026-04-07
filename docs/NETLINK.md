# Netlink Transport in erlkoenig

Wie erlkoenig ueber einen einzelnen AF_NETLINK Socket mit dem nf_tables Subsystem
des Linux-Kernels kommuniziert, welche Fehler dabei auftreten koennen und welche
Designentscheidungen aus den Eigenheiten des Protokolls folgen.

## Das Protokoll

Netlink ist kein Stream-Protokoll. Es ist datagramm-basiert: jeder `sendto`
produziert genau ein Datagramm, jeder `recv` liefert genau ein Datagramm.
Aber ein Datagramm kann **mehrere** Netlink-Nachrichten enthalten.

Jede Nachricht beginnt mit einem 16-Byte Header:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Length                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Type                 |            Flags              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Sequence Number                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Port ID                                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Die Sequence Number (`nlmsg_seq`) ist der Schluessel zur Zuordnung von
Antworten zu Anfragen. Der Kernel kopiert sie 1:1 in seine Antwort.
Wer sie ignoriert, baut sich einen State-Bleed-Bug.

## Batches: Atomare Transaktionen

nf_tables unterstuetzt atomare Batch-Operationen. Alle Nachrichten zwischen
`NFNL_MSG_BATCH_BEGIN` und `NFNL_MSG_BATCH_END` werden vom Kernel als eine
Transaktion verarbeitet: entweder gehen alle durch oder keine.

```
BATCH_BEGIN  (Seq=100, Flags=NLM_F_REQUEST)        -- kein ACK
MSG_1        (Seq=101, Flags=NLM_F_REQUEST|ACK)    -- ACK
MSG_2        (Seq=102, Flags=NLM_F_REQUEST|ACK)    -- ACK
MSG_3        (Seq=103, Flags=NLM_F_REQUEST|ACK)    -- ACK
BATCH_END    (Seq=104, Flags=NLM_F_REQUEST)        -- kein ACK
```

Entscheidend: `BATCH_BEGIN` und `BATCH_END` werden nur mit `NLM_F_REQUEST`
gesendet, **nicht** mit `NLM_F_ACK`. Der Kernel queued ACKs ausschliesslich
fuer Nachrichten die `NLM_F_ACK` im Flag-Feld tragen. Fuer einen Batch mit
N Nachrichten kommen daher genau **N ACKs** zurueck — nicht N+2.

Verifiziert im Kernel-Code (`nf-next/net/netfilter/nfnetlink.c`):

```c
if (nlh->nlmsg_flags & NLM_F_ACK)
    nfnl_err_add(&err_list, nlh, 0, &extack);
```

Der Kernel sammelt alle Fehler waehrend der Batch-Verarbeitung in einer
internen Liste (`err_list`) und sendet sie geblockt am Ende des Batches
ueber `nfnl_err_deliver`. Der Batch wird dabei nicht beim ersten Fehler
abgebrochen — der Kernel verarbeitet alle Nachrichten und meldet alle
Fehler. Aber die Transaktion wird zurueckgerollt: bei einem Fehler in
irgendeiner Nachricht wird nichts committed.

In `nfnl_msg.erl` sieht das so aus:

```erlang
batch_ctrl(MsgType, Seq) ->
    Type = (?NFNL_SUBSYS_NONE bsl 8) bor MsgType,
    NfGenMsg = <<0:8, ?NFNETLINK_V0:8, ?NFNL_SUBSYS_NFTABLES:16/big>>,
    Len = ?NLMSGHDR_SIZE + ?NFGENMSG_SIZE,
    <<Len:32/little, Type:16/little, ?NLM_F_REQUEST:16/little, ...>>.
    %%                               ^^^^^^^^^^^^^^^^
    %%                               Nur REQUEST, kein ACK
```

Regulaere Nachrichten dagegen setzen `NLM_F_REQUEST bor NLM_F_ACK bor NLM_F_CREATE`.

## ACKs lesen: Der Drain-Loop

Ein ACK ist eine `NLMSG_ERROR`-Nachricht mit Error-Code 0 (Erfolg) oder
einem negativen errno (Fehler). Der Response-Parser in `nfnl_response.erl`
iteriert ueber alle Nachrichten in einem Datagramm:

```erlang
parse_messages_seq(
    <<Len:32/little, ?NLMSG_ERROR:16/little, _Flags:16/little,
      Seq:32/little, _Pid:32/little,
      Error:32/signed-little, _Rest/binary>> = Bin, Acc)
  when Len >= 20 ->
    Result = case Error of
        0 -> ok;
        N -> {error, {N, errno_name(N)}}
    end,
    <<_:Len/binary, Tail/binary>> = Bin,
    parse_messages_seq(Tail, [{Seq, Result} | Acc]);
```

Die zentrale Designentscheidung: `Seq` wird extrahiert und zurueckgegeben,
nicht ignoriert. Die alte Version verwendete `_Seq` — das war der Bug.

### Warum Seq-basiert und nicht Count-basiert

Die alte `collect_loop` zaehlte einfach ACKs:

```erlang
%% ALT — kaputt
collect_loop(_Sock, 0, _Acc) -> ok;
collect_loop(Sock, Remaining, Acc) ->
    {ok, Data} = recv(Sock),
    Results = parse(Data),
    case check_results(Results) of
        {ok, Count} ->
            Left = Remaining - Count,
            if Left =< 0 -> ok;
               true -> collect_loop(Sock, Left, Acc)
            end;
        {error, _} = Err ->
            Err   %% <-- Bricht ab, liest keine weiteren ACKs!
    end.
```

Zwei Probleme:

1. **Abbruch bei Fehler.** Wenn eine Nachricht fehlschlaegt, gibt `check_results`
   sofort `{error, Reason}` zurueck. Die restlichen ACKs bleiben im Socket-Buffer.
   Der naechste `apply_msgs`-Aufruf liest sie und ordnet sie seinem Batch zu.
   Das ist State-Bleed.

2. **Count-basierte Terminierung ist fragil.** Wenn der Kernel jemals eine
   unerwartete Nachricht sendet (ein Monitor-Event, ein Broadcast), verschiebt
   sich der Zaehler. Seq-basierte Terminierung ist dagegen robust: die Loop
   endet wenn alle erwarteten Seqs beantwortet sind.

Die neue `collect_until_seq` behebt beides:

```erlang
collect_until_seq(_Sock, Expected, Acc) when map_size(Expected) =:= 0 ->
    Acc;
collect_until_seq(Sock, Expected, Acc) ->
    case nfnl_socket:recv(Sock) of
        {ok, Data} ->
            Parsed = nfnl_response:parse_with_seq(Data),
            {Expected2, Acc2} = process_acks(Parsed, Expected, Acc),
            collect_until_seq(Sock, Expected2, Acc2);
        {error, timeout} ->
            ...
    end.
```

`Expected` ist eine `#{Seq => true}` Map mit allen vergebenen Sequence-Nummern.
`process_acks` entfernt jede empfangene Seq aus der Map. Die Loop endet wenn
die Map leer ist. ACKs mit unbekannten Seqs werden verworfen.

### Fehler-Akkumulation

```erlang
process_acks([{Seq, Result} | Rest], Expected, Acc) ->
    case maps:take(Seq, Expected) of
        {true, Expected2} ->
            NewAcc = case {Acc, Result} of
                {ok, ok}         -> ok;
                {ok, {error, _}} -> Result;   %% Erster Fehler
                {{error, _}, _}  -> Acc        %% Behalte ersten Fehler
            end,
            process_acks(Rest, Expected2, NewAcc);
        error ->
            process_acks(Rest, Expected, Acc)
    end.
```

Der erste Fehler wird gemerkt, aber die Loop liest weiter bis alle Seqs
konsumiert sind. Der Socket ist nach der Rueckkehr garantiert sauber —
egal ob Erfolg oder Fehler.

## Erlang-Patterns

### gen_server als Socket-Owner

`nfnl_server` ist ein `gen_server` der den Netlink-Socket besitzt. Alle
Operationen laufen ueber `gen_server:call` und sind dadurch serialisiert.
Es gibt keine Parallelitaet auf dem Socket — zwei Batches koennen nie
gleichzeitig in Bearbeitung sein.

Das ist eine bewusste Entscheidung gegen Pipelining. Die Alternative
waere ein asynchrones Modell mit `{active, true}` Socket und einer
`pending`-Map die Caller per Seq zuordnet. Das wuerde Pipelining
ermoeglichen (mehrere Batches gleichzeitig auf dem Socket), ist aber
unnoetige Komplexitaet solange die Batch-Groessen klein sind.

Das synchrone Modell hat einen Vorteil: der Caller blockiert in
`gen_server:call` bis sein Batch vollstaendig beantwortet ist. Es gibt
keinen Zustand zwischen "gesendet" und "beantwortet" den man tracken
muesste.

### Message-Funktionen statt vorkodierter Binaries

Die API von `apply_msgs` nimmt keine fertigen Binaries sondern eine
Liste von Funktionen:

```erlang
apply_msgs(Server, [
    fun(Seq) -> nft_table:add(Family, Table, Seq) end,
    fun(Seq) -> nft_chain:add(Family, ChainOpts, Seq) end,
    fun(Seq) -> nft_encode:rule(..., Seq) end
]).
```

Jede Funktion bekommt die Sequence Number als Parameter und gibt die
kodierte Binary zurueck. Der Server vergibt die Seqs monoton und
baut den Batch zusammen:

```erlang
build_msgs([Fun | Rest], Seq, MsgAcc, SeqAcc) ->
    Msg = Fun(Seq),
    build_msgs(Rest, next_seq(Seq), [Msg | MsgAcc], [Seq | SeqAcc]).
```

`next_seq` ist `(Seq + 1) band 16#FFFFFFFF` — Wraparound-sicher.

Der Grund fuer Funktionen statt Binaries: der Caller kennt seine Seq
nicht im Voraus. Der Server ist die einzige Seq-Quelle.

### Expected-Map statt Seq-Range

Die erwarteten Sequence-Nummern werden als Map konstruiert, nicht als
arithmetischer Range:

```erlang
Expected = maps:from_keys(MsgSeqs, true),
```

`MsgSeqs` ist die tatsaechliche Liste der vergebenen Seqs aus `build_msgs`.
Kein `lists:seq(Begin, End)` — das wuerde bei einem 32-Bit Wraparound
(Seq geht ueber `16#FFFFFFFF` auf 0) eine negative Range oder eine
gigantische Liste erzeugen. Die Map ist O(1) im Lookup und immun gegen
Wraparound.

## SET_ID: Same-Batch Referenzen

Wenn eine Map und ihre Elemente im selben Batch erstellt werden, kann
der Kernel die Map nicht per Name finden — sie ist noch nicht committed.
Stattdessen referenziert die Element-Insertion die Map per `SET_ID`,
einer Client-seitigen ID die beim Erstellen der Map vergeben wird:

```
Batch:
  1. NEWSET      name="__lb_web"  SET_ID=42     -- Map erstellen
  2. NEWSETELEM  set="__lb_web"   SET_ID=42     -- Elemente einfuegen (findet Map per ID)
  3. NEWCHAIN    name="prerouting_nat"           -- Chain erstellen
  4. NEWRULE     lookup set="__lb_web" SET_ID=42 -- Rule referenziert Map per ID
```

Ohne `SET_ID` wuerde der Kernel bei Nachricht 2 und 4 mit `ENOENT` antworten,
weil die Map per Name noch nicht im committed State existiert.

In erlkoenig vergeben wir die `SET_ID` deterministisch aus dem Map-Namen:

```erlang
MapId = erlang:phash2(MapName) band 16#FFFF,
```

Dieselbe ID wird in `nft_set:add_data_map`, `nft_set_elem:add_data_map_elems`
und `nft_expr_ir:lookup_data` verwendet.

`NFTA_SET_ELEM_LIST_SET_ID` wird nur gesendet wenn die ID > 0 ist.
Bei 0 sucht der Kernel die Map ausschliesslich per Name — das funktioniert
nur wenn die Map bereits committed ist (separater Batch).

## Batch-Reihenfolge

Die Reihenfolge der Nachrichten innerhalb eines Batches ist entscheidend.
Der Kernel verarbeitet sie sequentiell:

```
1. Counter      (koennen von Rules referenziert werden)
2. Maps/Sets    (muessen existieren bevor Elemente eingefuegt werden)
3. Map-Elemente (referenzieren Maps per SET_ID)
4. Chains       (muessen existieren bevor Rules eingefuegt werden)
5. Rules        (referenzieren Chains per Name, Maps per SET_ID)
```

In `erlkoenig_config.erl`:

```erlang
AllMsgs = CounterMsgs ++ AllMapCreates ++ AllChainCreates ++ AllRuleCreates,
```

`AllMapCreates` enthaelt `[CreateMap, AddElems]` Paare — in dieser
Reihenfolge, nicht umgekehrt. Das war ein Bug: `lists:reverse(MapMsgs)`
drehte die Reihenfolge, sodass Elemente vor der Map-Erstellung kamen.
Der Kernel konnte die pending Map per SET_ID nicht finden und der gesamte
atomare Batch wurde zurueckgerollt.

## Selektiver Flush

Mehrere Subsysteme teilen sich die `erlkoenig`-Tabelle:

- `erlkoenig_firewall_nft`: Container-Firewall (forward, prerouting, ...)
- `erlkoenig_config`: DSL nft_tables (jhash Maps, benutzerdefinierte Chains)
- `erlkoenig_nft_ct_guard`: Ban-Sets (blocklist, blocklist6)

Frueher machten alle `delete table + add table` um die Tabelle zu
"flushen". Das loeschte Objekte der anderen Subsysteme. Jetzt loescht
jedes Subsystem nur seine eigenen Objekte:

```erlang
flush_own_chains() ->
    OwnChains = [?FORWARD_CHAIN, ?POSTROUTING_CHAIN, ...],
    lists:foreach(fun(CN) ->
        _ = nfnl_server:apply_msgs(?SERVER, [
            fun(S) -> nft_delete:flush_chain(?FAMILY, ?TABLE, CN, S) end
        ]),
        _ = nfnl_server:apply_msgs(?SERVER, [
            fun(S) -> nft_delete:chain(?FAMILY, ?TABLE, CN, S) end
        ])
    end, OwnChains).
```

Jeder Flush ist ein separater Batch weil nicht-existierende Objekte
(beim ersten Start) den gesamten Batch mit `ENOENT` abbrechen wuerden.
Einzelne Fehler werden ignoriert (`_ =`).

Das ist ein Hotfix. Die saubere Architektur ist SPEC-EK-013: ein
Reconciler-Prozess der als Single Owner die Tabelle besitzt und alle
Subsysteme ueber deklarative Intents koordiniert.

## NETLINK_EXT_ACK

Der Socket setzt `NETLINK_EXT_ACK=1` (`SOL_NETLINK=270`):

```erlang
_ = socket:setopt_native(Sock, {270, 11}, <<1:32/native>>),
```

Damit sendet der Kernel bei Fehlern zusaetzliche Attribute im ACK:
`NLMSGERR_ATTR_MSG` (Fehlertext) und `NLMSGERR_ATTR_OFFS`
(Byte-Offset des fehlerhaften Attributs). Das macht Debugging von
`ENOENT` und `EINVAL` in verschachtelten nft-Attributen drastisch
einfacher — man sieht nicht nur "Objekt nicht gefunden" sondern
welches Attribut in welchem Offset das Problem verursacht hat.

## Offene Punkte

### Unified Sequence Management

`nft_object.erl` und `nft_query.erl` verwenden noch eine eigene
`seq()` Funktion. Sie sollten die Seq aus dem gen_server State
beziehen, damit es genau eine Seq-Quelle gibt.

### Dump-Responses

Queries mit `NLM_F_DUMP` (z.B. `list_chains`) erzeugen Multi-Message
Antworten mit vielen Nachrichten unter derselben Seq, terminiert durch
`NLMSG_DONE`. Das ist fundamental anders als Batch-ACKs und braucht
eine eigene `collect_dump` Funktion die `NLMSG_DONE` erkennt und
`NLM_F_DUMP_INTR` (inkonsistenter Dump) als Retry-Signal behandelt.

### Socket-Isolation

Der Request-Socket darf keine Multicast-Memberships haben. Ein
zukuenftiger Monitor-Socket fuer nft-Events muss ein separater
Socket in einem eigenen Prozess sein.
