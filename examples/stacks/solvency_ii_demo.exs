defmodule SolvencyIIDemo do
  @moduledoc """
  Solvency II Q4 Reserve Reconciliation — Erda Demo Stack.

  This stack defines the three pillars of the audit-honest demo:
  1. SAP FS-CD Mock (HANA source)
  2. Actuarial Fileshare Mock (Excel source)
  3. Erda Macro-Kernel Extractor (The Tier B Workload)

  The 'requires' blocks here are mandatory capability declarations.
  Erlkoenig uses them to build kernel-level security boundaries and
  automatically emit the corresponding Ontology Facts.
  """

  use Erlkoenig.Stack

  # ── 1. Host-Netzwerk & Zonen ─────────────────────────

  host do
    # Wir isolieren die Solvency-Welt in einer eigenen IPVLAN-Zone.
    ipvlan "solvency_net",
      parent: {:dummy, "ek_solv0"},
      subnet: {10, 80, 0, 0, 24}
  end

  # ── 2. Datenquellen (Die Mocks) ───────────────────────

  # SAP HANA Mock Container
  pod "sap_source" do
    container "hana_mock",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["30015"], # HANA Default Port Mock
      zone: "solvency_net" do
      
      publish interval: 5000 do
        metric :memory
      end
    end
  end

  # Actuarial Fileshare Mock (Simuliert das Excel-Laufwerk)
  pod "actuarial_source" do
    container "excel_mock",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["8080"],
      zone: "solvency_net" do
      
      # Simuliert ein persistentes Volume für das Excel-Sheet
      volume "/data/actuarial", persist: "reserves_q4", size: "100M"
    end
  end

  # ── 3. Der Erda-Extraktor (Tier B Workload) ──────────

  pod "erda_workload" do
    container "macro_kernel_extractor",
      binary: "/opt/erda/bin/solvency_extractor",
      zone: "solvency_net" do

      # --- DER ONTOLOGY-ANKER: REQUIRES ---
      
      # 1. Zugriff auf SAP (HANA) deklarieren
      requires :hana,
        name: "fscd",
        schema: "FSCD",
        tables: ["CLAIM_HEADER", "CLAIM_RESERVE"],
        mode: :ro

      # 2. Zugriff auf Aktuars-Daten (Excel via Fileshare) deklarieren
      requires :fileshare,
        name: "reserve_books",
        path: "Q4-2025/Reserves.xlsx",
        format: "excel",
        sheets: ["Claims", "Reserves"],
        mode: :ro

      # 3. Lokale KI für Mapping-Vorschläge (Local Inference)
      requires :local_inference,
        name: "embeddings",
        model: "bge-m3",
        mode: :embed

      # Verhindert jegliche Kommunikation nach außen
      forbids :internet

      # Ressourcen-Limits zur Absicherung des Hosts
      limits %{
        memory: 512_000_000,
        cpu: 50, # 50% eines Kerns max
        pids: 20
      }

      # Logging-Stream für die Evidence-Kette
      stream retention: {30, :days} do
        channel :stdout
        channel :stderr
      end
    end
  end
end
