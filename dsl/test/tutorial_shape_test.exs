defmodule Erlkoenig.TutorialShapeTest do
  use ExUnit.Case, async: false

  @moduledoc """
  Schema contract for the 6 tutorial files under `examples/tutorial/`.

  Asserts that each tutorial compiles cleanly and that its emitted
  term shape matches what the tutorial module's `@moduledoc`
  promises.  When a tutorial drifts (macro refactor, renamed field)
  this test fails with a specific message pointing at the mismatch.

  Runs under `make test-dsl` (no root, no live kernel).
  """

  @tutorial_dir Path.expand("../../examples/tutorial", __DIR__)

  defp compile_tutorial(file) do
    [{mod, _} | _] = Code.compile_file(Path.join(@tutorial_dir, file))
    mod.config()
  end

  # ════════════════════════════════════════════════════════════════
  # 01 — Overview: minimal stack
  # ════════════════════════════════════════════════════════════════

  describe "01_overview.exs" do
    setup do
      {:ok, config: compile_tutorial("01_overview.exs")}
    end

    test "emits one zone 'demo' at 10.10.0.0/24", %{config: c} do
      assert [zone] = c.zones
      assert zone.name == "demo"
      assert zone.subnet == {10, 10, 0, 0}
      assert zone.netmask == 24
      assert zone.network.mode == :ipvlan
      assert zone.pool.start == {10, 10, 0, 2}
      assert zone.pool.stop == {10, 10, 0, 254}
    end

    test "emits one pod 'hello' with container 'web'", %{config: c} do
      assert [pod] = c.pods
      assert pod.name == "hello"
      assert pod.strategy == :one_for_one
      assert [ct] = pod.containers
      assert ct.name == "web"
      assert ct.zone == "demo"
      assert ct.replicas == 1
      assert ct.restart == :permanent
      assert ct.limits.memory == 128_000_000
      assert ct.limits.pids == 64
    end

    test "emits host nft table with input_drop counter + input chain", %{config: c} do
      assert [table] = c.nft_tables
      assert table.name == "erlkoenig_host"
      assert table.family == :inet
      assert "input_drop" in table.counters
      chain_names = Enum.map(table.chains, & &1.name)
      assert "input" in chain_names
      input = Enum.find(table.chains, &(&1.name == "input"))
      assert input.policy == :drop
      assert input.hook == :input
    end

    test "has no guard block", %{config: c} do
      refute Map.has_key?(c, :ct_guard)
    end
  end

  # ════════════════════════════════════════════════════════════════
  # 02 — Capabilities: all 4 requires
  # ════════════════════════════════════════════════════════════════

  describe "02_capabilities.exs" do
    setup do
      {:ok, config: compile_tutorial("02_capabilities.exs")}
    end

    test "worker container declares all 4 capabilities", %{config: c} do
      [pod] = c.pods
      [ct] = pod.containers
      assert ct.name == "worker"
      # requires is a flat list of atoms; opts (hosts) surface as separate keys
      assert :"dns.local" in ct.requires
      assert :"dns.allowlist" in ct.requires
      assert :"journal.local" in ct.requires
      assert :"postgres.local" in ct.requires
    end

    test "dns.allowlist hosts surface as top-level :dns_allowlist", %{config: c} do
      [pod] = c.pods
      [ct] = pod.containers
      hosts = ct.dns_allowlist
      assert "api.openai.com" in hosts
      assert "*.s3.amazonaws.com" in hosts
      assert "registry.npmjs.org" in hosts
    end

    test "postgres capability injects socket_mounts entry", %{config: c} do
      [pod] = c.pods
      [ct] = pod.containers
      # :"postgres.local" + :"journal.local" both want /run/erlkoenig — dedup
      assert ct[:socket_mounts] != nil
      assert ct.socket_mounts != []
    end

    test "capability declarations do NOT auto-inject nft rules (Glasbox)", %{config: c} do
      # The operator writes UDP/53 etc. explicitly. We verify by checking
      # the output chain has the operator-declared rules verbatim.
      [pod] = c.pods
      [ct] = pod.containers
      chains = ct.nft.chains
      output = Enum.find(chains, &(&1.name == "output"))
      assert output != nil
      # Rules are a keyword list of {verdict, opts_map}
      dns_rule =
        Enum.find(output.rules, fn
          {:accept, %{ip_daddr: {10, 20, 0, 1}, udp_dport: 53}} -> true
          _ -> false
        end)
      assert dns_rule != nil, "expected explicit DNS rule to GW on UDP/53"
    end
  end

  # ════════════════════════════════════════════════════════════════
  # 03 — Firewall: full nft primitive coverage
  # ════════════════════════════════════════════════════════════════

  describe "03_firewall.exs" do
    setup do
      {:ok, config: compile_tutorial("03_firewall.exs")}
    end

    test "host table carries sets, counters, maps, vmaps, flowtables", %{config: c} do
      [table] = c.nft_tables

      # sets — list of 2-tuples (basic) and 3-tuples (cidr_set with flags)
      set_names = Enum.map(table.sets, &elem(&1, 0))
      assert "ban" in set_names
      assert "trusted_cidrs" in set_names

      assert "input_drop" in table.counters
      assert "input_ban" in table.counters
      assert "forward_drop" in table.counters

      map_names = Enum.map(table.maps, & &1.name)
      assert "lb_backends" in map_names

      vmap_names = Enum.map(table.vmaps, & &1.name)
      assert "port_dispatch" in vmap_names

      ft_names = Enum.map(table.flowtables, & &1.name)
      assert "ft0" in ft_names
    end

    test "host has 4 base chains covering all hooks", %{config: c} do
      [table] = c.nft_tables
      # Only consider base chains (hook != nil) — regular chains
      # (nft_chain) are vmap jump-targets and have no hook.
      hooks = table.chains
              |> Enum.filter(& &1[:hook])
              |> Enum.map(& &1.hook)
              |> Enum.sort()
      assert :prerouting in hooks
      assert :input in hooks
      assert :forward in hooks
      assert :postrouting in hooks
    end

    test "trusted_cidrs set carries the 4 declared CIDRs (interval flag)", %{config: c} do
      [table] = c.nft_tables
      {_, :ipv4_addr, meta} = Enum.find(table.sets, &(elem(&1, 0) == "trusted_cidrs"))
      assert :interval in meta.flags
      assert length(meta.elements) == 4
      assert "10.0.0.0/8" in meta.elements
      assert "198.51.100.42" in meta.elements
    end

    test "lb_backends map keyed by ipv4_addr → ipv4_addr", %{config: c} do
      [table] = c.nft_tables
      map = Enum.find(table.maps, &(&1.name == "lb_backends"))
      assert map.key_type == :ipv4_addr
      assert map.data_type == :ipv4_addr
    end

    test "port_dispatch vmap has 4 jump entries", %{config: c} do
      [table] = c.nft_tables
      vmap = Enum.find(table.vmaps, &(&1.name == "port_dispatch"))
      assert vmap.type == :inet_service
      assert length(vmap.entries) == 4
      assert {22, {:jump, "ssh_handler"}} in vmap.entries
      assert {5432, {:jump, "postgres_handler"}} in vmap.entries
    end

    test "container edge has chain-level conn_limit per_ip: 100", %{config: c} do
      [pod] = c.pods
      [ct] = pod.containers
      chains = ct.nft.chains
      has_connlimit =
        Enum.any?(chains, fn ch ->
          Enum.any?(ch.rules, fn
            {:connlimit_drop, %{max: 100}} -> true
            _ -> false
          end)
        end)
      assert has_connlimit, "expected chain-level conn_limit per_ip: 100 as :connlimit_drop"
    end
  end

  # ════════════════════════════════════════════════════════════════
  # 04 — Threat Detection: guard block (flat term shape)
  # ════════════════════════════════════════════════════════════════

  describe "04_threat_detection.exs" do
    setup do
      {:ok, config: compile_tutorial("04_threat_detection.exs")}
    end

    test "emits ct_guard with flat thresholds", %{config: c} do
      g = c.ct_guard
      # detect → flat keys
      assert g.conn_flood == {50, 10}
      assert g.port_scan == {20, 60}
      assert g.slow_scan == {5, 3600}
      assert is_list(g.honeypot_ports)
      assert 23 in g.honeypot_ports
      assert 3389 in g.honeypot_ports
      assert 6379 in g.honeypot_ports
    end

    test "emits respond-side thresholds (ban + escalation)", %{config: c} do
      g = c.ct_guard
      assert g.suspect_after == 3
      assert g.suspect_by == :ports
      assert g.ban_duration == 3600
      assert g.honeypot_ban_duration == 86_400
      assert g.escalation == [3600, 21600, 86_400, 604_800]
      assert g.probation == 120
      assert g.forget_after == 300
    end

    test "allowlist surfaces as :whitelist", %{config: c} do
      # DSL key `allowlist` gets flattened into `whitelist` (legacy name)
      assert {127, 0, 0, 1} in c.ct_guard.whitelist
      assert {10, 40, 0, 1} in c.ct_guard.whitelist
    end
  end

  # ════════════════════════════════════════════════════════════════
  # 05 — Storage & PKI: volumes + signatures
  # ════════════════════════════════════════════════════════════════

  describe "05_storage_and_pki.exs" do
    setup do
      {:ok, config: compile_tutorial("05_storage_and_pki.exs")}
    end

    test "db container has 4 volumes with correct mount/persist pairs", %{config: c} do
      [pod] = c.pods
      db = Enum.find(pod.containers, &(&1.name == "db"))
      assert db != nil
      assert length(db.volumes) == 4

      # Each volume map uses :container (mount path) and :persist
      data = Enum.find(db.volumes, &(&1.container == "/var/lib/postgresql/data"))
      assert data.persist == "postgres-data"
      assert data.read_only == false
      assert data.ephemeral == false

      etc = Enum.find(db.volumes, &(&1.container == "/etc/postgresql"))
      assert etc.read_only == true

      ingest = Enum.find(db.volumes, &(&1.container == "/srv/import"))
      assert ingest.opts =~ "nosuid"
      assert ingest.opts =~ "nodev"
      assert ingest.opts =~ "noexec"

      tmp = Enum.find(db.volumes, &(&1.container == "/tmp"))
      assert tmp.ephemeral == true
    end

    test "db container keeps signature verification as an operator note",
         %{config: c} do
      [pod] = c.pods
      db = Enum.find(pod.containers, &(&1.name == "db"))
      refute Map.has_key?(db, :signature_required)
    end

    test "db container propagates files injection map", %{config: c} do
      [pod] = c.pods
      db = Enum.find(pod.containers, &(&1.name == "db"))
      assert is_map(db.files)
      assert Map.has_key?(db.files, "/etc/db/tls.crt")
      assert Map.has_key?(db.files, "/etc/db/config.toml")
    end

    test "api container omits the unsigned demo signature path",
         %{config: c} do
      [pod] = c.pods
      api = Enum.find(pod.containers, &(&1.name == "api"))
      refute Map.has_key?(api, :sig_path)
    end

    test "api container has the expected cgroup limits", %{config: c} do
      [pod] = c.pods
      api = Enum.find(pod.containers, &(&1.name == "api"))
      assert api.limits.disk == 1_000_000_000
      assert api.limits.cpu == 50_000
      assert api.limits.memory == 256_000_000
      assert api.limits.pids == 128
    end

    test "api declares postgres/journal/dns capabilities", %{config: c} do
      [pod] = c.pods
      api = Enum.find(pod.containers, &(&1.name == "api"))
      assert :"postgres.local" in api.requires
      assert :"journal.local" in api.requires
      assert :"dns.local" in api.requires
    end
  end

  # ════════════════════════════════════════════════════════════════
  # 06 — Multi-tier: 3 pods, all strategies, replicas, replica_ips refs
  # ════════════════════════════════════════════════════════════════

  describe "06_multi_tier.exs" do
    setup do
      {:ok, config: compile_tutorial("06_multi_tier.exs")}
    end

    test "has 3 pods with the 3 different strategies", %{config: c} do
      assert length(c.pods) == 3
      names_strats =
        c.pods
        |> Enum.map(&{&1.name, &1.strategy})
        |> Enum.sort()
      assert {"backend", :rest_for_one} in names_strats
      assert {"data", :one_for_all} in names_strats
      assert {"frontend", :one_for_one} in names_strats
    end

    test "has 2 zones (edge + internal) with disjoint subnets", %{config: c} do
      names = c.zones |> Enum.map(& &1.name) |> Enum.sort()
      assert names == ["edge", "internal"]
      edge = Enum.find(c.zones, &(&1.name == "edge"))
      internal = Enum.find(c.zones, &(&1.name == "internal"))
      assert edge.subnet == {10, 60, 0, 0}
      assert internal.subnet == {10, 61, 0, 0}
    end

    test "frontend nginx has replicas: 3 in edge zone", %{config: c} do
      fe = Enum.find(c.pods, &(&1.name == "frontend"))
      [nginx] = fe.containers
      assert nginx.replicas == 3
      assert nginx.zone == "edge"
    end

    test "backend pod has api (4 replicas) + metrics (4 replicas)", %{config: c} do
      be = Enum.find(c.pods, &(&1.name == "backend"))
      api = Enum.find(be.containers, &(&1.name == "api"))
      metrics = Enum.find(be.containers, &(&1.name == "metrics"))
      assert api.replicas == 4
      assert api.zone == "internal"
      assert metrics.replicas == 4
    end

    test "data pod has postgres + backup with memory-/disk-limits", %{config: c} do
      d = Enum.find(c.pods, &(&1.name == "data"))
      pg = Enum.find(d.containers, &(&1.name == "postgres"))
      bk = Enum.find(d.containers, &(&1.name == "backup"))
      assert pg.replicas == 1
      assert pg.limits.disk == 10_000_000_000
      assert bk.replicas == 1
    end

    test "replica_ips tuples live in host forward chain, NOT container nft " <>
         "(Glasbox: only host has the full IpMap at apply time)", %{config: c} do
      [table] = c.nft_tables
      forward = Enum.find(table.chains, &(&1.name == "forward"))
      assert forward != nil
      # Expect at least 3 cross-container rules referencing replica_ips.
      replica_refs =
        Enum.count(forward.rules, fn
          {_verdict, %{ip_saddr: {:replica_ips, _, _}}} -> true
          {_verdict, %{ip_daddr: {:replica_ips, _, _}}} -> true
          _ -> false
        end)
      assert replica_refs >= 3,
             "expected ≥3 replica_ips refs in host forward chain, " <>
             "got #{replica_refs}"

      # And container-local nft must NOT carry any replica_ips refs —
      # the DSL would compile it, but the container-nft translator
      # fails loud at runtime (SPEC-EK-023 §4).
      fe = Enum.find(c.pods, &(&1.name == "frontend"))
      [nginx] = fe.containers
      leaked =
        nginx.nft.chains
        |> Enum.flat_map(& &1.rules)
        |> Enum.any?(fn
          {_, %{ip_saddr: {:replica_ips, _, _}}} -> true
          {_, %{ip_daddr: {:replica_ips, _, _}}} -> true
          _ -> false
        end)
      refute leaked, "container-local nft must not carry replica_ips refs"
    end

    test "host nft table has api_backends jhash map", %{config: c} do
      [table] = c.nft_tables
      map_names = Enum.map(table.maps, & &1.name)
      assert "api_backends" in map_names
      api_backends = Enum.find(table.maps, &(&1.name == "api_backends"))
      assert api_backends.key_type == :inet_service
      assert api_backends.data_type == :ipv4_addr
    end

    test "has ct_guard block with 2 zone gateways in whitelist", %{config: c} do
      assert {10, 60, 0, 1} in c.ct_guard.whitelist
      assert {10, 61, 0, 1} in c.ct_guard.whitelist
    end
  end
end
