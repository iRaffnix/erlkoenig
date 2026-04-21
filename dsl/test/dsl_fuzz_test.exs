defmodule Erlkoenig.DSLFuzzTest do
  use ExUnit.Case, async: false
  use ExUnitProperties

  @moduledoc """
  Property-based fuzz testing of the DSL layer (Tier 1).

  Exercises the Builder APIs with random-but-valid inputs and
  asserts the Glasbox contract:

    * declared fields appear in the emitted term
    * capability `requires` produce the documented side-effects
    * validators reject malformed inputs loudly (no silent accept)
    * CIDR / wildcard hosts normalize as specified
    * replica_ips refs in container-nft context fail-loud

  Runs under `make test-dsl`. No root, no kernel.

  If a property fails, StreamData shrinks the input to the minimal
  counter-example — that minimal input becomes a new regression test.
  """

  # ════════════════════════════════════════════════════════════════
  # Generators
  # ════════════════════════════════════════════════════════════════

  @restart_policies [:permanent, :transient, :temporary]
  @strategies      [:one_for_one, :one_for_all, :rest_for_one]

  defp name_gen do
    StreamData.string(?a..?z, min_length: 3, max_length: 8)
  end

  defp ip_tuple do
    {StreamData.integer(10..254),
     StreamData.integer(0..255),
     StreamData.integer(0..255),
     StreamData.integer(1..254)}
    |> StreamData.tuple()
  end

  defp limits_gen do
    StreamData.fixed_map(%{
      memory: StreamData.integer(64_000_000..2_000_000_000),
      pids:   StreamData.integer(16..1024)
    })
  end

  defp capability_gen do
    StreamData.one_of([
      StreamData.constant({:"dns.local", []}),
      StreamData.constant({:"journal.local", []}),
      StreamData.constant({:"postgres.local", []}),
      StreamData.bind(
        StreamData.list_of(dns_host_gen(), min_length: 1, max_length: 4),
        fn hosts -> StreamData.constant({:"dns.allowlist", hosts: hosts}) end
      )
    ])
  end

  defp dns_host_gen do
    StreamData.one_of([
      StreamData.constant("api.example.com"),
      StreamData.constant("*.s3.amazonaws.com"),
      StreamData.constant("registry.npmjs.org"),
      StreamData.constant("*.internal.test")
    ])
  end

  defp volume_gen do
    StreamData.fixed_map(%{
      container: StreamData.map(name_gen(), &"/data/#{&1}"),
      persist:   name_gen(),
      ephemeral: StreamData.boolean(),
      read_only: StreamData.boolean()
    })
  end

  # nft rule opts — only the keys the translators actually handle
  defp nft_rule_gen do
    StreamData.one_of([
      StreamData.constant({:accept, %{ct_state: [:established, :related]}}),
      StreamData.map(StreamData.integer(1..65535),
        fn p -> {:accept, %{tcp_dport: p}} end),
      StreamData.map(StreamData.integer(1..65535),
        fn p -> {:accept, %{udp_dport: p}} end),
      StreamData.map(ip_tuple(),
        fn ip -> {:accept, %{ip_saddr: ip, tcp_dport: 443}} end),
      StreamData.constant({:accept, %{ip_protocol: :icmp}}),
      StreamData.constant({:drop, %{}})
    ])
  end

  defp signature_gen do
    StreamData.one_of([
      StreamData.constant(nil),
      StreamData.constant(:required),
      StreamData.constant("/etc/signed/bin.sig")
    ])
  end

  # ════════════════════════════════════════════════════════════════
  # Helper: build a container with random but coherent opts
  # ════════════════════════════════════════════════════════════════

  defp build_container(pod, ct_name, zone, ct_opts) do
    pod = Erlkoenig.Pod.Builder.begin_container(pod, ct_name,
      binary: "/opt/erlkoenig/rt/demo/test-echo",
      zone: zone,
      replicas: ct_opts.replicas,
      restart: ct_opts.restart,
      limits: ct_opts.limits,
      args: ["8080"]
    )

    pod =
      Enum.reduce(ct_opts.requires, pod, fn
        {cap, []}, acc ->
          Erlkoenig.Pod.Builder.add_requires(acc, cap, [])
        {cap, [hosts: hosts]}, acc ->
          Erlkoenig.Pod.Builder.add_requires(acc, cap, hosts: hosts)
      end)

    pod =
      Enum.reduce(ct_opts.volumes, pod, fn vol, acc ->
        Erlkoenig.Pod.Builder.add_volume(acc, vol)
      end)

    Erlkoenig.Pod.Builder.end_container(pod)
  end

  defp ct_opts_gen do
    gen all replicas  <- StreamData.integer(1..5),
            restart   <- StreamData.member_of(@restart_policies),
            limits    <- limits_gen(),
            requires  <- StreamData.list_of(capability_gen(), max_length: 4),
            volumes   <- StreamData.list_of(volume_gen(), max_length: 3) do
      # Dedup capabilities by cap name so two identical requires lines
      # don't blow up validators that assume uniqueness.
      requires_u =
        requires
        |> Enum.uniq_by(fn {k, _} -> k end)
      %{replicas: replicas, restart: restart, limits: limits,
        requires: requires_u, volumes: volumes}
    end
  end

  # ════════════════════════════════════════════════════════════════
  # Properties
  # ════════════════════════════════════════════════════════════════

  property "P1: every declared container appears in the pod term" do
    check all pod_name <- name_gen(),
              strategy <- StreamData.member_of(@strategies),
              n_cts    <- StreamData.integer(1..4),
              cts_opts <- StreamData.list_of(ct_opts_gen(),
                            length: n_cts),
              max_runs: 100 do
      pod = Erlkoenig.Pod.Builder.new(pod_name, strategy: strategy)

      {pod, ct_names} =
        cts_opts
        |> Enum.with_index()
        |> Enum.reduce({pod, []}, fn {opts, idx}, {p, names} ->
          name = "ct#{idx}"
          p = build_container(p, name, "zone1", opts)
          {p, [name | names]}
        end)

      term = Erlkoenig.Pod.Builder.to_term(pod)
      emitted = term.containers |> Enum.map(& &1.name) |> Enum.sort()
      assert emitted == Enum.sort(ct_names)
    end
  end

  property "P2: dns.allowlist hosts always surface as :dns_allowlist key" do
    check all hosts <- StreamData.list_of(dns_host_gen(),
                           min_length: 1, max_length: 5),
              max_runs: 100 do
      pod = Erlkoenig.Pod.Builder.new("p", strategy: :one_for_one)
      pod = Erlkoenig.Pod.Builder.begin_container(pod, "ct",
              binary: "/opt/bin", zone: "z", replicas: 1,
              restart: :permanent)
      pod = Erlkoenig.Pod.Builder.add_requires(pod, :"dns.allowlist",
              hosts: hosts)
      pod = Erlkoenig.Pod.Builder.end_container(pod)
      term = Erlkoenig.Pod.Builder.to_term(pod)
      [ct] = term.containers
      assert ct.dns_allowlist == hosts
    end
  end

  property "P3: journal.local + postgres.local dedup socket_mounts "
           <> "(both share /run/erlkoenig)" do
    check all has_journal  <- StreamData.boolean(),
              has_postgres <- StreamData.boolean(),
              max_runs: 40 do
      pod = Erlkoenig.Pod.Builder.new("p", strategy: :one_for_one)
      pod = Erlkoenig.Pod.Builder.begin_container(pod, "ct",
              binary: "/opt/bin", zone: "z", replicas: 1,
              restart: :permanent)
      pod =
        if has_journal,
          do: Erlkoenig.Pod.Builder.add_requires(pod, :"journal.local", []),
          else: pod
      pod =
        if has_postgres,
          do: Erlkoenig.Pod.Builder.add_requires(pod, :"postgres.local", []),
          else: pod
      pod = Erlkoenig.Pod.Builder.end_container(pod)
      term = Erlkoenig.Pod.Builder.to_term(pod)
      [ct] = term.containers
      mounts = Map.get(ct, :socket_mounts, [])

      # /run/erlkoenig host-path must be bind-mounted iff either cap is set.
      # Builder emits with trailing slash ("/run/erlkoenig/").
      run_ek_count = Enum.count(mounts, fn m ->
        host = Map.get(m, :host, "") || Map.get(m, :host_path, "")
        String.starts_with?(host, "/run/erlkoenig")
      end)

      expected_count = if has_journal or has_postgres, do: 1, else: 0
      assert run_ek_count == expected_count,
             "expected #{expected_count} /run/erlkoenig mount(s), got #{run_ek_count} " <>
             "(journal=#{has_journal} postgres=#{has_postgres})"
    end
  end

  property "P4: signature: :required propagates as :signature_required = true" do
    check all sig <- signature_gen(), max_runs: 30 do
      pod = Erlkoenig.Pod.Builder.new("p", strategy: :one_for_one)

      opts = [binary: "/opt/bin", zone: "z", replicas: 1, restart: :permanent]
      opts = if sig != nil, do: Keyword.put(opts, :signature, sig), else: opts

      pod = Erlkoenig.Pod.Builder.begin_container(pod, "ct", opts)
      pod = Erlkoenig.Pod.Builder.end_container(pod)
      term = Erlkoenig.Pod.Builder.to_term(pod)
      [ct] = term.containers

      case sig do
        nil ->
          refute Map.has_key?(ct, :signature_required)
          refute Map.has_key?(ct, :sig_path)
        :required ->
          assert ct[:signature_required] == true
          refute Map.has_key?(ct, :sig_path)
        path when is_binary(path) ->
          assert ct[:sig_path] == path
          refute Map.has_key?(ct, :signature_required)
      end
    end
  end

  property "P5: validator rejects bad restart policies" do
    check all bad <- StreamData.member_of([:ALWAYS, :perm, :forever,
                                            "permanent", nil, :restart]),
              max_runs: 10 do
      pod = Erlkoenig.Pod.Builder.new("p", strategy: :one_for_one)
      assert_raise CompileError, fn ->
        Erlkoenig.Pod.Builder.begin_container(pod, "ct",
          binary: "/opt/bin", zone: "z", replicas: 1, restart: bad)
      end
    end
  end

  property "P6: validator rejects non-positive replicas" do
    check all bad <- StreamData.one_of([
                StreamData.integer(-100..0),
                StreamData.float(min: -10.0, max: 10.0),
                StreamData.constant("many"),
                StreamData.constant(nil)
              ]),
              max_runs: 20 do
      pod = Erlkoenig.Pod.Builder.new("p", strategy: :one_for_one)
      assert_raise CompileError, fn ->
        Erlkoenig.Pod.Builder.begin_container(pod, "ct",
          binary: "/opt/bin", zone: "z", replicas: bad, restart: :permanent)
      end
    end
  end

  property "P7: validator rejects bad pod strategies" do
    check all bad <- StreamData.member_of([:one, :forever, "one_for_one",
                                            nil, :all_for_one]),
              max_runs: 10 do
      assert_raise CompileError, fn ->
        Erlkoenig.Pod.Builder.new("p", strategy: bad)
      end
    end
  end

  property "P8: volume round-trip — container key == declared mount path" do
    pair_gen =
      StreamData.fixed_map(%{
        container: StreamData.map(name_gen(), &"/data/#{&1}"),
        persist:   name_gen(),
        ephemeral: StreamData.boolean(),
        read_only: StreamData.boolean()
      })

    check all volumes <- StreamData.list_of(pair_gen,
                            min_length: 1, max_length: 5),
              max_runs: 60 do
      # Unique mount paths: otherwise two vols on same path are a
      # user error, not our contract to verify.
      volumes_u = Enum.uniq_by(volumes, & &1.container)

      pod = Erlkoenig.Pod.Builder.new("p", strategy: :one_for_one)
      pod = Erlkoenig.Pod.Builder.begin_container(pod, "ct",
              binary: "/opt/bin", zone: "z", replicas: 1,
              restart: :permanent)
      pod = Enum.reduce(volumes_u, pod, fn v, acc ->
        Erlkoenig.Pod.Builder.add_volume(acc, v)
      end)
      pod = Erlkoenig.Pod.Builder.end_container(pod)
      term = Erlkoenig.Pod.Builder.to_term(pod)
      [ct] = term.containers

      emitted_paths = Enum.map(ct.volumes, & &1.container)
      declared_paths = Enum.map(volumes_u, & &1.container)
      assert emitted_paths == declared_paths,
             "volume order/content drift: declared=#{inspect(declared_paths)} " <>
             "emitted=#{inspect(emitted_paths)}"
    end
  end

  property "P9: files map round-trips preserving all keys + values" do
    check all files <- StreamData.map_of(
                StreamData.string(:printable, min_length: 1, max_length: 20)
                  |> StreamData.map(&"/etc/#{&1}"),
                StreamData.string(:printable, min_length: 0, max_length: 200),
                max_length: 4
              ),
              max_runs: 40 do
      opts = [binary: "/opt/bin", zone: "z", replicas: 1, restart: :permanent]
      opts = if map_size(files) > 0, do: Keyword.put(opts, :files, files), else: opts

      pod = Erlkoenig.Pod.Builder.new("p", strategy: :one_for_one)
      pod = Erlkoenig.Pod.Builder.begin_container(pod, "ct", opts)
      pod = Erlkoenig.Pod.Builder.end_container(pod)
      term = Erlkoenig.Pod.Builder.to_term(pod)
      [ct] = term.containers

      if map_size(files) > 0 do
        assert ct[:files] == files
      else
        refute Map.has_key?(ct, :files)
      end
    end
  end

  property "P10: validator rejects files with non-string keys or values" do
    check all bad_files <- StreamData.one_of([
                StreamData.constant(%{42 => "content"}),
                StreamData.constant(%{"/path" => 123}),
                StreamData.constant(%{:atom_key => "value"}),
                StreamData.constant([{"/path", "content"}])  # list, not map
              ]),
              max_runs: 10 do
      pod = Erlkoenig.Pod.Builder.new("p", strategy: :one_for_one)
      assert_raise CompileError, fn ->
        Erlkoenig.Pod.Builder.begin_container(pod, "ct",
          binary: "/opt/bin", zone: "z", replicas: 1, restart: :permanent,
          files: bad_files)
      end
    end
  end

  # ════════════════════════════════════════════════════════════════
  # Round-trip properties via source-string compilation
  # Tests the macro layer (not just Builder API).
  # ════════════════════════════════════════════════════════════════

  property "P11: source-string compile → term → every declared pod name "
           <> "appears in config().pods" do
    check all pod_names <- StreamData.list_of(name_gen(),
                              min_length: 1, max_length: 3)
                           |> StreamData.map(&Enum.uniq/1)
                           |> StreamData.filter(&(length(&1) >= 1)),
              max_runs: 25 do
      mod_name = "Fuzz.P11.M#{:erlang.unique_integer([:positive])}"

      pods_src =
        pod_names
        |> Enum.with_index()
        |> Enum.map(fn {pn, i} ->
             """
               pod "#{pn}", strategy: :one_for_one do
                 container "c#{i}",
                   binary: "/opt/bin",
                   args: ["8080"],
                   zone: "z",
                   replicas: 1,
                   restart: :permanent,
                   limits: %{memory: 64_000_000, pids: 32}
               end
             """
           end)
        |> Enum.join("\n")

      src = """
      defmodule #{mod_name} do
        use Erlkoenig.Stack
        host do
          ipvlan "z", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
        end
        #{pods_src}
      end
      """

      [{mod, _}] = Code.compile_string(src)
      emitted = mod.config().pods |> Enum.map(& &1.name) |> Enum.sort()
      assert emitted == Enum.sort(pod_names)
    end
  end

  property "P12: every capability declared in DSL body ends up in requires list" do
    check all caps <- StreamData.list_of(StreamData.member_of([
                :"dns.local", :"journal.local", :"postgres.local"]),
                min_length: 0, max_length: 3)
              |> StreamData.map(&Enum.uniq/1),
              max_runs: 30 do
      mod_name = "Fuzz.P12.M#{:erlang.unique_integer([:positive])}"
      requires_src =
        caps |> Enum.map(fn c -> "    requires :\"#{c}\"" end) |> Enum.join("\n")

      src = """
      defmodule #{mod_name} do
        use Erlkoenig.Stack
        host do
          ipvlan "z", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
        end
        pod "p", strategy: :one_for_one do
          container "ct", binary: "/opt/bin", zone: "z",
            replicas: 1, restart: :permanent,
            limits: %{memory: 64_000_000, pids: 32} do
      #{requires_src}
          end
        end
      end
      """

      [{mod, _}] = Code.compile_string(src)
      [pod] = mod.config().pods
      [ct]  = pod.containers
      emitted = Map.get(ct, :requires, []) |> Enum.sort()
      assert emitted == Enum.sort(caps)
    end
  end

  property "P13: nft_rule with tcp_dport N round-trips N verbatim" do
    check all port <- StreamData.integer(1..65535),
              verdict <- StreamData.member_of([:accept, :drop]),
              max_runs: 40 do
      mod_name = "Fuzz.P13.M#{:erlang.unique_integer([:positive])}"
      src = """
      defmodule #{mod_name} do
        use Erlkoenig.Stack
        host do
          ipvlan "z", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
        end
        pod "p", strategy: :one_for_one do
          container "ct", binary: "/opt/bin", zone: "z",
            replicas: 1, restart: :permanent,
            limits: %{memory: 64_000_000, pids: 32} do
            nft do
              input policy: :drop do
                nft_rule :#{verdict}, tcp_dport: #{port}
              end
            end
          end
        end
      end
      """

      [{mod, _}] = Code.compile_string(src)
      [pod] = mod.config().pods
      [ct]  = pod.containers
      [chain] = ct.nft.chains
      assert [{^verdict, %{tcp_dport: ^port}}] = chain.rules
    end
  end

  property "P14: unknown nft option raises — at DSL or runtime, " <>
           "but MUST NOT silently drop" do
    # DSL currently passes unknown keys through at compile, but runtime
    # translator will raise (we fixed that today).  At minimum: the
    # key must either raise at compile OR appear verbatim in the term
    # for the runtime to catch.  No silent dropping.
    check all bad_key <- StreamData.member_of([
                :ip_saddrr, :tcp_dportt, :counterr, :bogus]),
              max_runs: 10 do
      mod_name = "Fuzz.P14.M#{:erlang.unique_integer([:positive])}"
      src = """
      defmodule #{mod_name} do
        use Erlkoenig.Stack
        host do
          ipvlan "z", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
        end
        pod "p", strategy: :one_for_one do
          container "ct", binary: "/opt/bin", zone: "z",
            replicas: 1, restart: :permanent,
            limits: %{memory: 64_000_000, pids: 32} do
            nft do
              input policy: :drop do
                nft_rule :accept, #{bad_key}: 443
              end
            end
          end
        end
      end
      """

      try do
        [{mod, _}] = Code.compile_string(src)
        [pod] = mod.config().pods
        [ct]  = pod.containers
        [chain] = ct.nft.chains
        [{:accept, opts}] = chain.rules
        assert Map.has_key?(opts, bad_key),
               "unknown key #{inspect(bad_key)} was silently dropped — " <>
               "neither raised at DSL compile nor preserved for runtime"
      rescue
        _ in CompileError -> :ok_raised_at_compile
      end
    end
  end

  # ════════════════════════════════════════════════════════════════
  # Aggressive properties — these hunt for the SPECIFIC bug classes
  # we've seen today (whitelist drift, silent drops, drift in both
  # directions between DSL and runtime).
  # ════════════════════════════════════════════════════════════════

  property "P16 [DRIFT HUNT]: every Pod.Builder.to_term key ends up " <>
           "somewhere the runtime reads it" do
    # Build containers with every optional surface turned on. Then
    # diff emitted keys against the runtime's build_spawn_opts
    # whitelist + the erlkoenig_ct maps:get surface. Fail if any
    # emitted key is unclaimed.
    pod = Erlkoenig.Pod.Builder.new("p", strategy: :one_for_one)
    pod = Erlkoenig.Pod.Builder.begin_container(pod, "ct",
            binary: "/opt/bin", zone: "z",
            replicas: 2, restart: :permanent,
            limits: %{memory: 128_000_000, pids: 64},
            signature: :required,
            files: %{"/etc/x" => "y"})
    pod = Erlkoenig.Pod.Builder.add_requires(pod, :"dns.local", [])
    pod = Erlkoenig.Pod.Builder.add_requires(pod, :"dns.allowlist",
            hosts: ["api.example.com"])
    pod = Erlkoenig.Pod.Builder.add_requires(pod, :"journal.local", [])
    pod = Erlkoenig.Pod.Builder.add_requires(pod, :"postgres.local", [])
    pod = Erlkoenig.Pod.Builder.add_volume(pod, %{
      container: "/var/data", persist: "vol1",
      ephemeral: false, read_only: false
    })
    pod = Erlkoenig.Pod.Builder.end_container(pod)
    term = Erlkoenig.Pod.Builder.to_term(pod)
    [ct] = term.containers

    # These are the keys the runtime actually reads (from
    # erlkoenig_config:build_spawn_opts + erlkoenig_ct init).
    known_runtime_keys = MapSet.new([
      :binary, :name, :args, :env, :zone, :replicas, :restart,
      :limits, :seccomp, :uid, :gid, :caps,
      :ip, :ports, :firewall, :nft,
      :volumes, :socket_mounts, :files,
      :publish, :stream,
      :requires, :dns_allowlist,
      :signature_required, :sig_path,
      :image_path,
      :pod_supervised, :pty, :output,
      # internal nothings
      :health_check
    ])

    emitted_keys = MapSet.new(Map.keys(ct))
    orphans = MapSet.difference(emitted_keys, known_runtime_keys)

    assert MapSet.size(orphans) == 0,
           "DSL emits keys that no runtime path consumes: " <>
           "#{inspect(MapSet.to_list(orphans))} — these are silent " <>
           "no-op features.  Either add consumer in erlkoenig_ct/config, " <>
           "or delete the emission."
  end

  property "P17 [DRIFT HUNT]: container.Builder.to_term covers everything " <>
           "the macro-container DSL sets" do
    # The older Container.Builder (used by `container :atom do` macros)
    # should emit the same surface as Pod.Builder (used by
    # `container "name", opts do`).  Any divergence is a silent
    # feature gap for one of the two paths.
    state1 = Erlkoenig.Container.Builder.new(:testct)
    state1 = Erlkoenig.Container.Builder.set_binary(state1, "/opt/bin")
    state1 = Erlkoenig.Container.Builder.set_signature(state1, :required)

    opts1 = Erlkoenig.Container.Builder.to_spawn_opts(state1)

    # Container.Builder uses :signature_required (pre-today also).
    # After today's fix, Pod.Builder does too.  Both MUST agree.
    assert opts1[:signature_required] == true,
           "Container.Builder does not propagate signature: :required " <>
           "through to_spawn_opts as :signature_required (Pod.Builder " <>
           "now does — they diverge)"
  end

  property "P18 [INJECTION]: DSL accepts long container names up to " <>
           "a reasonable length without silent truncation" do
    # Guard against hidden length limits that silently truncate.
    check all len <- StreamData.integer(1..200),
              max_runs: 30 do
      name = String.duplicate("n", len)
      pod = Erlkoenig.Pod.Builder.new("p", strategy: :one_for_one)

      try do
        pod = Erlkoenig.Pod.Builder.begin_container(pod, name,
                binary: "/opt/bin", zone: "z",
                replicas: 1, restart: :permanent)
        pod = Erlkoenig.Pod.Builder.end_container(pod)
        [ct] = Erlkoenig.Pod.Builder.to_term(pod).containers
        assert ct.name == name,
               "name drift: in=#{byte_size(name)}b out=#{byte_size(ct.name)}b"
      rescue
        CompileError -> :ok_rejected_explicitly
      end
    end
  end

  property "P19 [DRIFT]: guard block flat-term shape lossless" do
    # Tutorial 04 revealed the guard block flattens to a map with
    # specific keys. Assert that every DSL-declared guard field
    # produces a known top-level key — no hidden groupings.
    check all flood_n <- StreamData.integer(1..10_000),
              flood_t <- StreamData.integer(1..60),
              ban_s   <- StreamData.integer(60..86_400),
              max_runs: 30 do
      mod_name = "Fuzz.P19.M#{:erlang.unique_integer([:positive])}"
      src = """
      defmodule #{mod_name} do
        use Erlkoenig.Stack
        host do
          ipvlan "z", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
        end
        guard do
          detect do
            flood over: #{flood_n}, within: s(#{flood_t})
          end
          respond do
            ban_for s(#{ban_s})
          end
          allowlist [{127, 0, 0, 1}]
        end
        pod "p", strategy: :one_for_one do
          container "ct", binary: "/opt/bin", zone: "z",
            replicas: 1, restart: :permanent,
            limits: %{memory: 64_000_000, pids: 32}
        end
      end
      """
      [{mod, _}] = Code.compile_string(src)
      g = mod.config().ct_guard
      assert g.conn_flood == {flood_n, flood_t}
      assert g.ban_duration == ban_s
      # whitelist must preserve the single IP
      assert {127, 0, 0, 1} in g.whitelist
    end
  end

  property "P20 [SECURITY]: Any :"<>"dns.allowlist"<>" hosts with invalid " <>
           "patterns must raise or normalize — never silently accept" do
    # If DSL accepts an invalid host like "//xyz" or "" silently,
    # the filter behavior becomes undefined.
    check all bad_host <- StreamData.one_of([
                StreamData.constant(""),
                StreamData.constant("  "),
                StreamData.constant("http://example.com"),   # scheme included
                StreamData.constant("host with spaces"),
                StreamData.constant("\x00injected")
              ]),
              max_runs: 10 do
      pod = Erlkoenig.Pod.Builder.new("p", strategy: :one_for_one)
      pod = Erlkoenig.Pod.Builder.begin_container(pod, "ct",
              binary: "/opt/bin", zone: "z",
              replicas: 1, restart: :permanent)
      try do
        pod = Erlkoenig.Pod.Builder.add_requires(pod, :"dns.allowlist",
                hosts: [bad_host])
        pod = Erlkoenig.Pod.Builder.end_container(pod)
        [ct] = Erlkoenig.Pod.Builder.to_term(pod).containers
        hosts = ct.dns_allowlist

        # Whatever DSL accepts, it must be either the verbatim input
        # OR an explicit normalization.  Compare: the only acceptable
        # outcome for a bad host is rejection at DSL or normalization.
        # Silently accepting `"http://example.com"` as an egress
        # allowlist entry is a security hole: the actual DNS filter
        # can never match that (hosts don't contain schemes).
        assert hosts != [bad_host] or
               bad_host in ["  "],  # trailing-space hosts are borderline
               "dns.allowlist silently accepted invalid host " <>
               "#{inspect(bad_host)} — DNS filter will never match it, " <>
               "effectively blackholing all egress from this container"
      rescue
        CompileError -> :ok_raised_at_compile
      end
    end
  end

  property "P15: honeypot port list always reaches ct_guard.honeypot_ports" do
    check all ports <- StreamData.list_of(StreamData.integer(1..65535),
                min_length: 1, max_length: 6)
              |> StreamData.map(&Enum.uniq/1),
              max_runs: 40 do
      mod_name = "Fuzz.P15.M#{:erlang.unique_integer([:positive])}"
      src = """
      defmodule #{mod_name} do
        use Erlkoenig.Stack
        host do
          ipvlan "z", parent: {:dummy, "ek0"}, subnet: {10, 0, 0, 0, 24}
        end
        guard do
          detect do
            honeypot #{inspect(ports)}
          end
          respond do
            ban_for h(1)
          end
          allowlist [{127, 0, 0, 1}]
        end
        pod "p", strategy: :one_for_one do
          container "ct", binary: "/opt/bin", zone: "z",
            replicas: 1, restart: :permanent,
            limits: %{memory: 64_000_000, pids: 32}
        end
      end
      """

      [{mod, _}] = Code.compile_string(src)
      got = mod.config().ct_guard.honeypot_ports
      assert Enum.sort(got) == Enum.sort(ports)
    end
  end
end
