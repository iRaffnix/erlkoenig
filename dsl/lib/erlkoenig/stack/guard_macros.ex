defmodule Erlkoenig.Stack.GuardMacros do
  @moduledoc false

  # ═══════════════════════════════════════════════════════════

  # ═══════════════════════════════════════════════════════════
  # guard / watch — Erlang runtime
  # ═══════════════════════════════════════════════════════════

  @doc """
  Configure the reactive threat detection guard.

  Each suspicious source IP gets its own Erlang process
  (`erlkoenig_threat_actor`, gen_statem) with a lifecycle:

      observing → suspicious → banned → probation → (process dies)

  Actors detect floods, port scans, slow scans, and honeypot probes.
  Ban decisions flow through `erlkoenig_threat_mesh` — the single
  process that writes to the kernel blocklist. Kernel bans have
  built-in timeouts and auto-expire even if the BEAM crashes.

  ## Structure

  Three blocks — what we detect, how we respond, who we exempt:

  ## Examples

      guard do
        detect do
          flood over: 50, within: s(10)
          port_scan over: 20, within: m(1)
          slow_scan over: 5, within: h(1)
          honeypot [21, 22, 23, 445, 1433, 1521, 3306,
                    3389, 5900, 6379, 8080, 8888, 9200, 27017]
        end

        respond do
          suspect after: 3, distinct: :ports
          ban_for h(1)
          honeypot_ban_for h(24)
          escalate [h(1), h(6), h(24), d(7)]
          observe_after_unban m(2)
          forget_after m(5)
        end

        allowlist [
          {127, 0, 0, 1},
          {10, 0, 0, 1}
        ]
      end
  """
  defmacro guard(do: block) do
    quote do
      var!(ek_guard_builder) = ErlkoenigNft.Guard.Builder.new()
      unquote(block)
      @stack_guard ErlkoenigNft.Guard.Builder.to_term(var!(ek_guard_builder))
    end
  end

  # ── detect block ──────────────────────────────────────

  @doc "Open the detection block. Contains `flood`, `port_scan`, `slow_scan`, `honeypot`."
  defmacro detect(do: block) do
    quote do
      unquote(block)
    end
  end

  @doc "Detect connection floods: too many connections from one IP."
  defmacro flood(opts) do
    over = Keyword.fetch!(opts, :over)
    within = Keyword.fetch!(opts, :within)

    quote do
      var!(ek_guard_builder) =
        ErlkoenigNft.Guard.Builder.add_flood(
          var!(ek_guard_builder),
          unquote(over),
          unquote(within)
        )
    end
  end

  @doc "Detect port scans: too many distinct destination ports from one IP."
  defmacro port_scan(opts) do
    over = Keyword.fetch!(opts, :over)
    within = Keyword.fetch!(opts, :within)

    quote do
      var!(ek_guard_builder) =
        ErlkoenigNft.Guard.Builder.add_port_scan(
          var!(ek_guard_builder),
          unquote(over),
          unquote(within)
        )
    end
  end

  @doc "Detect slow scans: distinct ports over a long window."
  defmacro slow_scan(opts) do
    over = Keyword.fetch!(opts, :over)
    within = Keyword.fetch!(opts, :within)

    quote do
      var!(ek_guard_builder) =
        ErlkoenigNft.Guard.Builder.add_slow_scan(
          var!(ek_guard_builder),
          unquote(over),
          unquote(within)
        )
    end
  end

  @doc "Honeypot ports: any connection triggers instant ban."
  defmacro honeypot(ports) do
    quote do
      var!(ek_guard_builder) =
        ErlkoenigNft.Guard.Builder.set_honeypot_ports(
          var!(ek_guard_builder),
          unquote(ports)
        )
    end
  end

  # ── respond block ─────────────────────────────────────

  @doc "Open the response block. Defines what happens when a threat is detected."
  defmacro respond(do: block) do
    quote do
      unquote(block)
    end
  end

  @doc "Mark IP as suspicious after N distinct ports contacted."
  defmacro suspect(opts) do
    after_count = Keyword.fetch!(opts, :after)
    by = Keyword.get(opts, :distinct, :ports)

    quote do
      var!(ek_guard_builder) =
        ErlkoenigNft.Guard.Builder.set_suspect(
          var!(ek_guard_builder),
          unquote(after_count),
          unquote(by)
        )
    end
  end

  @doc "Default ban duration."
  defmacro ban_for(seconds) do
    quote do
      var!(ek_guard_builder) =
        ErlkoenigNft.Guard.Builder.set_ban_duration(
          var!(ek_guard_builder),
          unquote(seconds)
        )
    end
  end

  @doc "Ban duration for honeypot triggers."
  defmacro honeypot_ban_for(seconds) do
    quote do
      var!(ek_guard_builder) =
        ErlkoenigNft.Guard.Builder.set_honeypot_ban_duration(
          var!(ek_guard_builder),
          unquote(seconds)
        )
    end
  end

  @doc "Escalating ban durations for repeat offenders."
  defmacro escalate(durations) do
    quote do
      var!(ek_guard_builder) =
        ErlkoenigNft.Guard.Builder.set_escalation(
          var!(ek_guard_builder),
          unquote(durations)
        )
    end
  end

  @doc "Observation period after unban before the IP is forgotten."
  defmacro observe_after_unban(seconds) do
    quote do
      var!(ek_guard_builder) =
        ErlkoenigNft.Guard.Builder.set_probation(
          var!(ek_guard_builder),
          unquote(seconds)
        )
    end
  end

  @doc "Forget an IP after this many seconds without events."
  defmacro forget_after(seconds) do
    quote do
      var!(ek_guard_builder) =
        ErlkoenigNft.Guard.Builder.set_forget_after(
          var!(ek_guard_builder),
          unquote(seconds)
        )
    end
  end

  # ── allowlist ─────────────────────────────────────────

  @doc "IPs that are never banned, regardless of behavior."
  defmacro allowlist(ips) do
    quote do
      var!(ek_guard_builder) =
        ErlkoenigNft.Guard.Builder.set_allowlist(
          var!(ek_guard_builder),
          unquote(ips)
        )
    end
  end
end
