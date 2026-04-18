#
# Copyright 2026 Erlkoenig Contributors
#
# Licensed under the Apache License, Version 2.0

defmodule ErlkoenigNft.Guard.Builder do
  @moduledoc """
  Builder for the reactive threat detection DSL.

  erlkoenig's guard system creates **one Erlang process per suspicious
  source IP** (`erlkoenig_threat_actor`, gen_statem). Each actor tracks
  the IP's behavior through a lifecycle:

      observing → suspicious → banned → probation → (process dies)

  Actors never speak to the kernel directly. Ban/unban intentions flow
  through `erlkoenig_threat_mesh`, which is the single process that
  writes to the nftables blocklist. This architecture prevents race
  conditions and enables cluster-wide ban propagation.

  ## DSL Structure

  The guard DSL has three semantic blocks:

      guard do
        detect do         # what patterns to look for
          flood over: 50, within: s(10)
          port_scan over: 20, within: m(1)
          slow_scan over: 5, within: h(1)
          honeypot [21, 23, 445, 3389]  # NEVER include your SSH port
        end

        respond do        # what happens when detected
          suspect after: 3, distinct: :ports
          ban_for h(1)
          honeypot_ban_for h(24)
          escalate [h(1), h(6), h(24), d(7)]
          observe_after_unban m(2)
          forget_after m(5)
        end

        allowlist [...]   # who is exempt
      end

  Time units: `s()` seconds, `m()` minutes, `h()` hours, `d()` days.

  ## How It Works

  1. Conntrack events flow from the kernel to `erlkoenig_nft_ct_guard`
  2. ct_guard routes each event to a per-IP threat actor (created on demand)
  3. The actor checks flood, scan, slow_scan, and honeypot thresholds
  4. On ban: actor sends intention to threat_mesh, mesh writes to kernel
  5. Kernel blocklist has timeout — auto-expiry even if BEAM crashes
  6. On unban: actor enters probation, then dies if no new events

  This builder accumulates DSL macro calls and compiles them to a flat
  config map via `to_term/1`.
  """

  @doc "Create a new builder with default detect/respond/allowlist settings."
  def new do
    %{
      # detect block
      detectors: [],
      honeypot_ports: [],
      # respond block
      ban_duration: 3600,
      honeypot_ban_duration: 86400,
      escalation: [3600, 21600, 86400, 604800],
      suspect_after: 3,
      suspect_by: :distinct_ports,
      probation: 120,
      forget_after: 300,
      # allowlist
      allowlist: [{127, 0, 0, 1}],
      # internal
      cleanup_interval: 30_000
    }
  end

  # ── detect block ──────────────────────────────

  @doc "Add a connection flood detector with `over` threshold in `within` seconds."
  def add_flood(state, over, within) when is_integer(over) and is_integer(within) do
    %{state | detectors: state.detectors ++ [{:conn_flood, over, within}]}
  end

  @doc "Add a port scan detector with `over` threshold in `within` seconds."
  def add_port_scan(state, over, within) when is_integer(over) and is_integer(within) do
    %{state | detectors: state.detectors ++ [{:port_scan, over, within}]}
  end

  @doc "Add a slow scan detector with `over` threshold in `within` seconds."
  def add_slow_scan(state, over, within) when is_integer(over) and is_integer(within) do
    %{state | detectors: state.detectors ++ [{:slow_scan, over, within}]}
  end

  @doc "Set the list of honeypot ports to monitor."
  def set_honeypot_ports(state, ports) when is_list(ports) do
    %{state | honeypot_ports: ports}
  end

  @doc "Legacy: add a detector by type atom (`:conn_flood`, `:port_scan`, `:slow_scan`)."
  def add_detector(state, :conn_flood, threshold, window), do: add_flood(state, threshold, window)
  def add_detector(state, :port_scan, threshold, window), do: add_port_scan(state, threshold, window)
  def add_detector(state, :slow_scan, threshold, window), do: add_slow_scan(state, threshold, window)

  # ── respond block ─────────────────────────────

  @doc "Set the default ban duration in seconds."
  def set_ban_duration(state, seconds) when is_integer(seconds) and seconds > 0 do
    %{state | ban_duration: seconds}
  end

  @doc "Set the ban duration for honeypot hits in seconds."
  def set_honeypot_ban_duration(state, seconds) when is_integer(seconds) and seconds > 0 do
    %{state | honeypot_ban_duration: seconds}
  end

  @doc "Set the list of escalating ban durations for repeat offenders."
  def set_escalation(state, durations) when is_list(durations) do
    %{state | escalation: durations}
  end

  @doc "Set the suspect threshold and classification criteria."
  def set_suspect(state, after_count, by) when is_integer(after_count) and is_atom(by) do
    %{state | suspect_after: after_count, suspect_by: by}
  end

  @doc "Set the probation period in seconds after an actor is unbanned."
  def set_probation(state, seconds) when is_integer(seconds) and seconds > 0 do
    %{state | probation: seconds}
  end

  @doc "Set the idle timeout in seconds before an actor's state is forgotten."
  def set_forget_after(state, seconds) when is_integer(seconds) and seconds > 0 do
    %{state | forget_after: seconds}
  end

  # ── allowlist ─────────────────────────────────

  @doc "Set the allowlist to the given IPs (localhost is always included)."
  def set_allowlist(state, ips) when is_list(ips) do
    %{state | allowlist: [{127, 0, 0, 1} | ips]}
  end

  @doc "Append a single IP tuple to the allowlist."
  def add_allowlist(state, ip) when is_tuple(ip) do
    %{state | allowlist: state.allowlist ++ [ip]}
  end

  @doc "Legacy alias for `add_allowlist/2`."
  def add_whitelist(state, ip), do: add_allowlist(state, ip)

  # ── internal ──────────────────────────────────

  @doc "Set the cleanup timer interval in milliseconds."
  def set_cleanup_interval(state, ms) when is_integer(ms) and ms > 0 do
    %{state | cleanup_interval: ms}
  end

  # ── compile ──────────────────────────────────

  @doc "Compile the builder state into a flat config map for `ct_guard`."
  def to_term(state) do
    base = %{
      ban_duration: state.ban_duration,
      honeypot_ban_duration: state.honeypot_ban_duration,
      escalation: state.escalation,
      suspect_after: state.suspect_after,
      suspect_by: state.suspect_by,
      probation: state.probation,
      forget_after: state.forget_after,
      whitelist: Enum.uniq(state.allowlist),
      cleanup_interval: state.cleanup_interval
    }

    base = if state.honeypot_ports != [] do
      Map.put(base, :honeypot_ports, state.honeypot_ports)
    else
      base
    end

    Enum.reduce(state.detectors, base, fn
      {type, threshold, window}, acc ->
        Map.put(acc, type, {threshold, window})
    end)
  end
end
