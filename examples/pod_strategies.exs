defmodule PodStrategies do
  use Erlkoenig.Stack

  @bin "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server"

  # ═══════════════════════════════════════════════════════════════
  # Pod strategies side-by-side
  #
  #   Three pods, three containers each, same binary, one zone.
  #   Each pod runs under a different OTP strategy so the coupling
  #   between siblings becomes observable by SIGKILLing one child:
  #
  #     pod "ofo" — :one_for_one   → only the crashed container restarts
  #     pod "ofa" — :one_for_all   → all siblings restart with it
  #     pod "rfo" — :rest_for_one  → crashed container + every
  #                                   container defined after it
  #
  #   IPs (10.99.200.0/24, dummy parent ek_strat):
  #     .2  ofo-0-a      .5  ofa-0-a      .8  rfo-0-a
  #     .3  ofo-0-b      .6  ofa-0-b      .9  rfo-0-b
  #     .4  ofo-0-c      .7  ofa-0-c     .10  rfo-0-c
  #
  # Start:   ek up  examples/pod_strategies.exs
  # Stop:    ek down examples/pod_strategies.exs
  # ═══════════════════════════════════════════════════════════════

  pod "ofo", strategy: :one_for_one do
    container "a", binary: @bin, args: ["9000"],
      zone: "strategies", replicas: 1, restart: :transient
    container "b", binary: @bin, args: ["9000"],
      zone: "strategies", replicas: 1, restart: :transient
    container "c", binary: @bin, args: ["9000"],
      zone: "strategies", replicas: 1, restart: :transient
  end

  pod "ofa", strategy: :one_for_all do
    container "a", binary: @bin, args: ["9000"],
      zone: "strategies", replicas: 1, restart: :transient
    container "b", binary: @bin, args: ["9000"],
      zone: "strategies", replicas: 1, restart: :transient
    container "c", binary: @bin, args: ["9000"],
      zone: "strategies", replicas: 1, restart: :transient
  end

  pod "rfo", strategy: :rest_for_one do
    container "a", binary: @bin, args: ["9000"],
      zone: "strategies", replicas: 1, restart: :transient
    container "b", binary: @bin, args: ["9000"],
      zone: "strategies", replicas: 1, restart: :transient
    container "c", binary: @bin, args: ["9000"],
      zone: "strategies", replicas: 1, restart: :transient
  end

  host do
    ipvlan "strategies",
      parent: {:dummy, "ek_strat"},
      subnet: {10, 99, 200, 0, 24}
  end
end
