defmodule BenchSpawn do
  use Erlkoenig.Stack

  # ── Spawn-Speed Benchmark ────────────────────────────────
  #
  # Misst wie schnell Container hochfahren.
  # 10 identische Worker auf einer Bridge.
  #
  # Test:
  #   1. Config laden, Timer starten
  #   2. Warten bis alle 10 Container "running" sind
  #   3. Zeit messen: load() → letzter container_started Event
  #
  #   erlkoenig eval "
  #     T0 = erlang:monotonic_time(millisecond),
  #     erlkoenig_config:load(\"/tmp/bench_spawn.term\"),
  #     spawn(fun Loop() ->
  #       N = length(pg:get_members(erlkoenig_pg, erlkoenig_cts)),
  #       case N of
  #         10 ->
  #           T1 = erlang:monotonic_time(millisecond),
  #           io:format(\"~b containers in ~bms (~.1f ms/ct)~n\",
  #                     [N, T1-T0, (T1-T0)/N]);
  #         _ ->
  #           timer:sleep(100),
  #           Loop()
  #       end
  #     end).
  #   "

  host do
    bridge "bench", subnet: {10, 99, 0, 0, 24}
  end

  pod "w" do
    container "c",
      binary: "/opt/erlkoenig/rt/demo/test-erlkoenig-echo_server",
      args: ["9000"],
      restart: :no_restart do

      publish interval: 1000 do
        metric :memory
        metric :cpu
        metric :pids
      end
    end
  end

  attach "w", to: "bench", replicas: 10
end
