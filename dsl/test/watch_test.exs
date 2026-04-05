defmodule ErlkoenigNft.WatchTest do
  use ExUnit.Case, async: true

  alias ErlkoenigNft.Watch.Builder

  describe "Watch.Builder" do
    test "new creates state" do
      b = Builder.new(:traffic)
      assert b.name == "traffic"
      assert b.interval == 2000
      assert b.counters == []
      assert b.thresholds == []
    end

    test "add_counter and add_threshold" do
      b =
        Builder.new(:t)
        |> Builder.add_counter(:ssh_pkts)
        |> Builder.add_threshold(:ssh_pkts, :pps, :>, 100)

      assert b.counters == ["ssh_pkts"]
      assert length(b.thresholds) == 1
    end

    test "set_interval" do
      b = Builder.new(:t) |> Builder.set_interval(5000)
      assert b.interval == 5000
    end

    test "add_action log" do
      b = Builder.new(:t) |> Builder.add_action(:log)
      assert b.actions == [:log]
    end

    test "add_action webhook" do
      b = Builder.new(:t) |> Builder.add_action({:webhook, "https://x.io"})
      assert b.actions == [{:webhook, "https://x.io"}]
    end

    test "to_term produces erlkoenig_nft_watch compatible config" do
      term =
        Builder.new(:traffic)
        |> Builder.add_counter(:ssh)
        |> Builder.add_threshold(:ssh, :pps, :>, 50)
        |> Builder.set_interval(3000)
        |> Builder.add_action(:log)
        |> Builder.to_term()

      assert term.name == "traffic"
      assert term.family == 1
      assert term.table == "erlkoenig_ct"
      assert term.counters == ["ssh"]
      assert term.interval == 3000
      assert length(term.thresholds) == 1
      assert term.actions == [:log]
    end

    test "thresholds format matches erlkoenig_nft_watch" do
      term =
        Builder.new(:t)
        |> Builder.add_counter(:c)
        |> Builder.add_threshold(:c, :pps, :>, 100)
        |> Builder.to_term()

      [{counter, _obj, metric, op, value}] = term.thresholds
      assert counter == "c"
      assert metric == :pps
      assert op == :>
      assert value == 100
    end
  end

  # --- DSL tests ---

  defmodule TrafficWatch do
    use ErlkoenigNft.Watch

    watch :traffic do
      counter :ssh_pkts, :pps, threshold: 100
      counter :http_pkts, :pps, threshold: 5000
      interval 3000
      on_alert :log
      on_alert {:webhook, "https://alerts.example.com/fw"}
    end

    watch :security do
      counter :dropped, :packets, threshold: 1000
      on_alert :log
    end
  end

  describe "Watch DSL" do
    test "defines two watches" do
      assert length(TrafficWatch.watches()) == 2
    end

    test "traffic watch has correct counters" do
      [traffic | _] = TrafficWatch.watches()
      assert traffic.name == "traffic"
      assert traffic.counters == ["ssh_pkts", "http_pkts"]
      assert traffic.interval == 3000
    end

    test "traffic watch has two thresholds" do
      [traffic | _] = TrafficWatch.watches()
      assert length(traffic.thresholds) == 2
    end

    test "traffic watch has two actions" do
      [traffic | _] = TrafficWatch.watches()
      assert traffic.actions == [:log, {:webhook, "https://alerts.example.com/fw"}]
    end

    test "security watch uses default interval" do
      watches = TrafficWatch.watches()
      security = Enum.find(watches, &(&1.name == "security"))
      assert security.interval == 2000
      assert security.counters == ["dropped"]
    end
  end
end
