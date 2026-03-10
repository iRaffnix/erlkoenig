defmodule Erlkoenig.ContainerTest do
  use ExUnit.Case, async: true

  alias Erlkoenig.Container.Builder

  # --- Builder tests ---

  describe "Container.Builder" do
    test "new creates state with name" do
      b = Builder.new(:web)
      assert b.name == "web"
      assert b.binary == nil
      assert b.ports == []
      assert b.args == []
      assert b.env == %{}
    end

    test "set_binary" do
      b = Builder.new(:web) |> Builder.set_binary("/opt/bin/server")
      assert b.binary == "/opt/bin/server"
    end

    test "set_ip validates IPv4" do
      b = Builder.new(:web) |> Builder.set_ip({10, 0, 0, 10})
      assert b.ip == {10, 0, 0, 10}
    end

    test "set_ports" do
      b = Builder.new(:web) |> Builder.set_ports([{8080, 80}, {8443, 443}])
      assert b.ports == [{8080, 80}, {8443, 443}]
    end

    test "add_port appends" do
      b =
        Builder.new(:web)
        |> Builder.add_port({8080, 80})
        |> Builder.add_port({8443, 443})

      assert b.ports == [{8080, 80}, {8443, 443}]
    end

    test "set_args converts to strings" do
      b = Builder.new(:web) |> Builder.set_args(["--port", "8080"])
      assert b.args == ["--port", "8080"]
    end

    test "set_env normalizes keys and values" do
      b = Builder.new(:web) |> Builder.set_env(%{"PORT" => "80", "ENV" => "prod"})
      assert b.env == %{"PORT" => "80", "ENV" => "prod"}
    end

    test "put_env adds single entry" do
      b = Builder.new(:web) |> Builder.put_env("PORT", "80")
      assert b.env == %{"PORT" => "80"}
    end

    test "set_firewall_profile uses Profiles" do
      b = Builder.new(:web) |> Builder.set_firewall_profile(:standard)
      assert is_map(b.firewall)
      assert Map.has_key?(b.firewall, :chains)
    end

    test "set_firewall_profile with opts" do
      b = Builder.new(:web) |> Builder.set_firewall_profile(:strict, allow_tcp: [443])
      [chain] = b.firewall.chains
      assert {:tcp_accept, 443} in chain.rules
    end

    test "to_spawn_opts omits nil and empty values" do
      b =
        Builder.new(:web)
        |> Builder.set_ip({10, 0, 0, 10})
        |> Builder.set_ports([{8080, 80}])

      opts = Builder.to_spawn_opts(b)
      assert opts.ip == {10, 0, 0, 10}
      assert opts.ports == [{8080, 80}]
      refute Map.has_key?(opts, :args)
      refute Map.has_key?(opts, :env)
      refute Map.has_key?(opts, :firewall)
    end

    test "set_restart" do
      b = Builder.new(:web) |> Builder.set_restart({:on_failure, 3})
      assert b.restart == {:on_failure, 3}
    end

    test "set_files" do
      b =
        Builder.new(:web)
        |> Builder.set_files(%{"/etc/hostname" => "test\n", "/etc/config" => "{}"})

      assert b.files == %{"/etc/hostname" => "test\n", "/etc/config" => "{}"}
    end

    test "add_file appends" do
      b =
        Builder.new(:web)
        |> Builder.add_file("/etc/hostname", "test\n")
        |> Builder.add_file("/etc/config", "{}")

      assert b.files == %{"/etc/hostname" => "test\n", "/etc/config" => "{}"}
    end

    test "set_dns_name" do
      b = Builder.new(:web) |> Builder.set_dns_name("webserver")
      assert b.dns_name == "webserver"
    end

    test "to_spawn_opts includes name from definition" do
      b = Builder.new(:web) |> Builder.set_ip({10, 0, 0, 10})
      opts = Builder.to_spawn_opts(b)
      assert opts.name == "web"
    end

    test "to_spawn_opts uses dns_name over definition name" do
      b =
        Builder.new(:web)
        |> Builder.set_ip({10, 0, 0, 10})
        |> Builder.set_dns_name("my-webserver")

      opts = Builder.to_spawn_opts(b)
      assert opts.name == "my-webserver"
    end

    test "to_spawn_opts includes restart and files" do
      b =
        Builder.new(:web)
        |> Builder.set_ip({10, 0, 0, 10})
        |> Builder.set_restart({:on_failure, 5})
        |> Builder.add_file("/etc/hostname", "test\n")

      opts = Builder.to_spawn_opts(b)
      assert opts.restart == {:on_failure, 5}
      assert opts.files == %{"/etc/hostname" => "test\n"}
    end

    test "set_zone" do
      b = Builder.new(:web) |> Builder.set_zone(:dmz)
      assert b.zone == :dmz
    end

    test "set_health_check with keyword list" do
      b = Builder.new(:web) |> Builder.set_health_check(port: 8080, interval: 5000)
      assert b.health_check == %{port: 8080, interval: 5000}
    end

    test "set_health_check with map" do
      b = Builder.new(:web) |> Builder.set_health_check(%{port: 8080, retries: 3})
      assert b.health_check == %{port: 8080, retries: 3}
    end

    test "to_spawn_opts includes zone when set" do
      b = Builder.new(:web) |> Builder.set_ip({10, 0, 1, 10}) |> Builder.set_zone(:dmz)
      opts = Builder.to_spawn_opts(b)
      assert opts.zone == :dmz
    end

    test "to_spawn_opts omits zone when nil" do
      b = Builder.new(:web) |> Builder.set_ip({10, 0, 0, 10})
      opts = Builder.to_spawn_opts(b)
      refute Map.has_key?(opts, :zone)
    end

    test "to_spawn_opts includes health_check when set" do
      b = Builder.new(:web) |> Builder.set_ip({10, 0, 0, 10}) |> Builder.set_health_check(port: 7777)
      opts = Builder.to_spawn_opts(b)
      assert opts.health_check == %{port: 7777}
    end

    test "to_term includes name and binary" do
      b =
        Builder.new(:api)
        |> Builder.set_binary("/opt/bin/api")
        |> Builder.set_ip({10, 0, 0, 5})

      term = Builder.to_term(b)
      assert term.name == "api"
      assert term.binary == "/opt/bin/api"
      assert term.ip == {10, 0, 0, 5}
    end
  end
end
