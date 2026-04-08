defmodule Erlkoenig.DSL.MixProject do
  use Mix.Project

  def project do
    [
      app: :erlkoenig_dsl,
      version: "0.5.0",
      elixir: "~> 1.18",
      deps: deps(),
      name: "Erlkoenig DSL",
      source_url: "https://github.com/iRaffnix/erlkoenig",
      docs: [
        main: "overview",
        extras: [
          "guides/overview.md",
          "guides/installation.md",
          "guides/containers.md",
          "guides/networking.md",
          "guides/firewall.md",
          "guides/threat-detection.md",
          "guides/observability.md",
          "guides/elf-analysis.md",
          "guides/pki-signatures.md",
          "guides/logging.md",
          "guides/netlink-transport.md"
        ],
        groups_for_extras: [
          "Guides": Path.wildcard("guides/*.md")
        ],
        groups_for_modules: [
          "DSL": [Erlkoenig.Stack],
          "Builders": [Erlkoenig.Pod.Builder, Erlkoenig.Nft.TableBuilder, Erlkoenig.Nft.ChainBuilder]
        ]
      ]
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto, :public_key]]
  end

  defp deps do
    [
      {:ex_doc, "~> 0.35", only: :dev, runtime: false}
    ]
  end
end
