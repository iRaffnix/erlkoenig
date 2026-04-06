defmodule Erlkoenig.DSL.MixProject do
  use Mix.Project

  def project do
    [
      app: :erlkoenig_dsl,
      version: "0.4.0",
      elixir: "~> 1.18",
      deps: deps(),
      escript: escript(),
      name: "Erlkoenig DSL",
      source_url: "https://github.com/iRaffnix/erlkoenig",
      docs: [
        main: "Erlkoenig.Stack",
        groups_for_modules: [
          "DSL": [Erlkoenig.Stack],
          "Builders": [Erlkoenig.Pod.Builder, Erlkoenig.Nft.TableBuilder, Erlkoenig.Nft.ChainBuilder]
        ]
      ]
    ]
  end

  defp escript do
    [
      main_module: Erlkoenig.CLI,
      name: "erlkoenig",
      embed_elixir: true
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
