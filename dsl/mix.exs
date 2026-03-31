defmodule Erlkoenig.DSL.MixProject do
  use Mix.Project

  def project do
    [
      app: :erlkoenig_dsl,
      version: "0.4.0",
      elixir: "~> 1.18",
      deps: deps(),
      escript: escript()
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
    []
  end
end
