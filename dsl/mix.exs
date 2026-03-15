defmodule ErlkoenigEx.MixProject do
  use Mix.Project

  def project do
    [
      app: :erlkoenig_ex,
      version: "0.2.0",
      elixir: "~> 1.18",
      deps: deps(),
      escript: escript()
    ]
  end

  defp escript do
    [
      main_module: Erlkoenig.CLI,
      name: "erlkoenig-dsl"
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto, :public_key]]
  end

  defp deps do
    []
  end
end
