defmodule Erlkoenig.DSL.MixProject do
  use Mix.Project

  def project do
    [
      app: :erlkoenig_dsl,
      version: "0.6.0",
      elixir: "~> 1.18",
      deps: deps(),
      name: "Erlkoenig DSL",
      source_url: "https://github.com/iRaffnix/erlkoenig",
      docs: [
        main: "readme",
        output: "../doc/html",
        formatters: ["html"],
        extras: [
          "../doc/book/README.md":                   [title: "The Erlkoenig Book"],
          "../doc/book/01-overview.md":              [title: "1. Overview"],
          "../doc/book/02-installation.md":          [title: "2. Installation"],
          "../doc/book/03-first-container.md":       [title: "3. Your First Container"],
          "../doc/book/04-containers.md":            [title: "4. Containers & Pods"],
          "../doc/book/05-networking.md":            [title: "5. Networking"],
          "../doc/book/06-firewall.md":              [title: "6. Firewall"],
          "../doc/book/07-threat-detection.md":      [title: "7. Threat Detection"],
          "../doc/book/08-persistent-volumes.md":    [title: "8. Persistent Volumes"],
          "../doc/book/09-observability.md":         [title: "9. Observability"],
          "../doc/book/10-pki-signatures.md":        [title: "10. PKI & Signatures"],
          "../doc/book/11-logging.md":               [title: "11. Logging"],
          "../doc/book/12-runtime-architecture.md":  [title: "12. Runtime Architecture"],
          "../doc/book/13-elf-analysis.md":          [title: "13. ELF Analysis & Seccomp"],
          "../doc/book/14-netlink-transport.md":     [title: "14. Netlink Transport"],
          "../doc/book/15-volume-backing-ops.md":    [title: "15. Volume Backing Ops"],
          "../doc/book/16-supervision-and-admission.md": [title: "16. Supervision & Admission"],
          "../doc/book/17-property-based-testing.md": [title: "17. Property-Based Testing"],
          "../doc/book/18-operator-cli.md": [title: "18. Operator CLI"]
        ],
        groups_for_extras: [
          "Getting Started":  Path.wildcard("../doc/book/0[1-3]-*.md"),
          "DSL Reference":    Path.wildcard("../doc/book/0[4-9]-*.md") ++
                              Path.wildcard("../doc/book/1[0-1]-*.md"),
          "Internals & Ops":  Path.wildcard("../doc/book/1[2-8]-*.md")
        ],
        groups_for_modules: [
          "DSL":      [Erlkoenig.Stack],
          "Builders": [Erlkoenig.Pod.Builder,
                       Erlkoenig.Nft.TableBuilder,
                       Erlkoenig.Nft.ChainBuilder]
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
