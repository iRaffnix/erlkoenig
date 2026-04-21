defmodule Erlkoenig.DSL.MixProject do
  use Mix.Project

  def project do
    [
      app: :erlkoenig_dsl,
      version: "0.8.0",
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
          "../doc/book/18-operator-cli.md": [title: "18. Operator CLI"],
          "../doc/book/19-journal-local.md": [title: "19. Service Capabilities"],
          "../doc/book/20-audit-verifier.md": [title: "20. Audit Verifier"],
          "../doc/book/21-case-mgmt.md": [title: "21. case_mgmt Use-Case"],
          "../doc/book/22-dns-egress-allowlist.md": [title: "22. DNS Egress Allowlist"],
          "../doc/book/23-edge-primitives.md": [title: "23. Edge Primitives"]
        ],
        groups_for_extras: [
          "Getting Started":  Path.wildcard("../doc/book/0[1-3]-*.md"),
          "DSL Reference":    Path.wildcard("../doc/book/0[4-9]-*.md") ++
                              Path.wildcard("../doc/book/1[0-1]-*.md"),
          "Internals & Ops":  Path.wildcard("../doc/book/1[2-8]-*.md"),
          "Service Capabilities": Path.wildcard("../doc/book/19-*.md") ++
                                  Path.wildcard("../doc/book/20-*.md") ++
                                  Path.wildcard("../doc/book/21-*.md") ++
                                  Path.wildcard("../doc/book/22-*.md") ++
                                  Path.wildcard("../doc/book/23-*.md")
        ],
        groups_for_modules: [
          "DSL Entry":  [Erlkoenig.Stack,
                         Erlkoenig.DSL,
                         Erlkoenig.Capabilities],
          "Builders":   [Erlkoenig.Container,
                         Erlkoenig.Container.Builder,
                         Erlkoenig.Pod.Builder,
                         Erlkoenig.Host.Builder,
                         Erlkoenig.Images.Builder,
                         Erlkoenig.Limits.Builder,
                         Erlkoenig.Steering.Builder,
                         Erlkoenig.Nft.TableBuilder,
                         Erlkoenig.Nft.ChainBuilder],
          "NFT Firewall": [ErlkoenigNft.Firewall,
                           ErlkoenigNft.Firewall.Builder,
                           ErlkoenigNft.Firewall.Profiles,
                           ErlkoenigNft.Guard,
                           ErlkoenigNft.Guard.Builder,
                           ErlkoenigNft.Watch,
                           ErlkoenigNft.Watch.Builder,
                           ErlkoenigNft.CLI.Formatter],
          "Primitives": [Erlkoenig.Limits,
                         Erlkoenig.Seccomp,
                         Erlkoenig.TimeUnits,
                         Erlkoenig.Validation],
          "Mix Tasks":  [Mix.Tasks.Erlkoenig.Compile,
                         Mix.Tasks.Erlkoenig.Validate]
        ]
      ]
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto, :public_key]]
  end

  defp deps do
    [
      {:ex_doc, "~> 0.35", only: :dev, runtime: false},
      {:stream_data, "~> 1.1", only: [:dev, :test], runtime: false}
    ]
  end
end
