#
# Copyright 2026 Erlkoenig Contributors
#
# Licensed under the Apache License, Version 2.0
#
defmodule Erlkoenig.Nft.InContainerTest do
  @moduledoc """
  Tests for the container-local nft owner tagging — Spec
  SPEC-NFT-OWNERSHIP-SPLIT §7, phase 6e.0.b.

  Container nft is netns-local: no layout-bridge use, no fixed
  host table name, no cross-container visibility. The owner tag
  `:in_container` is a Glasbox/audit signal so a downstream
  consumer (audit log, dump tool) can attribute a chain to its
  surface without re-deriving the carrier.

  These tests focus on the IR shape that `Pod.Builder` produces.
  Both forms — `nft do … end` and the explicit
  `nft_in_container do … end` alias — must produce the identical
  output term.
  """

  use ExUnit.Case, async: true

  describe "container nft owner tag (Spec §7, 6e.0.b)" do
    test "nft do … end emits owner: :in_container on the block" do
      [{mod, _}] =
        Code.compile_string(~S"""
        defmodule TestStack.NftInCt.Legacy do
          use Erlkoenig.Stack

          host do
            ipvlan "demo", parent: {:dummy, "ek_demo"},
              subnet: {10, 70, 0, 0, 24}
          end

          pod "api", strategy: :one_for_one do
            container "web",
              binary: "/opt/bin/web",
              zone: "demo", replicas: 1, restart: :permanent do
              nft do
                input policy: :drop do
                  nft_rule :accept, ct_state: [:established, :related]
                end
              end
            end
          end
        end
        """)

      [ct] = hd(mod.config().pods).containers
      assert ct.nft.owner == :in_container
    end

    test "nft do … end denormalizes owner :in_container onto each chain" do
      [{mod, _}] =
        Code.compile_string(~S"""
        defmodule TestStack.NftInCt.ChainOwner do
          use Erlkoenig.Stack

          host do
            ipvlan "demo", parent: {:dummy, "ek_demo"},
              subnet: {10, 70, 0, 0, 24}
          end

          pod "api", strategy: :one_for_one do
            container "web",
              binary: "/opt/bin/web",
              zone: "demo", replicas: 1, restart: :permanent do
              nft do
                output policy: :drop do
                  nft_rule :accept, ct_state: [:established, :related]
                end
                input policy: :drop do
                  nft_rule :accept, tcp_dport: 4000
                end
              end
            end
          end
        end
        """)

      [ct] = hd(mod.config().pods).containers

      Enum.each(ct.nft.chains, fn c ->
        assert c.owner == :in_container,
               "chain #{inspect(c.name)} carries #{inspect(c.owner)}, " <>
                 "expected :in_container"
      end)
    end

    test "nft_in_container alias produces identical IR to legacy nft" do
      # Compile the same container twice — once with `nft do`,
      # once with `nft_in_container do` — and assert the
      # container nft IR is structurally identical. This is the
      # alias contract: the new name is sugar, not semantics.
      stack_with = fn macro_name ->
        ~s"""
        defmodule TestStack.NftInCt.Compare#{macro_name |> to_string() |> String.capitalize()} do
          use Erlkoenig.Stack

          host do
            ipvlan "demo", parent: {:dummy, "ek_demo"},
              subnet: {10, 70, 0, 0, 24}
          end

          pod "api", strategy: :one_for_one do
            container "web",
              binary: "/opt/bin/web",
              zone: "demo", replicas: 1, restart: :permanent do
              #{macro_name} do
                input policy: :drop do
                  nft_rule :accept, ct_state: [:established, :related]
                  nft_rule :accept, tcp_dport: 4000
                end
              end
            end
          end
        end
        """
      end

      [{legacy_mod, _}] = Code.compile_string(stack_with.(:nft))
      [{alias_mod, _}] = Code.compile_string(stack_with.(:nft_in_container))

      legacy_nft = hd(hd(legacy_mod.config().pods).containers).nft
      alias_nft = hd(hd(alias_mod.config().pods).containers).nft

      assert legacy_nft == alias_nft
      assert legacy_nft.owner == :in_container
    end

    test "owner tag is in_container, never legacy/host/zone/ct" do
      # Negative regression: a future change that accidentally
      # routes container nft through the host TableBuilder without
      # an explicit owner. Pin the value so that drift surfaces
      # here, not in audit output where it would mislead the
      # operator.
      [{mod, _}] =
        Code.compile_string(~S"""
        defmodule TestStack.NftInCt.OwnerPinned do
          use Erlkoenig.Stack

          host do
            ipvlan "demo", parent: {:dummy, "ek_demo"},
              subnet: {10, 70, 0, 0, 24}
          end

          pod "api", strategy: :one_for_one do
            container "web",
              binary: "/opt/bin/web",
              zone: "demo", replicas: 1, restart: :permanent do
              nft_in_container do
                input policy: :drop do
                  nft_rule :accept
                end
              end
            end
          end
        end
        """)

      [ct] = hd(mod.config().pods).containers
      refute ct.nft.owner in [:legacy, :host, :zone, :ct]
      assert ct.nft.owner == :in_container
    end

    test "container nft block scoping is netns-local: no host table coupling" do
      # The container nft IR lives under `ct.nft`, never as an
      # entry in `config.nft_tables` (those are the host-side
      # tables). Pin that boundary — a future bug that lifts a
      # container nft into nft_tables would re-create exactly the
      # cross-table coupling §7 forbids.
      [{mod, _}] =
        Code.compile_string(~S"""
        defmodule TestStack.NftInCt.NoHostCoupling do
          use Erlkoenig.Stack

          host do
            ipvlan "demo", parent: {:dummy, "ek_demo"},
              subnet: {10, 70, 0, 0, 24}
          end

          pod "api", strategy: :one_for_one do
            container "web",
              binary: "/opt/bin/web",
              zone: "demo", replicas: 1, restart: :permanent do
              nft_in_container do
                input policy: :drop do
                  nft_rule :accept
                end
              end
            end
          end
        end
        """)

      cfg = mod.config()
      # Container nft is reachable via the container itself.
      [ct] = hd(cfg.pods).containers
      assert ct.nft.owner == :in_container

      # No host nft_tables generated by a container-only block.
      refute Map.has_key?(cfg, :nft_tables)
    end
  end
end
