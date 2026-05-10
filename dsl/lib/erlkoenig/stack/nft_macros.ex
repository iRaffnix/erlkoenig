defmodule Erlkoenig.Stack.NftMacros do
  @moduledoc false

  # ═══════════════════════════════════════════════════════════
  # nft — per-container firewall (SPEC-EK-023)
  # ═══════════════════════════════════════════════════════════

  @doc """
  Define nftables firewall rules for this container.

  Rules are installed inside the container's network namespace via
  CMD_NFT_SETUP. Must be inside a `container` block with a `do` body.

  Contains `output` and `input` sub-blocks that map to nft base chains
  with the respective hooks.

  ## Example

      container "api", binary: "/opt/api", restart: :permanent do
        nft do
          output policy: :drop do
            nft_rule :accept, ct_state: [:established, :related]
            nft_rule :accept, iifname: "lo"
            nft_rule :accept, tcp_dport: 5432
          end
          input policy: :drop do
            nft_rule :accept, ct_state: [:established, :related]
            nft_rule :accept, iifname: "lo"
            nft_rule :accept, tcp_dport: 4000
          end
        end
      end
  """
  defmacro nft(do: block) do
    Module.put_attribute(__CALLER__.module, :ek_container_nft, true)

    quote do
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.begin_nft(var!(ek_pod_builder))
      unquote(block)
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.end_nft(var!(ek_pod_builder))
    end
  end

  @doc """
  Alias for `nft do … end` that names the owner explicitly per
  Spec SPEC-NFT-OWNERSHIP-SPLIT §7. Both forms produce identical
  IR (`owner: :in_container` on the block + denormalized on each
  chain). Use whichever reads better at the call site — the alias
  exists so an operator-facing `host { nft_host }, container {
  nft_in_container }` reads symmetrically.

  ## Example

      container "api", binary: "/opt/api", restart: :permanent do
        nft_in_container do
          output policy: :drop do
            nft_rule :accept, ct_state: [:established, :related]
          end
          input policy: :drop do
            nft_rule :accept, tcp_dport: 4000
          end
        end
      end
  """
  defmacro nft_in_container(do: block) do
    Module.put_attribute(__CALLER__.module, :ek_container_nft, true)

    quote do
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.begin_nft(var!(ek_pod_builder))
      unquote(block)
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.end_nft(var!(ek_pod_builder))
    end
  end

  @doc "Define an OUTPUT chain inside an `nft` block."
  defmacro output(opts, do: block) do
    quote do
      var!(ek_pod_builder) =
        Erlkoenig.Pod.Builder.begin_nft_chain(
          var!(ek_pod_builder),
          :output,
          unquote(opts)
        )

      unquote(block)
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.end_nft_chain(var!(ek_pod_builder))
    end
  end

  @doc "Define an INPUT chain inside an `nft` block."
  defmacro input(opts, do: block) do
    quote do
      var!(ek_pod_builder) =
        Erlkoenig.Pod.Builder.begin_nft_chain(
          var!(ek_pod_builder),
          :input,
          unquote(opts)
        )

      unquote(block)
      var!(ek_pod_builder) = Erlkoenig.Pod.Builder.end_nft_chain(var!(ek_pod_builder))
    end
  end

  # ═══════════════════════════════════════════════════════════
  # OLD SYNTAX REMOVED (ADR-0015: harter Bruch)
  #
  # The following macros were removed:
  #   chain/3      — use nft_table + base_chain/nft_chain instead
  #   rule/2       — use nft_rule instead (with nft field names)
  #   counters/1   — use nft_counter inside nft_table instead
  #   set/3        — not yet reimplemented
  #
  # Old field names:
  #   tcp: 8443    → tcp_dport: 8443
  #   iif: "eth0"  → iifname: "eth0"
  #   oif: "eth0"  → oifname: "eth0"
  #   ct: :established → ct_state: [:established, :related]
  #   log: "DROP:" → log_prefix: "DROP:"
  # ═══════════════════════════════════════════════════════════
  # nft_table / base_chain / chain — nft-transparent DSL (ADR-0015)
  # ═══════════════════════════════════════════════════════════

  @doc """
  Removed raw nftables table surface.

  Phase 6i closed the unowned `nft_table family, name do ... end`
  escape hatch. Use the owner-bound surfaces instead:
  `nft_host`, `nft_zone`, or `nft_ct`.
  """
  defmacro nft_table(family, name, do: block) do
    _ = {family, name, block}

    raise CompileError,
      file: __CALLER__.file,
      line: __CALLER__.line,
      description:
        "`nft_table` was removed by SPEC-NFT-OWNERSHIP-SPLIT phase 6i; " <>
          "rewrite the block to nft_host / nft_zone / nft_ct. " <>
          "There is no automatic migration or raw-table escape hatch."
  end

  # ═══════════════════════════════════════════════════════════
  # nft_host / nft_zone / nft_ct — owner-tagged table macros
  # ═══════════════════════════════════════════════════════════
  #
  # Per Spec SPEC-NFT-OWNERSHIP-SPLIT §7, these macros are
  # *layout-bound ownership surfaces*, not generic table builders.
  # They take no name argument and emit fixed table names defined
  # by the canonical layout contract:
  #
  #   nft_host → "erlkoenig_host"
  #   nft_zone → "erlkoenig_zone"
  #   nft_ct   → "erlkoenig_ct"
  #
  # A callsite override is deliberately not supported — that would
  # re-create a second source of truth next to the owner constants.

  @doc """
  Define the host firewall table (owner = `:host`).

  Emits an nft table named `erlkoenig_host`. Takes no name argument
  — the table name is fixed by the layout contract (Spec §7).
  Contains the input/output/ban chains for host protection.

  ## Example

      nft_host do
        base_chain "input", hook: :input, type: :filter,
          priority: :filter, policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, iifname: "lo"
          nft_rule :accept, tcp_dport: 22
        end
      end
  """
  defmacro nft_host(do: block) do
    owner_block_macro(__CALLER__, :host, "erlkoenig_host", block)
  end

  @doc """
  Define the zone-forward firewall table (owner = `:zone`).

  Emits an nft table named `erlkoenig_zone`. Takes no name argument.
  Contains the forward chain plus per-container regular chains as
  same-table jump targets.

  ## Example

      nft_zone do
        base_chain "forward", hook: :forward, type: :filter,
          priority: :filter, policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :jump, ip_daddr: {10, 0, 0, 5}, to: "container_db"
        end

        nft_chain "container_db" do
          nft_rule :accept, tcp_dport: 5432
          nft_rule :drop
        end
      end
  """
  defmacro nft_zone(do: block) do
    owner_block_macro(__CALLER__, :zone, "erlkoenig_zone", block)
  end

  @doc """
  Define the container-NAT table (owner = `:ct`).

  Emits an nft table named `erlkoenig_ct`. Takes no name argument.
  Holds NAT base chains only (prerouting/dstnat,
  postrouting/srcnat); filter chains and per-container policy
  chains do **not** belong here (Spec §5.3).

  ## Example

      nft_ct do
        base_chain "dnat", hook: :prerouting, type: :nat,
          priority: :dstnat, policy: :accept do
          nft_rule :dnat, tcp_dport: 8080, to: {{10, 0, 0, 5}, 8080}
        end

        base_chain "masquerade", hook: :postrouting, type: :nat,
          priority: :srcnat, policy: :accept do
          nft_rule :masquerade, ip_saddr: {10, 0, 0, 0, 24}
        end
      end
  """
  defmacro nft_ct(do: block) do
    owner_block_macro(__CALLER__, :ct, "erlkoenig_ct", block)
  end

  # Shared macro body for nft_host / nft_zone / nft_ct. Inline this
  # in every macro without reintroducing a raw-table path — keep it in one place.
  defp owner_block_macro(caller, owner, table_name, block) do
    Module.register_attribute(caller.module, :__ek_context__, accumulate: false)
    Module.put_attribute(caller.module, :__ek_context__, :nft_table)

    quote do
      var!(ek_nft_table) =
        Erlkoenig.Nft.TableBuilder.new(:inet, unquote(table_name), owner: unquote(owner))

      unquote(block)
      @stack_nft_tables var!(ek_nft_table)
    end
  end

  @doc """
  Define a base chain — attached to a netfilter hook.

  A base chain is an entry point into the firewall. The kernel delivers
  packets to the chain based on the hook point. In contrast to `nft_chain`
  (regular chain), which is only entered via `:jump` rules.

  Syntax: `base_chain "name", hook: ..., type: ..., priority: ..., policy: ... do ... end`

  The four parameters determine **when** (hook), **what it can do** (type),
  **in which order** (priority), and **what happens when nothing matches** (policy).

  ## Options

  ### `hook:` — when does this chain see packets

  | Hook | Packets | Typical use |
  |------|---------|-------------|
  | `:input` | Destined for the host itself | Host firewall (SSH, ICMP) |
  | `:forward` | Routed through the host (container ↔ container) | Container firewall |
  | `:output` | Sent by the host itself | Outbound restrictions |
  | `:prerouting` | All incoming, before routing decision | Ban sets (raw), DNAT |
  | `:postrouting` | All outgoing, after routing decision | SNAT, Masquerade |

  ### `type:` — what can the chain do

  | Type | Allowed actions | Typical with |
  |------|----------------|--------------|
  | `:filter` | accept, drop, jump, reject | input, forward, output, prerouting |
  | `:nat` | snat, dnat, masquerade, redirect | prerouting (dnat), postrouting (snat) |
  | `:route` | Mark-based rerouting | output |

  ### `priority:` — evaluation order (lower = earlier)

  | Priority | Value | When |
  |----------|-------|------|
  | `:raw` | -300 | Before conntrack — ban sets go here |
  | `:mangle` | -150 | Before filter — packet manipulation |
  | `:dstnat` | -100 | DNAT (port forwarding) |
  | `:filter` | 0 | Standard filtering |
  | `:security` | 50 | After filter — SELinux |
  | `:srcnat` | 100 | SNAT/Masquerade (after routing) |

  An integer can also be used directly (e.g. `priority: -200`).

  ### `policy:` — default verdict

  | Policy | Meaning |
  |--------|---------|
  | `:drop` | Drop everything that doesn't match a rule (secure, deny-by-default) |
  | `:accept` | Accept everything that doesn't match (open, use for NAT chains) |

  ## Common Combinations

  | Use Case | hook | type | priority | policy |
  |----------|------|------|----------|--------|
  | Host firewall | `:input` | `:filter` | `:filter` | `:drop` |
  | Container firewall | `:forward` | `:filter` | `:filter` | `:drop` |
  | Ban before conntrack | `:prerouting` | `:filter` | `:raw` | `:accept` |
  | Port forwarding (DNAT) | `:prerouting` | `:nat` | `:dstnat` | `:accept` |
  | Masquerade (SNAT) | `:postrouting` | `:nat` | `:srcnat` | `:accept` |

  ## Examples

      # Ban set in raw priority — before conntrack, zero kernel state
      base_chain "prerouting", hook: :prerouting, type: :filter,
        priority: :raw, policy: :accept do
        nft_rule :drop, set: "ban", counter: "input_ban"
      end

      # Host input firewall — deny by default
      base_chain "input", hook: :input, type: :filter,
        priority: :filter, policy: :drop do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, iifname: "lo"
        nft_rule :accept, ip_protocol: :icmp
        nft_rule :accept, tcp_dport: 22
        nft_rule :drop, counter: "input_drop", log_prefix: "HOST: "
      end

      # Container forward firewall — deny by default
      base_chain "forward", hook: :forward, type: :filter,
        priority: :filter, policy: :drop do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :jump,
          ip_saddr: {:replica_ips, "web", "nginx"}, to: "from-web"
        nft_rule :drop, counter: "forward_drop"
      end

      # NAT: masquerade container traffic leaving the host
      base_chain "postrouting", hook: :postrouting, type: :nat,
        priority: :srcnat, policy: :accept do
        nft_rule :masquerade, ip_saddr: {10, 0, 0, 0, 24}, oifname_ne: "eth0"
      end
  """
  defmacro base_chain(name, opts, do: block) do
    Module.put_attribute(__CALLER__.module, :ek_container_nft, false)

    quote do
      var!(ek_nft_chain) = Erlkoenig.Nft.ChainBuilder.new_base(unquote(name), unquote(opts))
      unquote(block)

      var!(ek_nft_table) =
        Erlkoenig.Nft.TableBuilder.add_chain(
          var!(ek_nft_table),
          var!(ek_nft_chain)
        )
    end
  end

  # Override: chain inside nft_table context (regular chain, no hook/policy)
  # The existing chain/3 macro handles host/pod contexts via @__ek_context__
  # This version is for nft_table context only
  @doc """
  Define a regular chain — a jump target with no hook.

  Regular chains are not attached to netfilter. They are entered
  via `:jump` rules from base chains or other regular chains.
  At the end of a regular chain, execution returns to the caller
  (implicit `return`).

  Used for **egress filtering**: one chain per container that controls
  what outbound traffic the container may send.

  ## Examples

      # Egress: nginx may only connect to API on port 4000
      nft_chain "from-web-nginx" do
        nft_rule :accept, ct_state: [:established, :related]
        nft_rule :accept, tcp_dport: 4000
        nft_rule :drop, counter: "nginx_drop"
      end

      # Called from forward chain via (dispatch by source IP — IPVLAN
      # slaves are not host-visible, so interface matches don't work):
      #   nft_rule :jump,
      #     ip_saddr: {:replica_ips, "web", "nginx"}, to: "from-web-nginx"
  """
  defmacro nft_chain(name, do: block) do
    Module.put_attribute(__CALLER__.module, :ek_container_nft, false)

    quote do
      var!(ek_nft_chain) = Erlkoenig.Nft.ChainBuilder.new_regular(unquote(name))
      unquote(block)

      var!(ek_nft_table) =
        Erlkoenig.Nft.TableBuilder.add_chain(
          var!(ek_nft_table),
          var!(ek_nft_chain)
        )
    end
  end

  @doc """
  Define a single nftables rule inside a chain.

  Each `nft_rule` maps 1:1 to a real `nft add rule` command.
  Rules are evaluated top-to-bottom — first match wins.

  Syntax: `nft_rule :action, match_field: value, match_field: value, ...`

  All match fields are AND-combined — all must match for the action to fire.
  For OR logic, write separate rules.

  ## Actions (first argument)

  | Action | nft equivalent | Required opts | Description |
  |--------|---------------|---------------|-------------|
  | `:accept` | `accept` | — | Accept the packet |
  | `:drop` | `drop` | — | Silently drop the packet |
  | `:return` | `return` | — | Return to the calling chain |
  | `:jump` | `jump <chain>` | `to:` | Jump to a named chain |
  | `:reject` | `reject` | — | Drop + send ICMP unreachable |
  | `:masquerade` | `masquerade` | — | SNAT to outgoing interface IP |
  | `:snat` | `snat to <ip>` | `snat_to:` | Source NAT to fixed IP |
  | `:dnat` | `dnat to <ip[:port]>` | `dnat_to:` | Destination NAT |
  | `:notrack` | `notrack` | — | Skip connection tracking |
  | `:ct_mark_set` | `ct mark set` | `mark:` | Set conntrack mark |
  | `:ct_mark_match` | `ct mark` | `mark:` | Match conntrack mark |
  | `:fib_rpf` | `fib saddr . iif oif 0 drop` | — | Reverse path filter (BCP38) |
  | `:connlimit_drop` | `ct count over N drop` | `limit:` | Connection limit per source IP |
  | `:vmap_dispatch` | `vmap @name` | `vmap:` | Verdict map dispatch |
  | `:dnat_lb` | `dnat to jhash ip saddr mod N map {...}` | `targets:`, `port:` | Source-IP hash loadbalancing |

  ## Match Fields (keyword options, all optional, combinable)

  ### Identity (who)

  | Field | nft equivalent | Type | Example |
  |-------|---------------|------|---------|
  | `ct_state:` | `ct state` | `[atom]` | `[:established, :related]` |
  | `ip_saddr:` | `ip saddr` | `ip_tuple` \\| `{:replica_ips, pod, ct}` | `{10,0,0,0,24}` |
  | `ip_daddr:` | `ip daddr` | `ip_tuple` \\| `{:replica_ips, pod, ct}` | `{10,0,0,2}` |
  | `ip_protocol:` | `ip protocol` | `atom` | `:icmp` |

  ### Interface (where)

  | Field | nft equivalent | Type | Example |
  |-------|---------------|------|---------|
  | `iifname:` | `iifname` | `string` | `"eth0"` |
  | `oifname:` | `oifname` | `string` | `"eth0"` |
  | `oifname_ne:` | `oifname !=` | `string` | `"eth0"` |

  ### Port (what)

  | Field | nft equivalent | Type | Example |
  |-------|---------------|------|---------|
  | `tcp_dport:` | `tcp dport` | `integer` \\| `{min, max}` | `8080` or `{8000, 9000}` |
  | `udp_dport:` | `udp dport` | `integer` | `53` |
  | `set:` | `@set_name` | `string` | `"ban"` — match IP against named set |

  ### Observability

  | Field | nft equivalent | Type | Example |
  |-------|---------------|------|---------|
  | `counter:` | `counter` | `string` | `"forward_drop"` — must be declared with `nft_counter` |
  | `log_prefix:` | `log prefix` | `string` | `"FWD: "` — triggers NFLOG with packet details |

  ### Action-specific

  | Field | Used with | Type | Example |
  |-------|-----------|------|---------|
  | `to:` | `:jump` | `string` | `"from-web-nginx"` |
  | `mark:` | `:ct_mark_set`, `:ct_mark_match` | `integer` | `1` |
  | `snat_to:` | `:snat` | `ip_tuple` | `{192,168,1,1}` |
  | `dnat_to:` | `:dnat` | `ip_tuple` \\| `{ip, port}` | `{10,0,0,2, 8080}` |
  | `limit:` | `:connlimit_drop` | `integer` | `100` |
  | `vmap:` | `:vmap_dispatch` | `string` | `"dispatch"` |
  | `targets:` | `:dnat_lb` | `{:replica_ips, pod, ct}` | Loadbalancing targets |
  | `port:` | `:dnat_lb` | `integer` | DNAT destination port |

  ## Deploy-Time Symbols

  Resolved when the config is loaded, not at compile time:

  - `{:replica_ips, "pod", "container"}` — expands to the list of container
    IPs across all replicas

  With `replicas: 3`, `{:replica_ips, "web", "nginx"}` generates three
  individual nft rules — one per IP.

  ## IP Tuple Format

  - `{a, b, c, d}` — single IP (e.g. `{10, 0, 0, 2}`)
  - `{a, b, c, d, mask}` — CIDR subnet (e.g. `{10, 0, 0, 0, 24}`)

  ## Combining Fields

  All fields are AND-combined. Every field must match:

      # TCP port 443 from eth0 to a specific IP — all three must match
      nft_rule :accept,
        iifname: "eth0",
        ip_daddr: {:replica_ips, "web", "nginx"},
        tcp_dport: 443

  For OR logic, write separate rules:

      # Accept port 80 OR port 443
      nft_rule :accept, tcp_dport: 80
      nft_rule :accept, tcp_dport: 443

  ## Examples

      # Accept established connections
      nft_rule :accept, ct_state: [:established, :related]

      # Drop IPs in ban set (before conntrack in raw chain)
      nft_rule :drop, set: "ban", counter: "input_ban"

      # Accept ICMP (ping)
      nft_rule :accept, ip_protocol: :icmp

      # Accept TCP on port 443 from eth0
      nft_rule :accept, iifname: "eth0", tcp_dport: 443

      # Jump to egress chain based on source IP (IPVLAN slaves have no
      # host-visible interface — dispatch by source IP instead)
      nft_rule :jump,
        ip_saddr: {:replica_ips, "web", "nginx"}, to: "from-web-nginx"

      # Allow traffic between pods (expanded at deploy time)
      nft_rule :accept,
        ip_saddr: {:replica_ips, "web", "nginx"},
        ip_daddr: {:replica_ips, "app", "api"},
        tcp_dport: 4000

      # Drop with counter and log
      nft_rule :drop, counter: "forward_drop", log_prefix: "FWD: "

      # Masquerade container subnet (NAT)
      nft_rule :masquerade, ip_saddr: {10, 0, 0, 0, 24}, oifname_ne: "eth0"

      # DNAT: forward port 8080 to container
      nft_rule :dnat, tcp_dport: 8080, dnat_to: {10, 0, 0, 2, 8080}

      # Reverse path filter (anti-spoofing)
      nft_rule :fib_rpf

      # Connection limit: max 100 concurrent from one IP
      nft_rule :connlimit_drop, tcp_dport: 80, limit: 100

      # Source-IP hash loadbalancing across replicas
      # jhash(ip saddr) mod N → DNAT to one of N container IPs
      # Same source IP always lands on same backend (sticky)
      nft_rule :dnat_lb,
        iifname: "eth0",
        tcp_dport: 8443,
        targets: {:replica_ips, "web", "nginx"},
        port: 8443
  """
  defmacro nft_rule(action, opts \\ []) do
    if Module.get_attribute(__CALLER__.module, :ek_container_nft) do
      quote do
        var!(ek_pod_builder) =
          Erlkoenig.Pod.Builder.add_nft_rule(
            var!(ek_pod_builder),
            unquote(action),
            unquote(opts)
          )
      end
    else
      quote do
        var!(ek_nft_chain) =
          Erlkoenig.Nft.ChainBuilder.add_rule(
            var!(ek_nft_chain),
            unquote(action),
            unquote(opts)
          )
      end
    end
  end

  @doc """
  Declare a named counter at table level.

  Named counters are table-level objects that track packet and byte counts.
  They must be declared before being referenced in rules via `counter:`.

  erlkoenig polls counter rates periodically and publishes them as AMQP
  events (`firewall.<chain>.drop`) when the packet rate is > 0.

  ## Validation

  - Counter referenced in `nft_rule` but not declared → `CompileError`

  ## Examples

      nft_zone do
        nft_counter "forward_drop"
        nft_counter "web_nginx_drop"

        base_chain "forward", hook: :forward, type: :filter,
          priority: :filter, policy: :drop do
          nft_rule :drop, counter: "forward_drop"
        end
      end
  """
  defmacro nft_counter(name) do
    quote do
      var!(ek_nft_table) =
        Erlkoenig.Nft.TableBuilder.add_counter(
          var!(ek_nft_table),
          unquote(name)
        )
    end
  end

  @doc """
  Declare a named set at table level.

  Sets are collections of values (IPs, ports, etc.) that can be matched
  against in rules. Used for dynamic blocklists, allowlists, and
  group-based filtering.

  ## Arguments

  | Argument | Type | Description |
  |----------|------|-------------|
  | `name` | `string` | Set name |
  | `type` | `atom` | Element type: `:ipv4_addr`, `:ipv6_addr`, `:inet_service` |

  ## Options

  | Option | Type | Default | Description |
  |--------|------|---------|-------------|
  | `flags:` | `[atom]` | `[]` | Set flags: `:interval`, `:timeout`, `:constant` |

  ## Examples

      nft_zone do
        nft_set "blocklist", :ipv4_addr

        base_chain "input", hook: :input, type: :filter,
          priority: :filter, policy: :drop do
          nft_rule :drop, set: "blocklist"
        end
      end
  """
  defmacro nft_set(name, type, opts \\ []) do
    quote do
      var!(ek_nft_table) =
        Erlkoenig.Nft.TableBuilder.add_set(
          var!(ek_nft_table),
          unquote(name),
          unquote(type),
          unquote(opts)
        )
    end
  end

  @doc """
  Declare a CIDR allow-/block-list set in one line.

  Sugar over `nft_set name, :ipv4_addr, flags: [:interval],
  elements: [cidrs]`. The `interval` flag tells the kernel this
  set stores ranges rather than point values, so `ip saddr @name`
  matches any IP inside any listed CIDR.

  Operator still writes the rule that consumes the set — the
  set definition carries no policy on its own.

  ## Arguments

  | Argument | Type | Description |
  |----------|------|-------------|
  | `name` | string | Set name; referenced by rules via `set: "name"` |
  | `cidrs` | `[String.t()]` | CIDR strings (`"10.0.0.0/8"`) and/or single IPs (`"192.168.42.5"`) |

  ## Compile-time checks

  - Empty `cidrs` list → `CompileError`
  - Non-binary entry → `CompileError`
  - Entry not matching an IPv4-with-optional-prefix pattern →
    `CompileError`

  Actual CIDR well-formedness (valid mask, no host bits set, etc.)
  is deferred to the runtime — nothing is gained by replicating
  that logic in the DSL.

  ## Examples

      nft_zone do
        nft_cidr_set "trusted", [
          "10.0.0.0/8",
          "192.168.0.0/16",
          "203.0.113.42"
        ]

        base_chain "input", hook: :input, type: :filter,
          priority: :filter, policy: :drop do
          nft_rule :accept, ct_state: [:established, :related]
          nft_rule :accept, set: "trusted"
        end
      end

  Compiles to the equivalent of:

      nft_set "trusted", :ipv4_addr,
        flags: [:interval],
        elements: ["10.0.0.0/8", "192.168.0.0/16", "203.0.113.42"]
  """
  defmacro nft_cidr_set(name, cidrs) do
    quote do
      var!(ek_nft_table) =
        Erlkoenig.Nft.TableBuilder.add_cidr_set(
          var!(ek_nft_table),
          unquote(name),
          unquote(cidrs)
        )
    end
  end

  @doc """
  Declare a flowtable for hardware/software fast-path offload.

  Flowtables bypass the full nftables evaluation pipeline for
  established connections. Once a flow is offloaded, subsequent
  packets are fast-pathed at the ingress hook — skipping all
  chains. This is nftables' native alternative to eBPF-based
  packet acceleration.

  ## Arguments

  | Argument | Type | Description |
  |----------|------|-------------|
  | `name` | string | Flowtable name (referenced by `nft_rule :flow_offload`) |

  ## Options

  | Option | Type | Default | Description |
  |--------|------|---------|-------------|
  | `devices:` | list of strings | required | Network interfaces to attach to |
  | `priority:` | integer | 0 | Ingress hook priority |

  ## Example

      nft_zone do
        nft_flowtable "ft0", devices: ["eth0"]

        base_chain "forward", hook: :forward, type: :filter,
                   priority: :filter, policy: :accept do
          nft_rule :flow_offload, flowtable: "ft0"
          nft_rule :accept, ct_state: [:established, :related]
        end
      end

  The first packet of a connection traverses the full chain. Once
  the connection is established, the kernel offloads it to the
  flowtable's ingress hook — no more chain evaluation for that flow.
  """
  defmacro nft_flowtable(name, opts) do
    quote do
      var!(ek_nft_table) =
        Erlkoenig.Nft.TableBuilder.add_flowtable(
          var!(ek_nft_table),
          unquote(name),
          unquote(opts)
        )
    end
  end

  @doc """
  Declare an explicit NFLOG group owned by the current nft table.

  Any `nft_rule` that logs to NFLOG must name its group with
  `nflog_group: N`, and the enclosing `nft_host` / `nft_zone` /
  `nft_ct` block must declare the same group here. This keeps packet
  events joined to table ownership without deriving owner metadata
  from chain names or numeric conventions.

  ## Example

      nft_host do
        nft_nflog_group 1, name: "host"

        base_chain "input", hook: :input, type: :filter,
          priority: :filter, policy: :drop do
          nft_rule :drop, counter: "input_drop",
            log_prefix: "HOST: ", nflog_group: 1
        end
      end
  """
  defmacro nft_nflog_group(group, opts \\ []) do
    quote do
      var!(ek_nft_table) =
        Erlkoenig.Nft.TableBuilder.add_nflog_group(
          var!(ek_nft_table),
          unquote(group),
          unquote(opts)
        )
    end
  end

  @doc """
  Declare a verdict map (vmap) at table level.

  Verdict maps associate keys with verdicts (accept/drop/jump). Used for
  efficient multi-target dispatch — one lookup instead of N sequential rules.

  ## Arguments

  | Argument | Type | Description |
  |----------|------|-------------|
  | `name` | `string` | Vmap name |
  | `type` | `atom` | Key type: `:ipv4_addr`, `:inet_service`, etc. |
  | `entries` | `[{key, action}]` | Static entries: `[{{10,0,0,2}, :accept}]` |

  ## Examples

      nft_zone do
        nft_vmap "dispatch", :ipv4_addr, [
          {{10, 0, 0, 2}, {:jump, "handle-web"}},
          {{10, 0, 0, 3}, {:jump, "handle-api"}}
        ]

        base_chain "forward", hook: :forward, type: :filter,
          priority: :filter, policy: :drop do
          nft_rule :vmap_dispatch, vmap: "dispatch"
        end
      end
  """
  defmacro nft_vmap(name, type, entries) do
    quote do
      var!(ek_nft_table) =
        Erlkoenig.Nft.TableBuilder.add_vmap(
          var!(ek_nft_table),
          unquote(name),
          unquote(type),
          unquote(entries)
        )
    end
  end

  @doc """
  Declare a named data map at table level.

  Data maps associate keys with data values (not verdicts). Used for
  jhash loadbalancing: hash result (integer) → container IP.

  The developer explicitly defines the map and its entries. No implicit
  map creation — what you write is what the kernel gets.

  ## Arguments

  | Argument | Type | Description |
  |----------|------|-------------|
  | `name` | `string` | Map name (e.g., `"web_jhash"`) |
  | `key_type` | `atom` | Key type: `:mark`, `:ipv4_addr`, etc. |
  | `data_type` | `atom` | Value type: `:ipv4_addr`, `:inet_service`, etc. |
  | `entries` | `list` | Static entries or `{:replica_ips, pod, ct}` |

  ## Examples

      # jhash loadbalancing map
      nft_map "web_jhash", :mark, :ipv4_addr,
        entries: {:replica_ips, "web", "nginx"}

      # Rule references the map explicitly
      nft_rule :dnat_jhash,
        iifname: "eth0",
        tcp_dport: 8443,
        map: "web_jhash",
        port: 8443
  """
  defmacro nft_map(name, key_type, data_type, opts \\ []) do
    # Accept both shapes:
    #   nft_map "m", :t, :t, [entries: [{k, v}, ...]]   (keyword form)
    #   nft_map "m", :t, :t, [{k, v}, {k, v}, ...]      (positional list)
    #   nft_map "m", :t, :t, {:replica_ips, "p", "c"}   (single ref)
    # Previously only keyword form was read — positional lists were
    # silently dropped (emitted as entries: []), leaving operators
    # with empty maps in the kernel.
    quote do
      var!(ek_nft_table) =
        Erlkoenig.Nft.TableBuilder.add_map(
          var!(ek_nft_table),
          unquote(name),
          unquote(key_type),
          unquote(data_type),
          Erlkoenig.Nft.TableBuilder.normalize_map_entries(unquote(opts))
        )
    end
  end

  @doc """
  Declare a concatenated verdict map at table level.

  Concat verdict maps use composite keys (e.g., ip saddr . ip daddr . tcp dport)
  for O(1) policy lookups. Replaces multiple individual accept/drop rules
  with a single hashtable lookup.

  ## Arguments

  | Argument | Type | Description |
  |----------|------|-------------|
  | `name` | `string` | Map name (e.g., `"fwd_policy"`) |
  | `fields` | `[atom]` | Key fields: `[:ipv4_addr, :ipv4_addr, :inet_service]` |
  | `entries` | `[tuple]` | `[{saddr, daddr, port, verdict}, ...]` |

  ## Examples

      nft_vmap "fwd_policy",
        fields: [:ipv4_addr, :ipv4_addr, :inet_service],
        entries: [
          {{10,0,0,2}, {10,0,1,2}, 4000, :accept},
          {{10,0,1,2}, {10,0,2,2}, 5432, :accept}
        ]

      nft_rule :vmap_lookup, vmap: "fwd_policy"
  """
  defmacro nft_vmap(name, opts) when is_list(opts) do
    fields = Keyword.fetch!(opts, :fields)
    entries = Keyword.get(opts, :entries, [])

    quote do
      var!(ek_nft_table) =
        Erlkoenig.Nft.TableBuilder.add_concat_vmap(
          var!(ek_nft_table),
          unquote(name),
          unquote(fields),
          unquote(entries)
        )
    end
  end
end
