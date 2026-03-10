#
# Copyright 2026 Erlkoenig Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

defmodule Erlkoenig.Firewall.Profiles do
  @moduledoc """
  Predefined firewall profiles for common container use cases.

  Each profile returns a term map compatible with
  `erlkoenig_firewall_nft:add_container/5`.

  Profiles:
    - `:strict`   — Only established + ICMP. No outbound by default.
    - `:standard` — Established + ICMP + DNS. Outbound allowed.
    - `:open`     — Everything allowed (monitoring only).

  ## Usage

      Erlkoenig.Firewall.Profiles.get(:standard)
      Erlkoenig.Firewall.Profiles.get(:strict, allow_tcp: [443])
  """

  alias Erlkoenig.Firewall.Builder

  @doc "Returns the term map for a named profile."
  def get(profile, opts \\ [])

  def get(:strict, opts) do
    allow_tcp = Keyword.get(opts, :allow_tcp, [])
    allow_udp = Keyword.get(opts, :allow_udp, [])

    b = Builder.new("strict")
    b = %{b | rules_acc: []}

    rules =
      [:ct_established_accept, :icmp_accept] ++
        Enum.map(allow_tcp, &{:tcp_accept, &1}) ++
        Enum.map(allow_udp, &{:udp_accept, &1})

    b = Builder.add_chain(b, "inbound", [hook: :input, policy: :drop], rules)
    Builder.to_term(b)
  end

  def get(:standard, opts) do
    allow_tcp = Keyword.get(opts, :allow_tcp, [])
    allow_udp = Keyword.get(opts, :allow_udp, [])

    b = Builder.new("standard")

    rules =
      [:ct_established_accept, :icmp_accept, {:udp_accept, 53}] ++
        Enum.map(allow_tcp, &{:tcp_accept, &1}) ++
        Enum.map(allow_udp, &{:udp_accept, &1}) ++
        [:accept]

    b = Builder.add_chain(b, "inbound", [hook: :input, policy: :drop], rules)
    Builder.to_term(b)
  end

  def get(:open, _opts) do
    b = Builder.new("open")
    b = Builder.add_chain(b, "inbound", [hook: :input, policy: :accept], [])
    Builder.to_term(b)
  end

  @doc "List all available profile names."
  def list, do: [:strict, :standard, :open]
end
