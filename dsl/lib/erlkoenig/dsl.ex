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

defmodule Erlkoenig.DSL do
  @moduledoc """
  Unified DSL entry point for Erlkoenig configurations.

  Combines container definitions with inline firewall rules.

  ## Example

      defmodule MyCluster do
        use Erlkoenig.DSL

        defaults do
          firewall :standard
        end

        container :web do
          binary "/opt/bin/server"
          ip {10, 0, 0, 10}
          ports [{8080, 80}]
          firewall :strict, allow_tcp: [80, 443]
        end

        container :worker do
          binary "/opt/bin/worker"
          ip {10, 0, 0, 20}
        end
      end

      MyCluster.containers()
      MyCluster.spawn_opts()
      MyCluster.watches()
      MyCluster.guard_config()
      MyCluster.write!("/etc/erlkoenig/cluster.term")
  """

  defmacro __using__(_opts) do
    quote do
      use Erlkoenig.Container
      use Erlkoenig.Watch
      use Erlkoenig.Guard
    end
  end
end
