defmodule Erlkoenig.Stack.WatchMacros do
  @moduledoc false

  @doc """
  Configure a conntrack/nflog watcher.

  Watchers subscribe to kernel events (connection tracking, logged packets)
  and forward them to the erlkoenig event bus for AMQP publishing.

  ## Examples

      watch "connections" do
        # watcher configuration
      end
  """
  defmacro watch(name, do: block) do
    quote do
      var!(ek_watch_builder) = ErlkoenigNft.Watch.Builder.new(unquote(name))
      unquote(block)
      @stack_watches ErlkoenigNft.Watch.Builder.to_term(var!(ek_watch_builder))
    end
  end
end
