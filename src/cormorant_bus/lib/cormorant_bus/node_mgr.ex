defmodule CormorantBus.NodeMgr do
  use GenServer

  @heartbeat_interval 5_000
  @offline_threshold 15_000

  def start_link(_) do
    GenServer.start_link(__MODULE__, %{nodes: %{}}, name: __MODULE__)
  end

  def init(state) do
    schedule_heartbeat()
    {:ok, state}
  end

  def get_nodes do
    GenServer.call(__MODULE__, :get_nodes)
  end

  def handle_call(:get_nodes, _from, state) do
    {:reply, state.nodes, state}
  end

  def handle_info(:heartbeat, state) do
    # Check all known nodes via Headscale API
    nodes = fetch_headscale_nodes()
    now = System.monotonic_time(:millisecond)

    updated_nodes = Enum.reduce(nodes, state.nodes, fn node, acc ->
      Map.put(acc, node["Hostname"], %{
        name: node["Hostname"],
        ip: List.first(node["IPAddresses"] || []),
        last_seen: node["LastSeen"] || "unknown",
        online: node["Online"] || false,
        updated_at: now
      })
    end)

    # Mark nodes offline if not seen
    final_nodes = Map.map(updated_nodes, fn {_k, v} ->
      if now - v.updated_at > @offline_threshold do
        %{v | online: false}
      else
        v
      end
    end)

    # Broadcast fleet status to all subscribers
    Phoenix.PubSub.broadcast(CormorantBus.PubSub, "fleet", {:fleet_update, final_nodes})

    schedule_heartbeat()
    {:noreply, %{state | nodes: final_nodes}}
  end

  defp schedule_heartbeat do
    Process.send_after(self(), :heartbeat, @heartbeat_interval)
  end

  defp fetch_headscale_nodes do
    case System.cmd("headscale", ["nodes", "list", "--output", "json"]) do
      {output, 0} ->
        case Jason.decode(output) do
          {:ok, nodes} -> nodes
          _ -> []
        end
      _ -> []
    end
  rescue
    _ -> []
  end
end
