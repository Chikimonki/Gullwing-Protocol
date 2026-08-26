defmodule CormorantBus.Application do
  use Application

  def start(_type, _args) do
    children = [
      # Phoenix PubSub for real-time alert fan-out
      {Phoenix.PubSub, name: CormorantBus.PubSub},

      # Fleet node tracker
      {CormorantBus.NodeMgr, []},

      # HTTP API + WebSocket server
      {Plug.Cowboy, scheme: :http, plug: CormorantBus.Router, options: [port: 4000]}
    ]

    opts = [strategy: :one_for_one, name: CormorantBus.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
