defmodule CormorantBus.Router do
  use Plug.Router

  plug :match
  plug :dispatch

  get "/health" do
    send_resp(conn, 200, Jason.encode!(%{status: "ok", name: "cormorant_bus", version: "1.0.0"}))
  end

  get "/fleet" do
    nodes = %{"desktop-sh1trj9" => %{name: "desktop-sh1trj9", ip: "100.64.0.1", online: true, last_seen: "now"}}
    send_resp(conn, 200, Jason.encode!(%{nodes: nodes, count: 1}))
  end

  post "/alert" do
    {:ok, body, conn} = read_body(conn)
    alert = Jason.decode!(body)
    Phoenix.PubSub.broadcast(CormorantBus.PubSub, "alerts", {:alert, alert})
    IO.puts("[ALERT] #{alert["type"]} — #{alert["binary"]} (weight: #{alert["weight"]})")
    send_resp(conn, 201, Jason.encode!(%{published: true}))
  end

  match _ do
    send_resp(conn, 404, Jason.encode!(%{error: "not found"}))
  end
end
