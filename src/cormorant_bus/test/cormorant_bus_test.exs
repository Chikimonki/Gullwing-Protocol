defmodule CormorantBusTest do
  use ExUnit.Case
  doctest CormorantBus

  test "greets the world" do
    assert CormorantBus.hello() == :world
  end
end
