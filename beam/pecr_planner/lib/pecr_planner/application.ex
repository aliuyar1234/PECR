defmodule PecrPlanner.Application do
  use Application

  @impl true
  def start(_type, _args) do
    children = [
      PecrPlanner.ShadowPlanner,
      {Task.Supervisor, name: PecrPlanner.UsefulnessTaskSupervisor}
    ]

    Supervisor.start_link(children,
      strategy: :one_for_one,
      name: PecrPlanner.Supervisor
    )
  end
end
