defmodule PecrPlanner.ShadowPlanner do
  use GenServer

  alias PecrPlanner.Contracts

  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @spec plan(map()) :: {:ok, map()} | {:error, map()}
  def plan(plan_request) when is_map(plan_request) do
    GenServer.call(__MODULE__, {:plan, plan_request})
  end

  @spec stats() :: map()
  def stats do
    GenServer.call(__MODULE__, :stats)
  end

  @impl true
  def init(_opts) do
    {:ok,
     %{
       planner_version: planner_version(),
       request_count: 0,
       last_request_id: nil
     }}
  end

  @impl true
  def handle_call({:plan, plan_request}, _from, state) do
    case Contracts.validate_plan_request(plan_request) do
      :ok ->
        request_count = state.request_count + 1
        request_id = Contracts.field(plan_request, "request_id")
        shadow_run_id = "beam-shadow-#{request_count}"

        response =
          Contracts.build_plan_response(plan_request, shadow_run_id, state.planner_version)

        next_state = %{
          state
          | request_count: request_count,
            last_request_id: request_id
        }

        {:reply, {:ok, response}, next_state}

      {:error, errors} ->
        {:reply, {:error, Contracts.invalid_plan_request(errors)}, state}
    end
  end

  def handle_call(:stats, _from, state) do
    {:reply,
     %{
       "planner_version" => state.planner_version,
       "request_count" => state.request_count,
       "last_request_id" => state.last_request_id,
       "status" => "shadow_only"
     }, state}
  end

  defp planner_version do
    case Application.spec(:pecr_planner, :vsn) do
      nil -> "0.1.0"
      version when is_list(version) -> List.to_string(version)
      version -> to_string(version)
    end
  end
end
