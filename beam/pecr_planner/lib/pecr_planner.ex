defmodule PecrPlanner do
  @moduledoc """
  Public entrypoint for the shadow-only BEAM planner scaffold.
  """

  alias PecrPlanner.Contracts
  alias PecrPlanner.ShadowPlanner
  alias PecrPlanner.UsefulnessJobs

  @spec shadow_plan(map()) :: {:ok, map()} | {:error, map()}
  def shadow_plan(plan_request) when is_map(plan_request) do
    ShadowPlanner.plan(plan_request)
  end

  def shadow_plan(_plan_request) do
    {:error, Contracts.invalid_plan_request(["plan_request must be a map"])}
  end

  @spec request_example() :: map()
  def request_example do
    Contracts.plan_request_example()
  end

  @spec response_example() :: map()
  def response_example do
    request_example()
    |> Contracts.build_plan_response("beam-shadow-1", "0.1.0")
  end

  @spec run_usefulness_job(String.t() | atom(), keyword()) :: {:ok, map()} | {:error, map()}
  def run_usefulness_job(job_name, options \\ []) do
    UsefulnessJobs.run(job_name, options)
  end

  @spec supported_usefulness_jobs() :: [String.t()]
  def supported_usefulness_jobs do
    UsefulnessJobs.supported_jobs()
  end
end
