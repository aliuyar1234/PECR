defmodule PecrPlanner.UsefulnessJobs do
  @moduledoc false

  alias PecrPlanner.UsefulnessJob

  @task_supervisor PecrPlanner.UsefulnessTaskSupervisor
  @await_padding_ms 1_000

  @spec supported_jobs() :: [String.t()]
  def supported_jobs, do: UsefulnessJob.supported_jobs()

  @spec start(String.t() | atom(), keyword()) :: {:ok, Task.t()} | {:error, map()}
  def start(job_name, options \\ []) do
    with {:ok, _apps} <- ensure_started(),
         {:ok, spec} <- UsefulnessJob.build(job_name, options) do
      {:ok,
       Task.Supervisor.async_nolink(@task_supervisor, fn ->
         UsefulnessJob.execute(spec)
       end)}
    end
  end

  @spec run(String.t() | atom(), keyword()) :: {:ok, map()} | {:error, map()}
  def run(job_name, options \\ []) do
    await_timeout_ms =
      options
      |> Keyword.get(:await_timeout_ms)
      |> resolve_await_timeout(
        Keyword.get(options, :timeout_ms, UsefulnessJob.default_timeout_ms())
      )

    with {:ok, task} <- start(job_name, options) do
      await(task, await_timeout_ms)
    end
  end

  @spec await(Task.t(), pos_integer()) :: {:ok, map()} | {:error, map()}
  def await(%Task{} = task, timeout_ms) when is_integer(timeout_ms) and timeout_ms > 0 do
    case Task.yield(task, timeout_ms) || Task.shutdown(task, :brutal_kill) do
      {:ok, result} ->
        {:ok, result}

      nil ->
        {:error,
         UsefulnessJob.invalid_job_request([
           "job timed out after #{timeout_ms} ms"
         ])}
    end
  end

  defp ensure_started do
    Application.ensure_all_started(:pecr_planner)
  end

  defp resolve_await_timeout(nil, job_timeout_ms), do: job_timeout_ms + @await_padding_ms

  defp resolve_await_timeout(await_timeout_ms, _job_timeout_ms)
       when is_integer(await_timeout_ms) and await_timeout_ms > 0,
       do: await_timeout_ms

  defp resolve_await_timeout(_await_timeout_ms, job_timeout_ms),
    do: job_timeout_ms + @await_padding_ms
end
