defmodule PecrPlanner.UsefulnessJob do
  @moduledoc false

  alias PecrPlanner.Paths

  @default_store "fixtures/replay/useful_tasks"
  @default_benchmark_manifest "fixtures/replay/useful_tasks/benchmark_manifest.json"
  @default_timeout_ms 30_000
  @supported_jobs ~w(validate-benchmark planner-compare scenario-preview nightly-report)

  @spec supported_jobs() :: [String.t()]
  def supported_jobs, do: @supported_jobs

  @spec default_timeout_ms() :: pos_integer()
  def default_timeout_ms, do: @default_timeout_ms

  @spec build(String.t() | atom(), keyword()) :: {:ok, map()} | {:error, map()}
  def build(job_name, options \\ []) do
    normalized_job_name =
      job_name
      |> to_string()
      |> String.trim()

    with :ok <- validate_job_name(normalized_job_name),
         {:ok, python} <- resolve_python(Keyword.get(options, :python)),
         {:ok, timeout_ms} <-
           resolve_timeout_ms(Keyword.get(options, :timeout_ms, @default_timeout_ms)),
         {:ok, spec} <- build_spec(normalized_job_name, python, timeout_ms, options) do
      {:ok, spec}
    end
  end

  @spec execute(map()) :: map()
  def execute(spec) do
    started_at_unix_ms = System.system_time(:millisecond)
    monotonic_started = System.monotonic_time(:millisecond)

    result =
      try do
        {output, exit_status} =
          System.cmd(spec.executable, spec.args,
            cd: spec.cd,
            stderr_to_stdout: true
          )

        %{
          "job_name" => spec.job_name,
          "summary" => spec.summary,
          "status" => if(exit_status == 0, do: "succeeded", else: "failed"),
          "exit_status" => exit_status,
          "command" => command_string(spec.executable, spec.args),
          "output" => output,
          "artifacts" => spec.artifacts
        }
      rescue
        error ->
          %{
            "job_name" => spec.job_name,
            "summary" => spec.summary,
            "status" => "failed_to_start",
            "exit_status" => nil,
            "command" => command_string(spec.executable, spec.args),
            "errors" => [Exception.message(error)],
            "output" => "",
            "artifacts" => spec.artifacts
          }
      end

    finished_at_unix_ms = System.system_time(:millisecond)
    duration_ms = System.monotonic_time(:millisecond) - monotonic_started

    Map.merge(result, %{
      "started_at_unix_ms" => started_at_unix_ms,
      "finished_at_unix_ms" => finished_at_unix_ms,
      "duration_ms" => duration_ms
    })
  end

  @spec invalid_job_request([String.t()]) :: map()
  def invalid_job_request(errors) do
    %{
      "status" => "invalid_job_request",
      "errors" => errors
    }
  end

  defp validate_job_name(job_name) when job_name in @supported_jobs, do: :ok

  defp validate_job_name(_job_name) do
    {:error,
     invalid_job_request([
       "unsupported job name; expected one of #{Enum.join(@supported_jobs, ", ")}"
     ])}
  end

  defp resolve_python(nil) do
    case System.find_executable("python") || System.find_executable("python3") do
      nil -> {:error, invalid_job_request(["python executable not found"])}
      python -> {:ok, python}
    end
  end

  defp resolve_python(python) when is_binary(python) and byte_size(python) > 0 do
    case System.find_executable(python) do
      nil ->
        if File.exists?(python) do
          {:ok, Path.expand(python)}
        else
          {:error, invalid_job_request(["python executable not found: #{python}"])}
        end

      resolved ->
        {:ok, resolved}
    end
  end

  defp resolve_timeout_ms(timeout_ms) when is_integer(timeout_ms) and timeout_ms > 0,
    do: {:ok, timeout_ms}

  defp resolve_timeout_ms(_timeout_ms) do
    {:error, invalid_job_request(["timeout_ms must be a positive integer"])}
  end

  defp build_spec("validate-benchmark", python, timeout_ms, options) do
    with {:ok, store} <- resolve_store(options) do
      {:ok,
       base_spec("validate-benchmark", python, timeout_ms,
         summary: "Validate deterministic useful-answer benchmark fixtures.",
         args: benchmark_cli_args(store, "validate")
       )}
    end
  end

  defp build_spec("planner-compare", python, timeout_ms, options) do
    with {:ok, store} <- resolve_store(options) do
      {:ok,
       base_spec("planner-compare", python, timeout_ms,
         summary: "Compare planner traces against the useful-answer benchmark manifest.",
         args: benchmark_cli_args(store, "planner-compare")
       )}
    end
  end

  defp build_spec("scenario-preview", python, timeout_ms, options) do
    with {:ok, store} <- resolve_store(options) do
      {:ok,
       base_spec("scenario-preview", python, timeout_ms,
         summary: "Preview benchmark scenarios for safe usefulness and scenario-expansion prep.",
         args: benchmark_cli_args(store, "list")
       )}
    end
  end

  defp build_spec("nightly-report", python, timeout_ms, options) do
    with {:ok, store} <- resolve_store(options),
         {:ok, benchmark_manifest} <- resolve_benchmark_manifest(options),
         {:ok, evaluation_name} <- resolve_evaluation_name(options),
         {:ok, engine_mode_args} <- resolve_engine_mode_args(options),
         {:ok, artifact_args, artifacts} <- resolve_artifact_args(options) do
      args =
        [
          "-B",
          repo_script("scripts/replay/nightly_usefulness_report.py"),
          "--store",
          store,
          "--benchmark-manifest",
          benchmark_manifest,
          "--evaluation-name",
          evaluation_name
        ] ++ engine_mode_args ++ artifact_args

      {:ok,
       base_spec("nightly-report", python, timeout_ms,
         summary: "Generate nightly usefulness JSON and Markdown artifacts from replay fixtures.",
         args: args,
         artifacts: artifacts
       )}
    end
  end

  defp base_spec(job_name, executable, timeout_ms, options) do
    %{
      job_name: job_name,
      executable: executable,
      args: Keyword.fetch!(options, :args),
      cd: Paths.repo_root(),
      timeout_ms: timeout_ms,
      summary: Keyword.fetch!(options, :summary),
      artifacts: Keyword.get(options, :artifacts, %{})
    }
  end

  defp benchmark_cli_args(store, command) do
    [
      "-B",
      repo_script("scripts/replay/useful_benchmark_cli.py"),
      "--store",
      store,
      command
    ]
  end

  defp resolve_store(options) do
    options
    |> Keyword.get(:store)
    |> resolve_repo_path(@default_store)
  end

  defp resolve_benchmark_manifest(options) do
    options
    |> Keyword.get(:benchmark_manifest)
    |> resolve_repo_path(@default_benchmark_manifest)
  end

  defp resolve_evaluation_name(options) do
    evaluation_name =
      options
      |> Keyword.get(:evaluation_name, "beam-shadow-usefulness")
      |> to_string()
      |> String.trim()

    if evaluation_name == "" do
      {:error, invalid_job_request(["evaluation_name must be a non-empty string"])}
    else
      {:ok, evaluation_name}
    end
  end

  defp resolve_engine_mode_args(options) do
    case Keyword.get(options, :engine_mode) do
      nil ->
        {:ok, []}

      engine_mode when engine_mode in ["baseline", "beam_planner", "rlm"] ->
        {:ok, ["--engine-mode", engine_mode]}

      engine_mode ->
        {:error,
         invalid_job_request([
           "engine_mode must be baseline, beam_planner, or rlm when provided (got #{inspect(engine_mode)})"
         ])}
    end
  end

  defp resolve_artifact_args(options) do
    with {:ok, output_json} <- optional_repo_path(Keyword.get(options, :output_json)),
         {:ok, output_md} <- optional_repo_path(Keyword.get(options, :output_md)) do
      args =
        []
        |> maybe_append_path("--output-json", output_json)
        |> maybe_append_path("--output-md", output_md)

      artifacts =
        %{}
        |> maybe_put_artifact("output_json", output_json)
        |> maybe_put_artifact("output_md", output_md)

      {:ok, args, artifacts}
    end
  end

  defp optional_repo_path(nil), do: {:ok, nil}
  defp optional_repo_path(path), do: resolve_repo_path(path)

  defp resolve_repo_path(path, default_relative_path \\ nil) do
    case Paths.resolve_repo_path(path, default_relative_path) do
      {:ok, resolved_path} -> {:ok, resolved_path}
      {:error, message} -> {:error, invalid_job_request([message])}
    end
  end

  defp maybe_append_path(args, _flag, nil), do: args
  defp maybe_append_path(args, flag, path), do: args ++ [flag, path]

  defp maybe_put_artifact(artifacts, _key, nil), do: artifacts
  defp maybe_put_artifact(artifacts, key, path), do: Map.put(artifacts, key, path)

  defp repo_script(relative_path) do
    Path.join(Paths.repo_root(), relative_path)
  end

  defp command_string(executable, args) do
    [executable | args]
    |> Enum.map(&shell_fragment/1)
    |> Enum.join(" ")
  end

  defp shell_fragment(fragment) do
    if String.contains?(fragment, [" ", "\t", "\""]) do
      "\"" <> String.replace(fragment, "\"", "\\\"") <> "\""
    else
      fragment
    end
  end
end
