defmodule PecrPlanner.JobCLI do
  @moduledoc false

  alias PecrPlanner.UsefulnessJob
  alias PecrPlanner.UsefulnessJobs

  @spec run([String.t()]) :: {String.t(), integer()}
  def run(argv) do
    with {:ok, job_name, options} <- parse(argv),
         {:ok, result} <- UsefulnessJobs.run(job_name, options) do
      {encode_success(result), 0}
    else
      {:error, error_response} ->
        {encode_error(error_response), 2}
    end
  end

  @spec main([String.t()] | nil) :: no_return()
  def main(argv \\ nil) do
    {serialized_response, exit_code} =
      argv
      |> cli_args()
      |> run()

    IO.write(serialized_response)
    System.halt(exit_code)
  end

  defp cli_args(nil), do: System.argv()
  defp cli_args(argv), do: argv

  defp parse([]) do
    {:error,
     UsefulnessJob.invalid_job_request([
       "expected a job name; supported jobs: #{Enum.join(UsefulnessJobs.supported_jobs(), ", ")}"
     ])}
  end

  defp parse([job_name | rest]) do
    {options, positional, invalid} =
      OptionParser.parse(rest,
        strict: [
          store: :string,
          benchmark_manifest: :string,
          evaluation_name: :string,
          engine_mode: :string,
          output_json: :string,
          output_md: :string,
          python: :string,
          timeout_ms: :integer,
          await_timeout_ms: :integer
        ]
      )

    cond do
      invalid != [] ->
        {:error,
         UsefulnessJob.invalid_job_request([
           "invalid cli arguments: " <>
             Enum.map_join(invalid, ", ", fn {key, _value} -> "--#{key}" end)
         ])}

      positional != [] ->
        {:error,
         UsefulnessJob.invalid_job_request([
           "unexpected positional arguments: #{Enum.join(positional, ", ")}"
         ])}

      true ->
        {:ok, job_name, options}
    end
  end

  defp encode_success(result) do
    lines =
      [
        "status=ok",
        "job_name=#{Map.get(result, "job_name")}",
        "job_status=#{Map.get(result, "status")}",
        "exit_status=#{Map.get(result, "exit_status")}",
        "duration_ms=#{Map.get(result, "duration_ms")}",
        "started_at_unix_ms=#{Map.get(result, "started_at_unix_ms")}",
        "finished_at_unix_ms=#{Map.get(result, "finished_at_unix_ms")}",
        "summary_b64=#{Base.encode64(Map.get(result, "summary") || "")}",
        "command_b64=#{Base.encode64(Map.get(result, "command") || "")}",
        "output_b64=#{Base.encode64(Map.get(result, "output") || "")}"
      ]
      |> append_artifacts(Map.get(result, "artifacts") || %{})
      |> append_errors(Map.get(result, "errors"))

    Enum.join(lines, "\n") <> "\n"
  end

  defp encode_error(error_response) do
    [
      "status=error",
      "error_status=#{Map.get(error_response, "status") || "unknown"}",
      "errors_b64=#{Base.encode64(Enum.join(Map.get(error_response, "errors") || [], "\n"))}"
    ]
    |> Enum.join("\n")
    |> Kernel.<>("\n")
  end

  defp append_artifacts(lines, artifacts) when map_size(artifacts) == 0, do: lines

  defp append_artifacts(lines, artifacts) do
    artifact_lines =
      artifacts
      |> Enum.sort_by(fn {key, _value} -> key end)
      |> Enum.map(fn {key, value} ->
        "artifact=#{key}|#{Base.encode64(value)}"
      end)

    lines ++ artifact_lines
  end

  defp append_errors(lines, nil), do: lines
  defp append_errors(lines, []), do: lines

  defp append_errors(lines, errors) do
    lines ++ ["errors_b64=#{Base.encode64(Enum.join(errors, "\n"))}"]
  end
end
