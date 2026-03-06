defmodule PecrPlanner.UsefulnessJobsTest do
  use ExUnit.Case

  alias PecrPlanner.Paths
  alias PecrPlanner.UsefulnessJobs

  test "supported jobs stay explicitly allowlisted" do
    assert UsefulnessJobs.supported_jobs() == [
             "validate-benchmark",
             "planner-compare",
             "scenario-preview",
             "nightly-report"
           ]
  end

  test "validate benchmark job succeeds against deterministic fixtures" do
    assert {:ok, result} =
             UsefulnessJobs.run("validate-benchmark", store: "fixtures/replay/useful_tasks")

    assert result["job_name"] == "validate-benchmark"
    assert result["status"] == "succeeded"
    assert result["exit_status"] == 0
    assert String.contains?(result["command"], "useful_benchmark_cli.py")
    assert String.contains?(result["output"], "\"ok\": true")
  end

  test "scenario preview job runs through the task supervisor" do
    assert {:ok, task} =
             UsefulnessJobs.start("scenario-preview", store: "fixtures/replay/useful_tasks")

    assert {:ok, result} = UsefulnessJobs.await(task, 30_000)
    assert result["job_name"] == "scenario-preview"
    assert result["status"] == "succeeded"
    assert result["exit_status"] == 0
    assert String.contains?(result["output"], "\"scenarios\"")
  end

  test "planner compare job succeeds against deterministic fixtures" do
    assert {:ok, result} =
             UsefulnessJobs.run("planner-compare", store: "fixtures/replay/useful_tasks")

    assert result["job_name"] == "planner-compare"
    assert result["status"] == "succeeded"
    assert result["exit_status"] == 0
    assert String.contains?(result["output"], "\"planner_comparisons\"")
  end

  test "nightly report job writes requested artifacts inside the repository" do
    tmp_dir =
      Path.join([
        Paths.beam_root(),
        "tmp",
        "test-nightly-report-#{System.unique_integer([:positive])}"
      ])

    File.mkdir_p!(tmp_dir)

    on_exit(fn ->
      File.rm_rf(tmp_dir)
    end)

    output_json = Path.join(tmp_dir, "nightly.json")
    output_md = Path.join(tmp_dir, "nightly.md")

    assert {:ok, result} =
             UsefulnessJobs.run("nightly-report",
               store: "fixtures/replay/useful_tasks",
               benchmark_manifest: "fixtures/replay/useful_tasks/benchmark_manifest.json",
               evaluation_name: "beam-shadow-fixture-report",
               output_json: output_json,
               output_md: output_md
             )

    assert result["job_name"] == "nightly-report"
    assert result["status"] == "succeeded"
    assert result["exit_status"] == 0
    assert File.exists?(output_json)
    assert File.exists?(output_md)
    assert result["artifacts"]["output_json"] == Path.expand(output_json)
    assert result["artifacts"]["output_md"] == Path.expand(output_md)
  end

  test "artifact paths may not escape the repository root" do
    assert {:error, error_response} =
             UsefulnessJobs.run("nightly-report",
               evaluation_name: "bad-path",
               output_json: "..\\outside.json"
             )

    assert error_response["status"] == "invalid_job_request"
    assert Enum.any?(error_response["errors"], &String.contains?(&1, "repository root"))
  end
end
