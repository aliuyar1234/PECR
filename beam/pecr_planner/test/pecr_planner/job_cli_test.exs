defmodule PecrPlanner.JobCLITest do
  use ExUnit.Case, async: true

  test "job cli runs benchmark validation and serializes a success response" do
    {output, exit_code} =
      PecrPlanner.JobCLI.run([
        "validate-benchmark",
        "--store",
        "fixtures/replay/useful_tasks"
      ])

    assert exit_code == 0
    assert String.contains?(output, "status=ok")
    assert String.contains?(output, "job_name=validate-benchmark")
    assert String.contains?(output, "job_status=succeeded")
    assert String.contains?(output, "command_b64=")
  end

  test "job cli rejects unsupported job names" do
    {output, exit_code} = PecrPlanner.JobCLI.run(["do-not-run"])

    assert exit_code == 2
    assert String.contains?(output, "status=error")
    assert String.contains?(output, "error_status=invalid_job_request")
  end
end
