defmodule PecrPlanner.CLITest do
  use ExUnit.Case, async: true

  test "cli builds a valid shadow response from contract fields" do
    {output, exit_code} =
      PecrPlanner.CLI.run([
        "--schema-version",
        "1",
        "--query",
        "What is the customer status and plan tier?",
        "--intent",
        "structured_lookup",
        "--operator",
        "fetch_rows",
        "--operator",
        "lookup_evidence",
        "--allow-search-ref-fetch-span"
      ])

    assert exit_code == 0
    assert String.contains?(output, "status=ok")
    assert String.contains?(output, "step=operator|fetch_rows")
  end
end
