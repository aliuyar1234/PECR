defmodule PecrPlanner.ContractsTest do
  use ExUnit.Case, async: true

  alias PecrPlanner.Contracts

  test "example request is valid" do
    assert :ok = Contracts.validate_plan_request(Contracts.plan_request_example())
  end

  test "invalid request reports contract field errors" do
    assert {:error, errors} =
             Contracts.validate_plan_request(%{
               "schema_version" => 2,
               "query" => "",
               "budget" => %{"max_operator_calls" => 0},
               "planner_hints" => %{}
             })

    assert "schema_version must be 1" in errors
    assert "query must be a non-empty string" in errors
    assert "budget.max_operator_calls must be a positive integer" in errors
    assert "planner_hints.intent is required" in errors
  end

  test "build_plan_response chooses useful shadow steps from planner intent" do
    response =
      Contracts.plan_request_example()
      |> Contracts.build_plan_response("beam-shadow-1", "0.1.0")

    assert response["schema_version"] == 1

    assert response["steps"] == [
             %{
               "kind" => "operator",
               "op_name" => "fetch_rows",
               "params" => %{}
             }
           ]

    assert String.contains?(response["planner_summary"], "structured_lookup")
  end

  test "cli response encoding emits line-based transport format" do
    response =
      Contracts.plan_response_example()
      |> then(&{:ok, &1})
      |> Contracts.encode_cli_response()

    assert String.contains?(response, "status=ok")
    assert String.contains?(response, "schema_version=1")
    assert String.contains?(response, "step=operator|fetch_rows")
    assert String.contains?(response, "planner_summary_b64=")
  end

  test "cli option parsing builds a contract-compatible request" do
    request =
      Contracts.plan_request_from_cli(
        query: "Show monthly customer trend over time",
        intent: "structured_aggregation",
        operator: "aggregate",
        allow_search_ref_fetch_span: true
      )

    assert :ok = Contracts.validate_plan_request(request)
    assert request["planner_hints"]["intent"] == "structured_aggregation"
    assert request["available_operator_names"] == ["aggregate"]
    assert request["allow_search_ref_fetch_span"] == true
  end

  test "recovery context steers the planner away from the failed step" do
    request =
      Contracts.plan_request_from_cli(
        query: "Show the source text and evidence for the support policy",
        intent: "evidence_lookup",
        operator: ["fetch_rows", "lookup_evidence"],
        recovery_failed_step: "fetch_rows",
        recovery_failure_terminal_mode: "SOURCE_UNAVAILABLE"
      )

    assert :ok = Contracts.validate_plan_request(request)

    response =
      request
      |> Contracts.build_plan_response("beam-shadow-recovery-1", "0.1.0")

    assert response["steps"] == [
             %{
               "kind" => "operator",
               "op_name" => "lookup_evidence",
               "params" => %{}
             }
           ]

    assert String.contains?(response["planner_summary"], "recovered from fetch_rows")
  end
end
