defmodule PecrPlanner.ShadowPlannerTest do
  use ExUnit.Case

  test "shadow_plan returns a contract-compatible shadow response" do
    assert {:ok, response} = PecrPlanner.shadow_plan(PecrPlanner.request_example())

    assert response["schema_version"] == 1

    assert response["steps"] == [
             %{
               "kind" => "operator",
               "op_name" => "fetch_rows",
               "params" => %{}
             }
           ]

    assert String.contains?(response["planner_summary"], "BEAM shadow planner")
  end

  test "version review intent prefers list_versions before lookup_evidence" do
    request =
      PecrPlanner.request_example()
      |> put_in(["planner_hints", "intent"], "version_review")

    assert {:ok, response} = PecrPlanner.shadow_plan(request)

    assert response["steps"] == [
             %{"kind" => "operator", "op_name" => "list_versions", "params" => %{}},
             %{"kind" => "operator", "op_name" => "lookup_evidence", "params" => %{}}
           ]
  end

  test "invalid payloads do not mutate planner stats" do
    before_stats = PecrPlanner.ShadowPlanner.stats()

    assert {:error, error_response} = PecrPlanner.shadow_plan(%{"schema_version" => 1})
    assert error_response["status"] == "invalid_plan_request"

    after_stats = PecrPlanner.ShadowPlanner.stats()
    assert after_stats["request_count"] == before_stats["request_count"]
  end
end
