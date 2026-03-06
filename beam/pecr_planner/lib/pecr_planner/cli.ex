defmodule PecrPlanner.CLI do
  @moduledoc false

  alias PecrPlanner.Contracts

  @spec run([String.t()]) :: {String.t(), integer()}
  def run(argv) do
    argv
    |> parse_request()
    |> run_shadow_plan()
    |> serialize()
  end

  @spec run_from_env(map()) :: {String.t(), integer()}
  def run_from_env(env \\ System.get_env()) do
    env
    |> request_from_env()
    |> run_shadow_plan()
    |> serialize()
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

  @spec main_from_env(map() | nil) :: no_return()
  def main_from_env(env \\ nil) do
    {serialized_response, exit_code} =
      env
      |> env_map()
      |> run_from_env()

    IO.write(serialized_response)
    System.halt(exit_code)
  end

  defp cli_args(nil), do: System.argv()
  defp cli_args(argv), do: argv
  defp env_map(nil), do: System.get_env()
  defp env_map(env), do: env

  defp parse_request(argv) do
    {options, _rest, invalid} =
      OptionParser.parse(argv,
        strict: [
          schema_version: :integer,
          query: :string,
          intent: :string,
          operator: :keep,
          recovery_failed_step: :string,
          recovery_failure_terminal_mode: :string,
          allow_search_ref_fetch_span: :boolean,
          max_operator_calls: :integer,
          max_bytes: :integer,
          max_wallclock_ms: :integer,
          max_recursion_depth: :integer,
          max_parallelism: :integer
        ]
      )

    cond do
      invalid != [] ->
        {:error,
         Contracts.invalid_plan_request([
           "invalid cli arguments: " <>
             Enum.map_join(invalid, ", ", fn {key, _value} -> "--#{key}" end)
         ])}

      true ->
        options
        |> Contracts.plan_request_from_cli()
        |> then(&{:ok, &1})
    end
  end

  defp run_shadow_plan({:ok, request}) do
    PecrPlanner.shadow_plan(request)
  end

  defp run_shadow_plan({:error, error_response}), do: {:error, error_response}

  defp serialize(result) do
    serialized_response = Contracts.encode_cli_response(result)
    exit_code = if String.starts_with?(serialized_response, "status=ok\n"), do: 0, else: 2
    {serialized_response, exit_code}
  end

  defp request_from_env(env) do
    operators =
      env
      |> Map.get("PECR_PLANNER_AVAILABLE_OPERATORS", "")
      |> String.split(",", trim: true)

    {:ok,
     Contracts.plan_request_from_cli(
       schema_version: parse_integer(Map.get(env, "PECR_PLANNER_SCHEMA_VERSION"), 1),
       query: Map.get(env, "PECR_PLANNER_QUERY", ""),
       intent: Map.get(env, "PECR_PLANNER_INTENT", "default"),
       operator: operators,
       recovery_failed_step: Map.get(env, "PECR_PLANNER_RECOVERY_FAILED_STEP"),
       recovery_failure_terminal_mode:
         Map.get(env, "PECR_PLANNER_RECOVERY_FAILURE_TERMINAL_MODE"),
       allow_search_ref_fetch_span:
         parse_boolean(Map.get(env, "PECR_PLANNER_ALLOW_SEARCH_REF_FETCH_SPAN")),
       max_operator_calls: parse_integer(Map.get(env, "PECR_PLANNER_MAX_OPERATOR_CALLS"), 10),
       max_bytes: parse_integer(Map.get(env, "PECR_PLANNER_MAX_BYTES"), 2_048),
       max_wallclock_ms: parse_integer(Map.get(env, "PECR_PLANNER_MAX_WALLCLOCK_MS"), 1_000),
       max_recursion_depth: parse_integer(Map.get(env, "PECR_PLANNER_MAX_RECURSION_DEPTH"), 3),
       max_parallelism: parse_optional_integer(Map.get(env, "PECR_PLANNER_MAX_PARALLELISM"))
     )}
  end

  defp parse_integer(nil, default), do: default

  defp parse_integer(value, default) do
    case Integer.parse(value) do
      {parsed, ""} -> parsed
      _ -> default
    end
  end

  defp parse_optional_integer(nil), do: nil

  defp parse_optional_integer(value) do
    case Integer.parse(value) do
      {parsed, ""} -> parsed
      _ -> nil
    end
  end

  defp parse_boolean("1"), do: true
  defp parse_boolean("true"), do: true
  defp parse_boolean("TRUE"), do: true
  defp parse_boolean(_value), do: false
end
