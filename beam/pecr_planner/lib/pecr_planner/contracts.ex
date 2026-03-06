defmodule PecrPlanner.Contracts do
  @moduledoc false

  @schema_version 1
  @default_budget %{
    "max_operator_calls" => 10,
    "max_bytes" => 2_048,
    "max_wallclock_ms" => 1_000,
    "max_recursion_depth" => 3,
    "max_parallelism" => 1
  }

  @spec plan_request_example() :: map()
  def plan_request_example do
    %{
      "schema_version" => @schema_version,
      "query" => "What is the customer status and plan tier?",
      "budget" => @default_budget,
      "planner_hints" => %{
        "intent" => "structured_lookup",
        "recommended_path" => [
          %{
            "kind" => "operator",
            "op_name" => "fetch_rows",
            "params" => %{
              "view_id" => "safe_customer_view_public",
              "fields" => ["status", "plan_tier"]
            }
          }
        ]
      },
      "available_operator_names" => [
        "fetch_rows",
        "lookup_evidence",
        "list_versions",
        "aggregate",
        "compare",
        "search",
        "fetch_span"
      ],
      "allow_search_ref_fetch_span" => true
    }
  end

  @spec plan_response_example() :: map()
  def plan_response_example do
    build_plan_response(plan_request_example(), "beam-shadow-1", "0.1.0")
  end

  @spec plan_request_from_cli(keyword()) :: map()
  def plan_request_from_cli(options) do
    operator_names =
      options
      |> Keyword.get_values(:operator)
      |> Enum.flat_map(fn
        value when is_list(value) -> value
        value -> [value]
      end)
      |> Enum.uniq()

    recovery_context = cli_recovery_context(options)

    %{
      "schema_version" => Keyword.get(options, :schema_version, @schema_version),
      "query" => Keyword.get(options, :query, ""),
      "budget" => %{
        "max_operator_calls" =>
          Keyword.get(options, :max_operator_calls, @default_budget["max_operator_calls"]),
        "max_bytes" => Keyword.get(options, :max_bytes, @default_budget["max_bytes"]),
        "max_wallclock_ms" =>
          Keyword.get(options, :max_wallclock_ms, @default_budget["max_wallclock_ms"]),
        "max_recursion_depth" =>
          Keyword.get(options, :max_recursion_depth, @default_budget["max_recursion_depth"]),
        "max_parallelism" =>
          Keyword.get(options, :max_parallelism, @default_budget["max_parallelism"])
      },
      "planner_hints" => %{
        "intent" => Keyword.get(options, :intent, "default"),
        "recommended_path" => []
      },
      "recovery_context" => recovery_context,
      "available_operator_names" => operator_names,
      "allow_search_ref_fetch_span" => Keyword.get(options, :allow_search_ref_fetch_span, false)
    }
    |> drop_nil_recovery_context()
  end

  @spec validate_plan_request(map()) :: :ok | {:error, [String.t()]}
  def validate_plan_request(plan_request) when is_map(plan_request) do
    errors =
      []
      |> validate_schema_version(field(plan_request, "schema_version"))
      |> validate_query(field(plan_request, "query"))
      |> validate_budget(field(plan_request, "budget"))
      |> validate_planner_hints(field(plan_request, "planner_hints"))
      |> validate_recovery_context(field(plan_request, "recovery_context"))
      |> validate_available_operator_names(field(plan_request, "available_operator_names"))
      |> validate_allow_search_ref_fetch_span(field(plan_request, "allow_search_ref_fetch_span"))

    case errors do
      [] -> :ok
      _ -> {:error, Enum.reverse(errors)}
    end
  end

  def validate_plan_request(_plan_request) do
    {:error, ["plan_request must be a map"]}
  end

  @spec invalid_plan_request([String.t()]) :: map()
  def invalid_plan_request(errors) do
    %{
      "status" => "invalid_plan_request",
      "errors" => errors
    }
  end

  @spec build_plan_response(map(), String.t(), String.t()) :: map()
  def build_plan_response(plan_request, shadow_run_id, planner_version) do
    steps = select_steps(plan_request)

    summary =
      build_summary(
        field(plan_request, "planner_hints") || %{},
        field(plan_request, "recovery_context"),
        steps,
        shadow_run_id,
        planner_version
      )

    %{
      "schema_version" => @schema_version,
      "steps" => steps,
      "planner_summary" => summary
    }
  end

  @spec encode_cli_response({:ok, map()} | {:error, map()}) :: String.t()
  def encode_cli_response({:ok, response}) do
    lines =
      ["status=ok", "schema_version=#{field(response, "schema_version")}"]
      |> append_summary(field(response, "planner_summary"))
      |> append_steps(field(response, "steps") || [])

    Enum.join(lines, "\n") <> "\n"
  end

  def encode_cli_response({:error, error_response}) do
    lines = [
      "status=error",
      "error_status=#{field(error_response, "status") || "unknown"}",
      "errors_b64=#{Base.encode64(Enum.join(field(error_response, "errors") || [], "\n"))}"
    ]

    Enum.join(lines, "\n") <> "\n"
  end

  @spec field(map(), String.t()) :: any()
  def field(map, key) do
    Map.get(map, key) || Map.get(map, String.to_atom(key))
  end

  defp validate_schema_version(errors, value) when is_integer(value) and value == @schema_version,
    do: errors

  defp validate_schema_version(errors, _value) do
    ["schema_version must be #{inspect(@schema_version)}" | errors]
  end

  defp validate_query(errors, value) when is_binary(value) and byte_size(value) > 0, do: errors
  defp validate_query(errors, _value), do: ["query must be a non-empty string" | errors]

  defp validate_budget(errors, budget) when is_map(budget) do
    errors
    |> require_positive_integer(budget, "max_operator_calls")
    |> require_positive_integer(budget, "max_bytes")
    |> require_non_negative_integer(budget, "max_wallclock_ms")
    |> require_positive_integer(budget, "max_recursion_depth")
    |> require_optional_positive_integer(budget, "max_parallelism")
  end

  defp validate_budget(errors, _budget), do: ["budget must be an object" | errors]

  defp validate_planner_hints(errors, planner_hints) when is_map(planner_hints) do
    errors
    |> require_non_empty_string(planner_hints, "intent", "planner_hints.intent is required")
    |> validate_recommended_path(field(planner_hints, "recommended_path"))
  end

  defp validate_planner_hints(errors, _planner_hints) do
    ["planner_hints must be an object" | errors]
  end

  defp validate_recovery_context(errors, nil), do: errors

  defp validate_recovery_context(errors, recovery_context) when is_map(recovery_context) do
    errors
    |> require_non_empty_string(
      recovery_context,
      "failed_step",
      "recovery_context.failed_step is required"
    )
    |> require_non_empty_string(
      recovery_context,
      "failure_terminal_mode",
      "recovery_context.failure_terminal_mode is required"
    )
    |> validate_attempted_path(field(recovery_context, "attempted_path"))
  end

  defp validate_recovery_context(errors, _recovery_context) do
    ["recovery_context must be an object when provided" | errors]
  end

  defp validate_recommended_path(errors, path) when is_list(path) do
    if Enum.all?(path, &valid_step?/1) do
      errors
    else
      ["planner_hints.recommended_path must contain valid planner steps" | errors]
    end
  end

  defp validate_recommended_path(errors, nil), do: errors

  defp validate_recommended_path(errors, _path),
    do: ["planner_hints.recommended_path must be an array" | errors]

  defp validate_attempted_path(errors, nil), do: errors

  defp validate_attempted_path(errors, path) when is_list(path) do
    if Enum.all?(path, &valid_step?/1) do
      errors
    else
      ["recovery_context.attempted_path must contain valid planner steps" | errors]
    end
  end

  defp validate_attempted_path(errors, _path),
    do: ["recovery_context.attempted_path must be an array" | errors]

  defp validate_available_operator_names(errors, operators) when is_list(operators) do
    if Enum.all?(operators, &is_binary/1) do
      errors
    else
      ["available_operator_names must contain only strings" | errors]
    end
  end

  defp validate_available_operator_names(errors, nil), do: errors

  defp validate_available_operator_names(errors, _operators),
    do: ["available_operator_names must be an array of strings" | errors]

  defp validate_allow_search_ref_fetch_span(errors, value)
       when is_boolean(value) or is_nil(value),
       do: errors

  defp validate_allow_search_ref_fetch_span(errors, _value) do
    ["allow_search_ref_fetch_span must be a boolean" | errors]
  end

  defp require_positive_integer(errors, map, key) do
    case field(map, key) do
      value when is_integer(value) and value > 0 -> errors
      _ -> ["budget.#{key} must be a positive integer" | errors]
    end
  end

  defp require_non_negative_integer(errors, map, key) do
    case field(map, key) do
      value when is_integer(value) and value >= 0 -> errors
      _ -> ["budget.#{key} must be a non-negative integer" | errors]
    end
  end

  defp require_optional_positive_integer(errors, map, key) do
    case field(map, key) do
      nil -> errors
      value when is_integer(value) and value > 0 -> errors
      _ -> ["budget.#{key} must be a positive integer when provided" | errors]
    end
  end

  defp require_non_empty_string(errors, map, key, message) do
    case field(map, key) do
      value when is_binary(value) and byte_size(value) > 0 -> errors
      _ -> [message | errors]
    end
  end

  defp valid_step?(%{"kind" => "operator", "op_name" => op_name}) when is_binary(op_name),
    do: true

  defp valid_step?(%{kind: "operator", op_name: op_name}) when is_binary(op_name), do: true

  defp valid_step?(%{"kind" => "search_ref_fetch_span", "max_refs" => max_refs})
       when is_integer(max_refs) and max_refs > 0,
       do: true

  defp valid_step?(%{kind: "search_ref_fetch_span", max_refs: max_refs})
       when is_integer(max_refs) and max_refs > 0,
       do: true

  defp valid_step?(_step), do: false

  defp select_steps(plan_request) do
    planner_hints = field(plan_request, "planner_hints") || %{}
    available_operators = MapSet.new(field(plan_request, "available_operator_names") || [])
    allow_search_ref_fetch_span = field(plan_request, "allow_search_ref_fetch_span") == true
    recovery_context = field(plan_request, "recovery_context")

    preferred_steps =
      if is_map(recovery_context) do
        recovery_steps(
          planner_hints,
          recovery_context,
          available_operators,
          allow_search_ref_fetch_span
        )
      else
        intent_steps(
          field(planner_hints, "intent"),
          available_operators,
          allow_search_ref_fetch_span
        )
      end

    preferred_steps
    |> Enum.filter(&step_allowed?(&1, available_operators, allow_search_ref_fetch_span))
    |> Enum.uniq()
  end

  defp build_summary(planner_hints, recovery_context, steps, shadow_run_id, planner_version) do
    intent = field(planner_hints, "intent") || "default"

    chosen =
      steps
      |> Enum.map(&step_name/1)
      |> Enum.join(" -> ")

    chosen_text =
      if chosen == "" do
        "no executable shadow steps"
      else
        chosen
      end

    case recovery_context do
      recovery when is_map(recovery) ->
        failed_step = field(recovery, "failed_step") || "unknown"
        failure_terminal_mode = field(recovery, "failure_terminal_mode") || "UNKNOWN"

        "BEAM shadow planner #{planner_version} recovered from #{failed_step} after #{failure_terminal_mode} with #{chosen_text} for #{intent} (shadow_run_id=#{shadow_run_id})."

      _ ->
        "BEAM shadow planner #{planner_version} selected #{chosen_text} for #{intent} (shadow_run_id=#{shadow_run_id})."
    end
  end

  defp append_summary(lines, summary) when is_binary(summary) and byte_size(summary) > 0 do
    lines ++ ["planner_summary_b64=#{Base.encode64(summary)}"]
  end

  defp append_summary(lines, _summary), do: lines

  defp append_steps(lines, steps) do
    Enum.reduce(steps, lines, fn step, acc ->
      case step do
        %{"kind" => "operator", "op_name" => op_name} ->
          acc ++ ["step=operator|#{op_name}"]

        %{"kind" => "search_ref_fetch_span", "max_refs" => max_refs} ->
          acc ++ ["step=search_ref_fetch_span|#{max_refs}"]

        _ ->
          acc
      end
    end)
  end

  defp cli_recovery_context(options) do
    failed_step =
      options
      |> Keyword.get(:recovery_failed_step)
      |> to_optional_trimmed_string()

    failure_terminal_mode =
      options
      |> Keyword.get(:recovery_failure_terminal_mode)
      |> to_optional_trimmed_string()

    if is_nil(failed_step) and is_nil(failure_terminal_mode) do
      nil
    else
      %{
        "failed_step" => failed_step || "unknown",
        "failure_terminal_mode" => failure_terminal_mode || "SOURCE_UNAVAILABLE",
        "attempted_path" => []
      }
    end
  end

  defp drop_nil_recovery_context(%{"recovery_context" => nil} = request),
    do: Map.delete(request, "recovery_context")

  defp drop_nil_recovery_context(request), do: request

  defp to_optional_trimmed_string(nil), do: nil

  defp to_optional_trimmed_string(value) do
    value
    |> to_string()
    |> String.trim()
    |> case do
      "" -> nil
      trimmed -> trimmed
    end
  end

  defp intent_steps("structured_lookup", _available_operators, _allow_search_ref_fetch_span),
    do: [operator_step("fetch_rows")]

  defp intent_steps("structured_aggregation", available_operators, _allow_search_ref_fetch_span),
    do: aggregate_or_compare_steps(available_operators)

  defp intent_steps("evidence_lookup", available_operators, allow_search_ref_fetch_span),
    do: evidence_lookup_steps(available_operators, allow_search_ref_fetch_span)

  defp intent_steps("version_review", available_operators, _allow_search_ref_fetch_span),
    do: version_review_steps(available_operators)

  defp intent_steps(
         "structured_evidence_lookup",
         available_operators,
         allow_search_ref_fetch_span
       ),
       do:
         [operator_step("fetch_rows")] ++
           evidence_lookup_steps(available_operators, allow_search_ref_fetch_span)

  defp intent_steps(
         "structured_aggregation_evidence",
         available_operators,
         allow_search_ref_fetch_span
       ),
       do:
         aggregate_or_compare_steps(available_operators) ++
           evidence_lookup_steps(available_operators, allow_search_ref_fetch_span)

  defp intent_steps(
         "structured_version_review",
         available_operators,
         _allow_search_ref_fetch_span
       ),
       do: [operator_step("fetch_rows")] ++ version_review_steps(available_operators)

  defp intent_steps(_intent, available_operators, allow_search_ref_fetch_span),
    do: fallback_steps(available_operators, allow_search_ref_fetch_span)

  defp recovery_steps(
         planner_hints,
         recovery_context,
         available_operators,
         allow_search_ref_fetch_span
       ) do
    failed_step = field(recovery_context, "failed_step")
    recommended_steps = field(planner_hints, "recommended_path") || []

    (recommended_steps ++
       intent_steps(
         field(planner_hints, "intent"),
         available_operators,
         allow_search_ref_fetch_span
       ) ++
       fallback_steps(available_operators, allow_search_ref_fetch_span))
    |> Enum.reject(&(step_name(&1) == failed_step))
  end

  defp aggregate_or_compare_steps(available_operators) do
    cond do
      MapSet.member?(available_operators, "compare") -> [operator_step("compare")]
      MapSet.member?(available_operators, "aggregate") -> [operator_step("aggregate")]
      true -> []
    end
  end

  defp evidence_lookup_steps(available_operators, allow_search_ref_fetch_span) do
    cond do
      MapSet.member?(available_operators, "lookup_evidence") ->
        [operator_step("lookup_evidence")]

      allow_search_ref_fetch_span and
        MapSet.member?(available_operators, "search") and
          MapSet.member?(available_operators, "fetch_span") ->
        [search_ref_fetch_span_step()]

      true ->
        []
    end
  end

  defp version_review_steps(available_operators) do
    steps =
      if MapSet.member?(available_operators, "list_versions") do
        [operator_step("list_versions")]
      else
        []
      end

    if MapSet.member?(available_operators, "lookup_evidence") do
      steps ++ [operator_step("lookup_evidence")]
    else
      steps
    end
  end

  defp fallback_steps(available_operators, allow_search_ref_fetch_span) do
    cond do
      MapSet.member?(available_operators, "fetch_rows") ->
        [operator_step("fetch_rows")]

      MapSet.member?(available_operators, "lookup_evidence") ->
        [operator_step("lookup_evidence")]

      MapSet.member?(available_operators, "list_versions") ->
        [operator_step("list_versions")]

      MapSet.member?(available_operators, "compare") ->
        [operator_step("compare")]

      MapSet.member?(available_operators, "aggregate") ->
        [operator_step("aggregate")]

      allow_search_ref_fetch_span and
        MapSet.member?(available_operators, "search") and
          MapSet.member?(available_operators, "fetch_span") ->
        [search_ref_fetch_span_step()]

      true ->
        []
    end
  end

  defp step_allowed?(%{"kind" => "operator", "op_name" => op_name}, available_operators, _allow),
    do: MapSet.member?(available_operators, op_name)

  defp step_allowed?(%{"kind" => "search_ref_fetch_span"}, _available_operators, allow),
    do: allow

  defp step_allowed?(_step, _available_operators, _allow), do: false

  defp step_name(%{"kind" => "operator", "op_name" => op_name}), do: op_name
  defp step_name(%{"kind" => "search_ref_fetch_span"}), do: "search_ref_fetch_span"
  defp step_name(_step), do: "unknown"

  defp operator_step(op_name) do
    %{
      "kind" => "operator",
      "op_name" => op_name,
      "params" => %{}
    }
  end

  defp search_ref_fetch_span_step do
    %{
      "kind" => "search_ref_fetch_span",
      "max_refs" => 2
    }
  end
end
