alias PecrPlanner.Contracts

{options, _args, invalid} =
  OptionParser.parse(System.argv(),
    strict: [
      schema_version: :integer,
      query: :string,
      intent: :string,
      max_operator_calls: :integer,
      max_bytes: :integer,
      max_wallclock_ms: :integer,
      max_recursion_depth: :integer,
      max_parallelism: :integer,
      allow_search_ref_fetch_span: :boolean,
      operator: :keep
    ]
  )

response =
  cond do
    invalid != [] ->
      invalid
      |> Enum.map(fn
        {key, nil} -> "invalid option: --#{key}"
        {key, value} -> "invalid option: --#{key}=#{value}"
      end)
      |> Contracts.invalid_plan_request()
      |> then(&{:error, &1})

    true ->
      options
      |> Contracts.plan_request_from_cli()
      |> PecrPlanner.shadow_plan()
  end

IO.write(Contracts.encode_cli_response(response))
