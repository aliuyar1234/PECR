# Operator Contract Checklist

Use this checklist when adding or modifying gateway operators.

1. Confirm contract template exists in `scripts/replay/operator_contract_templates/*.json`.
2. Ensure template defines:
   - `name`
   - `op_name`
   - representative `params`
   - `allowed_terminal_modes`
   - `required_result_paths` for non-empty result objects.
3. Start local stack (`docker compose up -d`) with local auth secret configured.
4. Run:
   - `python3 scripts/replay/run_operator_contract_tests.py --gateway-url http://127.0.0.1:8080 --local-auth-secret "$PECR_LOCAL_AUTH_SHARED_SECRET"`
5. If a template fails:
   - verify operator response shape and terminal modes,
   - update template only when contract intent changed,
   - otherwise fix operator behavior.
6. For replay/eval validation, run:
   - `python3 scripts/replay/replay_eval_cli.py --store target/replay scorecards`
   - `python3 scripts/replay/regression_gate.py --store target/replay --allow-empty`
