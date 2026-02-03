package pecr.authz

default decision := {
  "allow": false,
  "cacheable": false,
  "reason": "default_deny",
  "redaction": {}
}

decision := {"allow": true, "cacheable": true, "reason": "health", "redaction": {}} {
  input.action == "health"
}

decision := {"allow": true, "cacheable": false, "reason": "create_session_dev", "redaction": {}} {
  input.action == "create_session"
  input.principal_id == "dev"
}

decision := {"allow": true, "cacheable": false, "reason": "finalize_dev", "redaction": {}} {
  input.action == "finalize"
  input.principal_id == "dev"
}

decision := {"allow": true, "cacheable": true, "reason": "operator_call_dev", "redaction": {}} {
  input.action == "operator_call"
  input.principal_id == "dev"
  input.op_name in {"search", "list_versions", "fetch_span", "fetch_rows", "aggregate", "diff"}
}
