package pecr.authz

default decision := {
  "allow": false,
  "cacheable": false,
  "reason": "default_deny",
  "redaction": {}
}

decision := {"allow": true, "cacheable": true, "reason": "health", "redaction": {}} if {
  input.action == "health"
}

decision := {"allow": true, "cacheable": false, "reason": "create_session_dev", "redaction": {}} if {
  input.action == "create_session"
  input.principal_id in {"dev", "support", "guest"}
}

decision := {"allow": true, "cacheable": false, "reason": "finalize_dev", "redaction": {}} if {
  input.action == "finalize"
  input.principal_id in {"dev", "support", "guest"}
}

decision := {"allow": true, "cacheable": true, "reason": "operator_call_dev", "redaction": {}} if {
  input.action == "operator_call"
  input.principal_id == "dev"
  input.op_name in {"search", "list_versions", "fetch_span", "fetch_rows", "aggregate", "diff", "redact"}
}

decision := {"allow": true, "cacheable": true, "reason": "operator_call_support_search", "redaction": {}} if {
  input.action == "operator_call"
  input.principal_id == "support"
  input.op_name == "search"
}

decision := {"allow": true, "cacheable": true, "reason": "operator_call_support_fs", "redaction": {}} if {
  input.action == "operator_call"
  input.principal_id == "support"
  input.op_name in {"list_versions", "fetch_span", "diff"}
  input.object_id != null
  prefix := {"public/", "injection/"}[_]
  startswith(input.object_id, prefix)
}

decision := {"allow": true, "cacheable": true, "reason": "operator_call_support_db", "redaction": {}} if {
  input.action == "operator_call"
  input.principal_id == "support"
  input.op_name in {"fetch_rows", "aggregate"}
  input.view_id != null
  input.view_id in {"safe_customer_view_public", "safe_customer_view_support"}
}
