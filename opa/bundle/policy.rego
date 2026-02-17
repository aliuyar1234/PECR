package pecr.authz

default decision = {
  "allow": false,
  "cacheable": false,
  "reason": "default_deny",
  "redaction": {}
}

principal_is_session_allowed {
  input.principal_id == "dev"
}

principal_is_session_allowed {
  input.principal_id == "support"
}

principal_is_session_allowed {
  input.principal_id == "guest"
}

dev_operator_allowed {
  input.op_name == "search"
}

dev_operator_allowed {
  input.op_name == "list_versions"
}

dev_operator_allowed {
  input.op_name == "fetch_span"
}

dev_operator_allowed {
  input.op_name == "fetch_rows"
}

dev_operator_allowed {
  input.op_name == "aggregate"
}

dev_operator_allowed {
  input.op_name == "diff"
}

dev_operator_allowed {
  input.op_name == "redact"
}

support_fs_operator_allowed {
  input.op_name == "list_versions"
}

support_fs_operator_allowed {
  input.op_name == "fetch_span"
}

support_fs_operator_allowed {
  input.op_name == "diff"
}

support_db_operator_allowed {
  input.op_name == "fetch_rows"
}

support_db_operator_allowed {
  input.op_name == "aggregate"
}

support_db_view_allowed {
  input.view_id == "safe_customer_view_public"
}

support_db_view_allowed {
  input.view_id == "safe_customer_view_support"
}

decision = {"allow": true, "cacheable": true, "reason": "health", "redaction": {}} {
  input.action == "health"
}

decision = {"allow": true, "cacheable": false, "reason": "create_session_dev", "redaction": {}} {
  input.action == "create_session"
  principal_is_session_allowed
}

decision = {"allow": true, "cacheable": false, "reason": "finalize_dev", "redaction": {}} {
  input.action == "finalize"
  principal_is_session_allowed
}

decision = {"allow": true, "cacheable": true, "reason": "operator_call_dev", "redaction": {}} {
  input.action == "operator_call"
  input.principal_id == "dev"
  dev_operator_allowed
}

decision = {"allow": true, "cacheable": true, "reason": "operator_call_support_search", "redaction": {}} {
  input.action == "operator_call"
  input.principal_id == "support"
  input.op_name == "search"
}

decision = {
  "allow": true,
  "cacheable": true,
  "reason": "operator_call_support_fs",
  "redaction": {
    "deny_fields": ["admin_note", "injection_note"]
  }
} {
  input.action == "operator_call"
  input.principal_id == "support"
  support_fs_operator_allowed
  input.object_id != null
  prefix := {"public/", "injection/"}[_]
  startswith(input.object_id, prefix)
}

decision = {
  "allow": true,
  "cacheable": true,
  "reason": "operator_call_support_db",
  "redaction": {
    "deny_fields": ["admin_note", "injection_note"]
  }
} {
  input.action == "operator_call"
  input.principal_id == "support"
  support_db_operator_allowed
  input.view_id != null
  support_db_view_allowed
}
