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
  input.op_name == "compare"
}

dev_operator_allowed {
  input.op_name == "discover_dimensions"
}

dev_operator_allowed {
  input.op_name == "lookup_evidence"
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

support_db_operator_allowed {
  input.op_name == "compare"
}

support_db_operator_allowed {
  input.op_name == "discover_dimensions"
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

decision = {
  "allow": true,
  "cacheable": true,
  "reason": "narrow_query_dev_structured",
  "redaction": {},
  "narrowing": {
    "scope_labels": ["customer rows in safe_customer_view_public"],
    "view_ids": ["safe_customer_view_public"],
    "examples": [
      "What is the customer status and plan tier in safe_customer_view_public?",
      "Compare customer counts by plan tier in safe_customer_view_public."
    ]
  }
} {
  input.action == "narrow_query"
  input.principal_id == "dev"
  input.params.intent == "structured_lookup"
}

decision = {
  "allow": true,
  "cacheable": true,
  "reason": "narrow_query_dev_structured",
  "redaction": {},
  "narrowing": {
    "scope_labels": ["customer rows in safe_customer_view_public"],
    "view_ids": ["safe_customer_view_public"],
    "examples": [
      "What is the customer status and plan tier in safe_customer_view_public?",
      "Compare customer counts by plan tier in safe_customer_view_public."
    ]
  }
} {
  input.action == "narrow_query"
  input.principal_id == "dev"
  input.params.intent == "structured_aggregation"
}

decision = {
  "allow": true,
  "cacheable": true,
  "reason": "narrow_query_dev_structured",
  "redaction": {},
  "narrowing": {
    "scope_labels": ["customer rows in safe_customer_view_public"],
    "view_ids": ["safe_customer_view_public"],
    "examples": [
      "What is the customer status and plan tier in safe_customer_view_public?",
      "Compare customer counts by plan tier in safe_customer_view_public."
    ]
  }
} {
  input.action == "narrow_query"
  input.principal_id == "dev"
  input.params.intent == "structured_evidence_lookup"
}

decision = {
  "allow": true,
  "cacheable": true,
  "reason": "narrow_query_dev_structured",
  "redaction": {},
  "narrowing": {
    "scope_labels": ["customer rows in safe_customer_view_public"],
    "view_ids": ["safe_customer_view_public"],
    "examples": [
      "What is the customer status and plan tier in safe_customer_view_public?",
      "Compare customer counts by plan tier in safe_customer_view_public."
    ]
  }
} {
  input.action == "narrow_query"
  input.principal_id == "dev"
  input.params.intent == "structured_aggregation_evidence"
}

decision = {
  "allow": true,
  "cacheable": true,
  "reason": "narrow_query_dev_docs",
  "redaction": {},
  "narrowing": {
    "scope_labels": ["public documents under public/"],
    "source_scopes": ["public/"],
    "document_hints": ["policy documents", "versioned documents"],
    "examples": [
      "Show the source text and evidence for the support policy in public documents.",
      "What changed in the latest version of the support policy document under public/?"
    ]
  }
} {
  input.action == "narrow_query"
  input.principal_id == "dev"
  input.params.intent == "evidence_lookup"
}

decision = {
  "allow": true,
  "cacheable": true,
  "reason": "narrow_query_dev_docs",
  "redaction": {},
  "narrowing": {
    "scope_labels": ["public documents under public/"],
    "source_scopes": ["public/"],
    "document_hints": ["policy documents", "versioned documents"],
    "examples": [
      "Show the source text and evidence for the support policy in public documents.",
      "What changed in the latest version of the support policy document under public/?"
    ]
  }
} {
  input.action == "narrow_query"
  input.principal_id == "dev"
  input.params.intent == "version_review"
}

decision = {
  "allow": true,
  "cacheable": true,
  "reason": "narrow_query_dev_docs",
  "redaction": {},
  "narrowing": {
    "scope_labels": ["public documents under public/"],
    "source_scopes": ["public/"],
    "document_hints": ["policy documents", "versioned documents"],
    "examples": [
      "Show the source text and evidence for the support policy in public documents.",
      "What changed in the latest version of the support policy document under public/?"
    ]
  }
} {
  input.action == "narrow_query"
  input.principal_id == "dev"
  input.params.intent == "structured_version_review"
}

decision = {
  "allow": true,
  "cacheable": true,
  "reason": "narrow_query_support_structured",
  "redaction": {},
  "narrowing": {
    "scope_labels": [
      "customer rows in safe_customer_view_public",
      "customer rows in safe_customer_view_support"
    ],
    "view_ids": ["safe_customer_view_public", "safe_customer_view_support"],
    "examples": [
      "What is the customer status and plan tier in safe_customer_view_public?",
      "Compare customer counts by status in safe_customer_view_support."
    ]
  }
} {
  input.action == "narrow_query"
  input.principal_id == "support"
  input.params.intent == "structured_lookup"
}

decision = {
  "allow": true,
  "cacheable": true,
  "reason": "narrow_query_support_structured",
  "redaction": {},
  "narrowing": {
    "scope_labels": [
      "customer rows in safe_customer_view_public",
      "customer rows in safe_customer_view_support"
    ],
    "view_ids": ["safe_customer_view_public", "safe_customer_view_support"],
    "examples": [
      "What is the customer status and plan tier in safe_customer_view_public?",
      "Compare customer counts by status in safe_customer_view_support."
    ]
  }
} {
  input.action == "narrow_query"
  input.principal_id == "support"
  input.params.intent == "structured_aggregation"
}

decision = {
  "allow": true,
  "cacheable": true,
  "reason": "narrow_query_support_structured",
  "redaction": {},
  "narrowing": {
    "scope_labels": [
      "customer rows in safe_customer_view_public",
      "customer rows in safe_customer_view_support"
    ],
    "view_ids": ["safe_customer_view_public", "safe_customer_view_support"],
    "examples": [
      "What is the customer status and plan tier in safe_customer_view_public?",
      "Compare customer counts by status in safe_customer_view_support."
    ]
  }
} {
  input.action == "narrow_query"
  input.principal_id == "support"
  input.params.intent == "structured_evidence_lookup"
}

decision = {
  "allow": true,
  "cacheable": true,
  "reason": "narrow_query_support_structured",
  "redaction": {},
  "narrowing": {
    "scope_labels": [
      "customer rows in safe_customer_view_public",
      "customer rows in safe_customer_view_support"
    ],
    "view_ids": ["safe_customer_view_public", "safe_customer_view_support"],
    "examples": [
      "What is the customer status and plan tier in safe_customer_view_public?",
      "Compare customer counts by status in safe_customer_view_support."
    ]
  }
} {
  input.action == "narrow_query"
  input.principal_id == "support"
  input.params.intent == "structured_aggregation_evidence"
}

decision = {
  "allow": true,
  "cacheable": true,
  "reason": "narrow_query_support_docs",
  "redaction": {},
  "narrowing": {
    "scope_labels": [
      "public documents under public/",
      "support-visible documents under injection/"
    ],
    "source_scopes": ["public/", "injection/"],
    "document_hints": ["policy documents", "versioned documents"],
    "examples": [
      "Show the source text and evidence for the support policy in public documents.",
      "What changed in the latest version of the support policy document under public/?"
    ]
  }
} {
  input.action == "narrow_query"
  input.principal_id == "support"
  input.params.intent == "evidence_lookup"
}

decision = {
  "allow": true,
  "cacheable": true,
  "reason": "narrow_query_support_docs",
  "redaction": {},
  "narrowing": {
    "scope_labels": [
      "public documents under public/",
      "support-visible documents under injection/"
    ],
    "source_scopes": ["public/", "injection/"],
    "document_hints": ["policy documents", "versioned documents"],
    "examples": [
      "Show the source text and evidence for the support policy in public documents.",
      "What changed in the latest version of the support policy document under public/?"
    ]
  }
} {
  input.action == "narrow_query"
  input.principal_id == "support"
  input.params.intent == "version_review"
}

decision = {
  "allow": true,
  "cacheable": true,
  "reason": "narrow_query_support_docs",
  "redaction": {},
  "narrowing": {
    "scope_labels": [
      "public documents under public/",
      "support-visible documents under injection/"
    ],
    "source_scopes": ["public/", "injection/"],
    "document_hints": ["policy documents", "versioned documents"],
    "examples": [
      "Show the source text and evidence for the support policy in public documents.",
      "What changed in the latest version of the support policy document under public/?"
    ]
  }
} {
  input.action == "narrow_query"
  input.principal_id == "support"
  input.params.intent == "structured_version_review"
}

decision = {
  "allow": true,
  "cacheable": true,
  "reason": "narrow_query_dev_default",
  "redaction": {},
  "narrowing": {
    "scope_labels": [
      "customer rows in safe_customer_view_public",
      "public documents under public/"
    ],
    "view_ids": ["safe_customer_view_public"],
    "source_scopes": ["public/"],
    "document_hints": ["policy documents", "versioned documents"],
    "examples": [
      "What is the customer status and plan tier in safe_customer_view_public?",
      "Show the source text and evidence for the support policy in public documents."
    ]
  }
} {
  input.action == "narrow_query"
  input.principal_id == "dev"
  input.params.intent == "default"
}

decision = {
  "allow": true,
  "cacheable": true,
  "reason": "narrow_query_support_default",
  "redaction": {},
  "narrowing": {
    "scope_labels": [
      "customer rows in safe_customer_view_public",
      "customer rows in safe_customer_view_support",
      "public documents under public/",
      "support-visible documents under injection/"
    ],
    "view_ids": ["safe_customer_view_public", "safe_customer_view_support"],
    "source_scopes": ["public/", "injection/"],
    "document_hints": ["policy documents", "versioned documents"],
    "examples": [
      "What is the customer status and plan tier in safe_customer_view_support?",
      "Show the source text and evidence for the support policy in public documents."
    ]
  }
} {
  input.action == "narrow_query"
  input.principal_id == "support"
  input.params.intent == "default"
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

decision = {"allow": true, "cacheable": true, "reason": "operator_call_support_lookup_evidence", "redaction": {}} {
  input.action == "operator_call"
  input.principal_id == "support"
  input.op_name == "lookup_evidence"
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
