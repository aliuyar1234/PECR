pub(super) fn is_allowlisted_operator(op_name: &str) -> bool {
    matches!(
        op_name,
        "search" | "fetch_span" | "fetch_rows" | "aggregate" | "list_versions" | "diff" | "redact"
    )
}
