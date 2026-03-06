# Client Integration Guide

PECR should feel helpful before it feels restrictive. Clients should render `response_text` directly, then use `response_kind`, `claim_map`, and error guidance to shape follow-up UX.

## Happy Path

- Treat a `/v1/run` response with `terminal_mode=SUPPORTED` and no `response_kind` as a normal grounded answer.
- Use `claim_map.claims[*].evidence_unit_ids` or `evidence_snippets` when you want expandable citations, inline provenance, or audit links.

## Partial Answers

- `response_kind=partial_answer` means PECR found grounded support for part of the ask and kept the unresolved part explicit.
- Show the supported portion normally.
- Surface `claim_map.notes` as a small status message such as “Some requested details remain unresolved.”
- Do not collapse the unresolved portion into a generic error. The point is to preserve the useful part.

## Ambiguity And Narrowing

- `response_kind=ambiguous` means a short clarification would help more than a low-value guess.
- Render `claim_map.clarification_prompt.question` as the next-step prompt.
- Render `claim_map.clarification_prompt.options` as one-click chips or suggested follow-up queries when present.
- Keep the original answer text visible so users understand why PECR asked for narrowing.

## Blocked Or Unavailable States

- `response_kind=blocked` means policy prevented the requested path.
- `response_kind=source_down` means a source or dependency was unavailable.
- In either case, render `message` first, then show `what_failed` and `safe_alternative` as the actionable recovery path.
- Prefer “Try this safe next step” UX over dead-end error banners.

## Recommended UI Mapping

- `SUPPORTED` + no `response_kind`: normal grounded answer
- `partial_answer`: answer plus unresolved-details callout
- `ambiguous`: answer plus clarification prompt
- `blocked`: refusal card with safe alternative
- `source_down`: retry/degraded-state card with safe alternative

## Good Defaults

- Keep `response_text` as the primary user-visible text.
- Treat `response_kind` as presentation guidance, not as a replacement for `terminal_mode`.
- Log `trace_id` with client telemetry so replay/debug workflows stay connected end to end.
