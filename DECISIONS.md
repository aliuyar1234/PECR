# PECR Target Repo Decisions

This log records implementation-repo decisions for `pecr`.

The SSOT spec pack and its decision log live in the sibling repo `pcdr`.

## D-0001 — Vendor upstream RLM repo pinned commit

**Decision**
- Vendored upstream `alexzhang13/rlm` at commit `76abb9c93ae314db96bae411bf4cd88a17349aad` into `vendor/rlm`.
- RLM integration is gated behind the `pecr-controller` Cargo feature `rlm` and is disabled by default.
- Runtime guard: selecting `PECR_CONTROLLER_ENGINE=rlm` requires explicit `PECR_RLM_SANDBOX_ACK=1`.

**Why**
- Satisfy SSOT T-0033 and keep optional code-execution paths off-by-default.

**SSOT references**
- SSOT decision: `pcdr/DECISIONS.md` (D-0007)
- SSOT security requirements: `pcdr/spec/06_SECURITY_AND_THREAT_MODEL.md` (Sandboxing and egress controls; RLM optional)

## D-0002 â€” Explicit module ownership and boundary map

**Decision**
- Adopt an explicit module ownership and coupling map in `README.md` and `RUNBOOK.md`.
- Treat `crates/policy` as the shared policy decision contract between OPA responses and gateway enforcement code.
- Keep controller/gateway separation as a hard architectural boundary, with `crates/boundary-check` as CI enforcement.

**Why**
- Reduce ambiguity around cross-module edits and ownership handoffs.
- Prevent accidental architectural drift where policy/data concerns leak into the wrong runtime.
- Improve incident response speed by clarifying who owns each domain when regressions occur.

**Affected areas**
- `README.md` (module boundaries and ownership table)
- `RUNBOOK.md` (coupling checklist and operational ownership map)
- `crates/policy` (shared policy decision types and redaction parsing)
