# PECR Target Repo Decisions

This log records implementation-repo decisions for `pecr`.

The SSOT spec pack and its decision log live in the sibling repo `pcdr`.

## D-0001 — Vendor upstream RLM repo pinned commit

**Decision**
- Vendored upstream `alexzhang13/rlm` at commit `37f6d0b26b9661ebb7d6f333740a354fc030e6c4` into `vendor/rlm`.
- RLM integration is gated behind the `pecr-controller` Cargo feature `rlm` and is disabled by default.
- Runtime guard: selecting `PECR_CONTROLLER_ENGINE=rlm` requires explicit `PECR_RLM_SANDBOX_ACK=1`.

**Why**
- Satisfy SSOT T-0033 and keep optional code-execution paths off-by-default.

**SSOT references**
- SSOT decision: `pcdr/DECISIONS.md` (D-0007)
- SSOT security requirements: `pcdr/spec/06_SECURITY_AND_THREAT_MODEL.md` (Sandboxing and egress controls; RLM optional)
