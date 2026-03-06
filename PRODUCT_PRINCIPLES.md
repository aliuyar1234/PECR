# Product Principles

PECR should be a trustworthy, useful retrieval-and-reasoning runtime. Security, replayability, and maintainability are required, but they are not the product by themselves. The system should help as much as it safely can before it blocks.

## Core Position

- Be helpful first, constrained second, denying last.
- Prefer scoped, evidence-backed partial answers over hard failure when the safe path still exists.
- Keep policy mostly invisible when the system is healthy.
- Make every downgrade or refusal explainable and actionable.
- Preserve the architecture invariants in `docs/architecture/invariants.md`.

## What Good Looks Like

- A user usually gets a useful `SUPPORTED` answer, not a generic refusal.
- If one operator path fails, the controller tries another useful path before giving up.
- If access is restricted, the system returns the safest answer it can still support.
- If a source is unavailable, the system degrades clearly instead of pretending confidence.
- RLM planning improves answer quality and recovery behavior, not just internal elegance.

## Policy Philosophy

- Policy should shape access, scope, and evidence handling.
- Policy should not dominate the product experience.
- Hard deny is for real boundary violations, not ordinary query ambiguity.
- When something is blocked, the response should say:
  - what was blocked
  - why it was blocked
  - what safe alternative remains

## RLM Direction

PECR should become a more useful version of the forked RLM project:

- better query planning for real user jobs
- stronger evidence selection and synthesis
- better fallback and retry behavior
- clearer final answers with grounded citations
- production-grade replay, contracts, health, and bounded execution

## Decision Filter

When choosing between two designs, prefer the one that:

1. increases useful-answer rate
2. keeps evidence grounding intact
3. reduces unnecessary friction or dead-end denial
4. stays simple enough to maintain
5. preserves trust boundaries and replay guarantees

## Non-Goals

- Maximizing denials as proof of safety
- Exposing raw policy machinery as the main user experience
- Shipping clever planning that is hard to debug, evaluate, or replay
