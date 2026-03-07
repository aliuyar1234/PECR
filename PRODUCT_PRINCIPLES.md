# Product Principles

PECR should be a trustworthy, useful retrieval-and-reasoning runtime. Security, replayability, and maintainability are required, but they are not the product by themselves. The system should help as much as it safely can before it blocks.

## Core Position

- Be helpful first, constrained second, denying last.
- Be RLM-first in product direction while keeping non-RLM paths limited to shadowing, evaluation, or safe fallback.
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
- RLM is the main reasoning runtime; baseline and other planner paths exist only to de-risk rollout, benchmark behavior, or provide temporary fallback.

## Policy Philosophy

- Policy should shape access, scope, and evidence handling.
- Policy should not dominate the product experience.
- Hard deny is for real boundary violations, not ordinary query ambiguity.
- When something is blocked, the response should say:
  - what was blocked
  - why it was blocked
  - what safe alternative remains

## RLM-First Direction

PECR should become an RLM-first product that is more useful and more governable than the forked RLM project:

- RLM should own planning, replanning, clarification, batching decisions, and recovery behavior.
- long-context reasoning should strengthen evidence synthesis, cross-document comparison, and version review.
- PECR should still own policy, evidence capture, finalize, replay, health, and bounded execution.
- baseline and BEAM are not peer long-term product bets; they are transition tools unless explicitly re-scoped.
- the system should feel more useful because of RLM, not just more complicated around it.

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
- Treating baseline, BEAM, and RLM as equal long-term product directions
