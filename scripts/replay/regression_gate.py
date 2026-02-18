#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from replay_lib import compute_scorecards, load_replay_bundles, reconstruct_outcome, source_unavailable_rate


SHA256_HEX_RE = re.compile(r"^[a-f0-9]{64}$")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Replay-based regression gate for persisted controller replay bundles."
    )
    parser.add_argument("--store", default="target/replay", help="Replay store root directory")
    parser.add_argument("--engine-mode", choices=["baseline", "rlm"])
    parser.add_argument("--min-quality-score", type=float, default=0.0)
    parser.add_argument("--max-source-unavailable-rate", type=float, default=1.0)
    parser.add_argument(
        "--allow-empty",
        action="store_true",
        help="Pass when there are no replay bundles (default for CI compatibility).",
    )
    args = parser.parse_args()

    bundles = load_replay_bundles(Path(args.store), engine_mode=args.engine_mode)
    if not bundles:
        if args.allow_empty:
            print("PASS: replay regression gate skipped (no replay bundles found)")
            return 0
        print("FAIL: no replay bundles found")
        return 1

    failures: list[str] = []
    for bundle in bundles:
        metadata = bundle.get("metadata", {})
        run_id = metadata.get("run_id", "<unknown>")
        bundle_hash = metadata.get("bundle_hash", "")
        if not SHA256_HEX_RE.fullmatch(str(bundle_hash)):
            failures.append(f"{run_id}: invalid bundle_hash format")

        outcome = reconstruct_outcome(bundle)
        if outcome.get("terminal_mode") != metadata.get("terminal_mode"):
            failures.append(f"{run_id}: reconstructed terminal_mode mismatch")
        if outcome.get("trace_id") != metadata.get("trace_id"):
            failures.append(f"{run_id}: reconstructed trace_id mismatch")
        if outcome.get("claim_map") != bundle.get("claim_map"):
            failures.append(f"{run_id}: reconstructed claim_map mismatch")
        if outcome.get("response_text") != bundle.get("response_text"):
            failures.append(f"{run_id}: reconstructed response_text mismatch")

        quality_score = float(metadata.get("quality_score", 0.0))
        if quality_score < args.min_quality_score:
            failures.append(
                f"{run_id}: quality_score {quality_score:.2f} < min_quality_score {args.min_quality_score:.2f}"
            )

    su_rate = source_unavailable_rate(bundles)
    if su_rate > args.max_source_unavailable_rate:
        failures.append(
            "source_unavailable_rate "
            f"{su_rate:.4f} > max_source_unavailable_rate {args.max_source_unavailable_rate:.4f}"
        )

    scorecards = compute_scorecards(bundles)
    print(json.dumps({"scorecards": scorecards}, indent=2, sort_keys=True))

    if failures:
        print("FAIL: replay regression gate detected issues:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(f"PASS: replay regression gate validated {len(bundles)} bundle(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
