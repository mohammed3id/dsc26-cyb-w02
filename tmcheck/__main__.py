"""python -m tmcheck MODEL.yaml"""
import json
import sys
from dataclasses import asdict

from .core import ModelError, coverage_gaps, load_model, policy_findings, rank, validate


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python -m tmcheck MODEL.yaml", file=sys.stderr)
        return 2

    try:
        model = load_model(argv[0])
    except ModelError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    issues = validate(model)
    gaps = coverage_gaps(model)
    policy = policy_findings(model)
    ranked = rank(model)

    report = {
        "issues": [asdict(i) for i in issues],
        "gaps": [asdict(g) for g in gaps],
        "policy": [asdict(p) for p in policy],
        "ranked": [asdict(r) for r in ranked],
    }
    print(json.dumps(report, indent=2))
    return 1 if (issues or gaps or policy) else 0


if __name__ == "__main__":
    raise SystemExit(main())