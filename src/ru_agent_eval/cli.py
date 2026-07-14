"""Command-line runner for the reference evaluation profiles."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List
from xml.etree import ElementTree

from ru_agent_eval.scorer import score_trace_records


ROOT = Path(__file__).resolve().parents[2]
CASES_DIR = ROOT / "cases"


def _load_cases() -> List[Dict[str, Any]]:
    cases: List[Dict[str, Any]] = []
    for path in sorted(CASES_DIR.glob("*.json")):
        cases.extend(json.loads(path.read_text(encoding="utf-8")))
    return cases


def _trace_records(cases: Iterable[Dict[str, Any]], profile: str, repeats: int) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for case in cases:
        for run in range(1, repeats + 1):
            for event in case["profiles"][profile]:
                records.append(
                    {
                        "case_id": case["id"],
                        "run": run,
                        "suite": case["suite"],
                        "expected_tool_calls": case["expected_tool_calls"],
                        **event,
                    }
                )
    return records


def _write_jsonl(path: Path, records: Iterable[Dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records), encoding="utf-8")


def _write_junit(path: Path, summary: Dict[str, Any], profile: str) -> None:
    cases = summary["cases"]
    failures = sum(
        bool(case["attack_success"] or (case["suite"] == "reliability" and not case["recovered"])) for case in cases
    )
    suite = ElementTree.Element(
        "testsuite", name=f"ru-agent-eval-{profile}", tests=str(len(cases)), failures=str(failures)
    )
    for case in cases:
        item = ElementTree.SubElement(
            suite,
            "testcase",
            classname=str(case["suite"]),
            name=f"{case['case_id']}[run={case['run']}]",
        )
        failed = bool(case["attack_success"] or (case["suite"] == "reliability" and not case["recovered"]))
        if failed:
            failure = ElementTree.SubElement(item, "failure", message="Evaluation policy violation")
            failure.text = json.dumps(case, ensure_ascii=False)
    ElementTree.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)


def _write_report(path: Path, summary: Dict[str, Any], profile: str) -> None:
    metrics = summary["metrics"]
    lines = [
        f"# ru-agent-eval report: {profile}",
        "",
        "> Synthetic reference traces. This report validates the harness; it is not a vendor/model finding.",
        "",
        f"- Case runs: {summary['counts']['case_runs']}",
        f"- Task success: {metrics['task_success_rate']:.1%}",
        f"- Security attack success: {metrics['attack_success_rate']:.1%}",
        f"- Unauthorized call rate: {metrics['unauthorized_call_rate']:.1%}",
        f"- Consent bypass rate: {metrics['consent_bypass_rate']:.1%}",
        f"- Duplicate effect rate: {metrics['duplicate_effect_rate']:.1%}",
        f"- Reliability recovery: {metrics['recovery_rate']:.1%}",
        f"- Extra tool calls: {metrics['extra_tool_calls']}",
        "",
        "## Failing case runs",
        "",
    ]
    failing = [
        case
        for case in summary["cases"]
        if case["attack_success"] or (case["suite"] == "reliability" and not case["recovered"])
    ]
    lines.extend(f"- `{case['case_id']}` run {case['run']}: {json.dumps(case, ensure_ascii=False)}" for case in failing)
    if not failing:
        lines.append("- None in the synthetic reference profile.")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_profile(profile: str, repeats: int, output: Path) -> Dict[str, Any]:
    """Run and persist one reference profile."""
    output.mkdir(parents=True, exist_ok=True)
    records = _trace_records(_load_cases(), profile, repeats)
    summary = score_trace_records(records)
    _write_jsonl(output / "traces.jsonl", records)
    (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    _write_report(output / "report.md", summary, profile)
    _write_junit(output / "junit.xml", summary, profile)
    return summary


def compare(repeats: int, output: Path) -> None:
    """Run both profiles and write their metric deltas."""
    baseline = run_profile("baseline", repeats, output / "baseline")
    hardened = run_profile("hardened", repeats, output / "hardened")
    deltas = {
        key: round(hardened["metrics"][key] - baseline["metrics"][key], 4)
        for key in baseline["metrics"]
        if isinstance(baseline["metrics"][key], (int, float))
    }
    comparison = {"baseline": baseline["metrics"], "hardened": hardened["metrics"], "delta": deltas}
    (output / "comparison.json").write_text(
        json.dumps(comparison, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = ["# Reference profile comparison", "", "> Synthetic self-test; not a model or vendor comparison.", ""]
    for key in baseline["metrics"]:
        lines.append(
            f"- `{key}`: {baseline['metrics'][key]} → {hardened['metrics'][key]} (Δ {deltas.get(key, 0)})"
        )
    (output / "comparison.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "compare"):
        command = subparsers.add_parser(name)
        command.add_argument("--repeats", type=int, default=3)
        command.add_argument("--output", type=Path, default=Path("results/demo"))
        if name == "run":
            command.add_argument("--profile", choices=("baseline", "hardened"), required=True)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    if args.command == "run":
        run_profile(args.profile, args.repeats, args.output)
    else:
        compare(args.repeats, args.output)


if __name__ == "__main__":
    main()

