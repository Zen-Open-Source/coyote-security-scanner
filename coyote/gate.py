"""CI-oriented gate command for Coyote.

This command is designed for automation and PR checks:
- Run a repository scan
- Compare against baseline when present
- Apply configurable fail thresholds
- Emit machine-readable outputs (JSON summary, SARIF)
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass, field

from . import __version__
from .baseline import (
    DEFAULT_BASELINE_PATH,
    DiffResult,
    baseline_exists,
    diff_scans,
    save_baseline,
)
from .config import load_config
from .deps import run_dependency_scan
from .sarif import generate_sarif, sarif_to_json
from .scanner import ScanResult, run_scan


FAIL_THRESHOLDS = ("none", "critical", "high", "medium", "low")


def _threshold_triggered(high: int, medium: int, low: int, threshold: str) -> bool:
    """Return True when counts breach the selected threshold."""
    if threshold == "none":
        return False
    if threshold == "critical":
        # Coyote severity levels are HIGH/MEDIUM/LOW. Critical-class issues map to HIGH.
        return high > 0
    if threshold == "high":
        return high > 0
    if threshold == "medium":
        return (high + medium) > 0
    if threshold == "low":
        return (high + medium + low) > 0
    return False


@dataclass
class GateEvaluation:
    """Outcome of gate evaluation."""

    passed: bool
    mode: str  # baseline_diff | absolute
    baseline_found: bool
    fail_reasons: list[str] = field(default_factory=list)

    # Scan summary
    total: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    files_scanned: int = 0
    files_skipped: int = 0

    # Diff summary (only set when mode == baseline_diff)
    new_count: int = 0
    new_high: int = 0
    new_medium: int = 0
    new_low: int = 0
    fixed_count: int = 0
    existing_count: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "passed": self.passed,
            "mode": self.mode,
            "baseline_found": self.baseline_found,
            "fail_reasons": self.fail_reasons,
            "summary": {
                "total_findings": self.total,
                "high": self.high,
                "medium": self.medium,
                "low": self.low,
                "files_scanned": self.files_scanned,
                "files_skipped": self.files_skipped,
            },
            "diff": {
                "new_count": self.new_count,
                "new_high": self.new_high,
                "new_medium": self.new_medium,
                "new_low": self.new_low,
                "fixed_count": self.fixed_count,
                "existing_count": self.existing_count,
            }
            if self.mode == "baseline_diff"
            else None,
        }


def evaluate_gate(
    scan_result: ScanResult,
    diff: DiffResult | None,
    *,
    baseline_found: bool,
    require_baseline: bool,
    fail_on: str,
    fail_on_new: str,
    fail_on_errors: bool,
    diff_error: str = "",
) -> GateEvaluation:
    """Evaluate pass/fail for a scan and optional baseline diff."""
    reasons: list[str] = []
    mode = "baseline_diff" if diff is not None else "absolute"

    if require_baseline and not baseline_found:
        reasons.append("baseline is required but was not found")

    if diff_error:
        reasons.append(f"baseline diff failed: {diff_error}")

    if fail_on_errors and scan_result.errors:
        reasons.append(f"scan produced {len(scan_result.errors)} runtime error(s)")

    if diff is not None:
        if _threshold_triggered(diff.new_high_count, diff.new_medium_count, diff.new_low_count, fail_on_new):
            reasons.append(
                "new findings breached fail threshold "
                f"({fail_on_new}): HIGH={diff.new_high_count}, "
                f"MEDIUM={diff.new_medium_count}, LOW={diff.new_low_count}"
            )
    else:
        if _threshold_triggered(scan_result.high_count, scan_result.medium_count, scan_result.low_count, fail_on):
            reasons.append(
                "findings breached fail threshold "
                f"({fail_on}): HIGH={scan_result.high_count}, "
                f"MEDIUM={scan_result.medium_count}, LOW={scan_result.low_count}"
            )

    return GateEvaluation(
        passed=not reasons,
        mode=mode,
        baseline_found=baseline_found,
        fail_reasons=reasons,
        total=scan_result.total_count,
        high=scan_result.high_count,
        medium=scan_result.medium_count,
        low=scan_result.low_count,
        files_scanned=scan_result.files_scanned,
        files_skipped=scan_result.files_skipped,
        new_count=diff.new_count if diff else 0,
        new_high=diff.new_high_count if diff else 0,
        new_medium=diff.new_medium_count if diff else 0,
        new_low=diff.new_low_count if diff else 0,
        fixed_count=diff.fixed_count if diff else 0,
        existing_count=diff.existing_count if diff else 0,
    )


def _print_human_summary(
    repo_path: str,
    scan_result: ScanResult,
    evaluation: GateEvaluation,
    fail_on: str,
    fail_on_new: str,
) -> None:
    print(f"Coyote v{__version__} gate")
    print(f"Repository: {repo_path}")
    print(
        "Scan Summary: "
        f"total={scan_result.total_count} high={scan_result.high_count} "
        f"medium={scan_result.medium_count} low={scan_result.low_count} "
        f"files_scanned={scan_result.files_scanned}"
    )

    if evaluation.mode == "baseline_diff":
        print(
            "Diff Summary: "
            f"new={evaluation.new_count} (high={evaluation.new_high} "
            f"medium={evaluation.new_medium} low={evaluation.new_low}) "
            f"fixed={evaluation.fixed_count} existing={evaluation.existing_count} "
            f"fail_on_new={fail_on_new}"
        )
    else:
        print(f"Gate Mode: absolute fail_on={fail_on}")

    if scan_result.findings_suppressed > 0:
        print(f"Suppressed Findings: {scan_result.findings_suppressed}")

    if scan_result.errors:
        print(f"Scan Errors: {len(scan_result.errors)}")
        for err in scan_result.errors:
            print(f"  - {err}")

    status = "PASS" if evaluation.passed else "FAIL"
    print(f"Gate Result: {status}")
    if evaluation.fail_reasons:
        for reason in evaluation.fail_reasons:
            print(f"  - {reason}")


def _write_summary_output(path: str, payload: dict[str, object]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def _merge_scan_results(primary: ScanResult, secondary: ScanResult) -> ScanResult:
    """Merge a secondary ScanResult into the primary result."""
    primary.findings.extend(secondary.findings)
    primary.files_scanned += secondary.files_scanned
    primary.files_skipped += secondary.files_skipped
    primary.errors.extend(secondary.errors)
    primary.findings_suppressed += secondary.findings_suppressed
    return primary


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Coyote CI gate (scan + baseline diff + fail thresholds)",
    )
    parser.add_argument(
        "--repo",
        default=".",
        help="Repository path to scan (default: current directory).",
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Config file for scan defaults (default: config.yaml).",
    )
    parser.add_argument(
        "--baseline-path",
        default=DEFAULT_BASELINE_PATH,
        help=f"Path to baseline file (default: {DEFAULT_BASELINE_PATH}).",
    )
    parser.add_argument(
        "--require-baseline",
        action="store_true",
        help="Fail when baseline file is missing.",
    )
    parser.add_argument(
        "--save-baseline",
        action="store_true",
        help="Save current findings as baseline after evaluation.",
    )
    parser.add_argument(
        "--fail-on",
        choices=FAIL_THRESHOLDS,
        default="high",
        help="Absolute-mode fail threshold when baseline is not used (default: high).",
    )
    parser.add_argument(
        "--fail-on-new",
        choices=FAIL_THRESHOLDS,
        default="high",
        help="Baseline-diff fail threshold for NEW findings (default: high).",
    )
    parser.add_argument(
        "--fail-on-errors",
        action="store_true",
        help="Fail if scan runtime errors occur.",
    )
    parser.add_argument(
        "--entropy",
        action="store_true",
        help="Enable entropy-based secret detection.",
    )
    parser.add_argument(
        "--entropy-threshold",
        type=float,
        default=4.5,
        help="Entropy threshold (default: 4.5).",
    )
    parser.add_argument(
        "--deps",
        action="store_true",
        help="Enable dependency vulnerability scanning (requirements/lockfiles).",
    )
    parser.add_argument(
        "--deps-advisory-db",
        metavar="FILE",
        help="Use local advisory JSON file instead of querying OSV API.",
    )
    parser.add_argument(
        "--deps-timeout",
        type=int,
        default=20,
        help="OSV API timeout in seconds for dependency scan (default: 20).",
    )
    parser.add_argument(
        "--deps-batch-size",
        type=int,
        default=100,
        help="OSV batch size for dependency scan (default: 100).",
    )
    parser.add_argument(
        "--deps-skip-dev",
        action="store_true",
        help="Skip development dependencies when lockfiles mark them.",
    )
    parser.add_argument(
        "--shield",
        action="store_true",
        help="Validate shield.md structure against Shield v0 checks.",
    )
    parser.add_argument(
        "--require-shield",
        action="store_true",
        help="Fail when shield.md is missing (implies --shield).",
    )
    parser.add_argument(
        "--ignore-file",
        help="Custom suppression file (default: .coyote-ignore in repo root).",
    )
    parser.add_argument(
        "--no-ignore",
        action="store_true",
        help="Disable suppression and report all findings.",
    )
    parser.add_argument(
        "--sarif",
        nargs="?",
        const="-",
        metavar="FILE",
        help="Output SARIF to stdout (-) or to FILE.",
    )
    parser.add_argument(
        "--sarif-output",
        metavar="FILE",
        help="Write SARIF output to FILE.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print gate summary as JSON to stdout.",
    )
    parser.add_argument(
        "--output",
        help="Write gate summary JSON to FILE.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    config = load_config(args.config)
    repo_path = os.path.abspath(args.repo)

    scan_result = run_scan(
        repo_path=repo_path,
        exclude_paths=config.scan.exclude_paths,
        exclude_extensions=config.scan.exclude_extensions,
        max_file_size=config.max_file_size_bytes,
        enable_entropy=args.entropy,
        entropy_threshold=args.entropy_threshold,
        ignore_file=args.ignore_file,
        no_ignore=args.no_ignore,
        enable_shield_scan=(args.shield or args.require_shield),
        require_shield=args.require_shield,
    )

    if args.deps:
        deps_result = run_dependency_scan(
            repo_path=repo_path,
            include_dev_dependencies=(not args.deps_skip_dev),
            advisory_db_path=args.deps_advisory_db,
            advisory_provider=None,
            osv_timeout_seconds=args.deps_timeout,
            osv_batch_size=args.deps_batch_size,
            ignore_file=args.ignore_file,
            no_ignore=args.no_ignore,
        )
        scan_result = _merge_scan_results(scan_result, deps_result)

    diff: DiffResult | None = None
    diff_error = ""
    baseline_found = baseline_exists(args.baseline_path)

    if baseline_found:
        try:
            diff = diff_scans(scan_result, args.baseline_path, current_commit="")
        except Exception as exc:  # keep gate deterministic even with bad baseline file
            diff = None
            diff_error = str(exc)

    evaluation = evaluate_gate(
        scan_result,
        diff,
        baseline_found=baseline_found,
        require_baseline=args.require_baseline,
        fail_on=args.fail_on,
        fail_on_new=args.fail_on_new,
        fail_on_errors=args.fail_on_errors,
        diff_error=diff_error,
    )

    sarif_output_path = args.sarif_output or args.sarif
    if sarif_output_path:
        sarif_doc = generate_sarif(scan_result)
        sarif_json = sarif_to_json(sarif_doc)
        if sarif_output_path == "-":
            print(sarif_json)
        else:
            os.makedirs(os.path.dirname(sarif_output_path) or ".", exist_ok=True)
            with open(sarif_output_path, "w", encoding="utf-8") as handle:
                handle.write(sarif_json)

    summary_payload = {
        "scanner": f"Coyote v{__version__}",
        "repo_path": repo_path,
        "evaluation": evaluation.to_dict(),
    }

    if args.output:
        _write_summary_output(args.output, summary_payload)

    if args.save_baseline:
        save_baseline(scan_result, args.baseline_path, commit_hash="")

    if args.json:
        print(json.dumps(summary_payload, indent=2))
    else:
        _print_human_summary(
            repo_path=repo_path,
            scan_result=scan_result,
            evaluation=evaluation,
            fail_on=args.fail_on,
            fail_on_new=args.fail_on_new,
        )

    return 0 if evaluation.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
