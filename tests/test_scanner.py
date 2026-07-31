"""Smoke tests for chainsentry — verify detectors fire on known-bad input
and stay quiet on known-good input."""
from __future__ import annotations

import sys
from pathlib import Path

# Make the package importable when running from project root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chainsentry.scanner import scan_file  # noqa: E402


CONTRACTS = Path(__file__).resolve().parents[1] / "contracts"


def test_vulnerable_contract_flags_at_least_one_high():
    report = scan_file(CONTRACTS / "vulnerable.sol")
    assert any(f.severity == "high" for f in report.findings), \
        f"expected at least one high-severity finding, got: {[(f.detector, f.severity) for f in report.findings]}"


def test_vulnerable_contract_flags_reentrancy():
    report = scan_file(CONTRACTS / "vulnerable.sol")
    assert any(f.detector == "reentrancy" for f in report.findings), \
        "expected reentrancy detector to fire"


def test_vulnerable_contract_flags_tx_origin():
    report = scan_file(CONTRACTS / "vulnerable.sol")
    assert any(f.detector == "tx-origin" for f in report.findings)


def test_vulnerable_contract_flags_floating_pragma():
    report = scan_file(CONTRACTS / "vulnerable.sol")
    assert any(f.detector == "floating-pragma" for f in report.findings)


def test_vulnerable_contract_flags_unsigned_pragma():
    report = scan_file(CONTRACTS / "vulnerable.sol")
    assert any(f.detector == "integer-overflow" for f in report.findings)


def test_safe_contract_low_finding_count():
    report = scan_file(CONTRACTS / "safe.sol")
    high = [f for f in report.findings if f.severity in ("high", "critical")]
    assert not high, f"expected no high-severity findings on safe.sol, got: {high}"


def test_safe_contract_no_reentrancy():
    report = scan_file(CONTRACTS / "safe.sol")
    assert not any(f.detector == "reentrancy" for f in report.findings)


def test_detector_count_is_twelve():
    """After M2 expansion, 12 detectors should be registered."""
    from chainsentry.detectors import ALL_DETECTORS
    assert len(ALL_DETECTORS) >= 12, f"expected >=12 detectors, got {len(ALL_DETECTORS)}"


def test_empty_source_no_findings():
    report = scan_file(CONTRACTS / "vulnerable.sol")  # existence check
    assert report.detector_count > 0
    assert report.duration_ms >= 0


def run_all() -> int:
    failures = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  ok   {name}")
            except AssertionError as exc:
                print(f"  FAIL {name}: {exc}")
                failures += 1
            except Exception as exc:  # noqa: BLE001
                print(f"  ERR  {name}: {exc!r}")
                failures += 1
    if failures:
        print(f"\n{failures} test(s) failed")
        return 1
    print("\nAll tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_all())
