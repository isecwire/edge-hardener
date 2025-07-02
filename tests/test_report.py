#!/usr/bin/env python3
"""
Tests for generate_report.py v2.0
Copyright (c) 2026 isecwire GmbH. MIT License.

Run: python3 -m pytest tests/test_report.py
 or: python3 tests/test_report.py
"""

import json
import sys
import unittest
from pathlib import Path

# Add parent directory so we can import generate_report
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from generate_report import (
    build_result_row,
    generate_report,
    compute_risk_score,
    risk_label,
    analyze_categories,
    compliance_percentage,
    remediation_priority,
    compare_baselines,
    ascii_radar_chart,
    generate_text_report,
)


def _make_data(results=None, hostname="test-gw", kernel="6.1.0", arch="aarch64",
               timestamp="2026-01-15T10:00:00+00:00", version="2.0.0",
               policy=""):
    """Build a minimal JSON data dict matching edge_hardener.sh output."""
    if results is None:
        results = []
    pass_c = sum(1 for r in results if r.get("status") == "PASS")
    fail_c = sum(1 for r in results if r.get("status") == "FAIL")
    warn_c = sum(1 for r in results if r.get("status") == "WARN")
    data = {
        "hostname": hostname,
        "kernel": kernel,
        "arch": arch,
        "timestamp": timestamp,
        "version": version,
        "summary": {
            "total": len(results),
            "pass": pass_c,
            "fail": fail_c,
            "warn": warn_c,
        },
        "results": results,
    }
    if policy:
        data["policy"] = policy
    return data


class TestRiskScore(unittest.TestCase):
    """Tests for risk score computation."""

    def test_zero_checks(self):
        data = _make_data(results=[])
        self.assertEqual(compute_risk_score(data), 0)

    def test_all_pass(self):
        results = [{"check": f"C{i}", "status": "PASS", "detail": ""} for i in range(10)]
        data = _make_data(results=results)
        self.assertEqual(compute_risk_score(data), 0)

    def test_all_fail(self):
        results = [{"check": f"C{i}", "status": "FAIL", "detail": ""} for i in range(10)]
        data = _make_data(results=results)
        self.assertEqual(compute_risk_score(data), 100)

    def test_mixed(self):
        results = [
            {"check": "A", "status": "PASS", "detail": ""},
            {"check": "B", "status": "FAIL", "detail": ""},
            {"check": "C", "status": "WARN", "detail": ""},
        ]
        data = _make_data(results=results)
        score = compute_risk_score(data)
        self.assertGreater(score, 0)
        self.assertLess(score, 100)

    def test_risk_labels(self):
        self.assertEqual(risk_label(0), "Excellent")
        self.assertEqual(risk_label(10), "Excellent")
        self.assertEqual(risk_label(15), "Good")
        self.assertEqual(risk_label(30), "Moderate")
        self.assertEqual(risk_label(60), "High")
        self.assertEqual(risk_label(80), "Critical")


class TestCategoryAnalysis(unittest.TestCase):
    """Tests for category breakdown."""

    def test_empty(self):
        cats = analyze_categories([])
        self.assertEqual(len(cats), 0)

    def test_single_category(self):
        results = [
            {"check": "A", "status": "PASS", "category": "Kernel"},
            {"check": "B", "status": "FAIL", "category": "Kernel"},
        ]
        cats = analyze_categories(results)
        self.assertIn("Kernel", cats)
        self.assertEqual(cats["Kernel"]["pass"], 1)
        self.assertEqual(cats["Kernel"]["fail"], 1)
        self.assertEqual(cats["Kernel"]["total"], 2)

    def test_multiple_categories(self):
        results = [
            {"check": "A", "status": "PASS", "category": "Network"},
            {"check": "B", "status": "WARN", "category": "SSH"},
            {"check": "C", "status": "FAIL", "category": "Network"},
        ]
        cats = analyze_categories(results)
        self.assertEqual(len(cats), 2)
        self.assertEqual(cats["Network"]["total"], 2)
        self.assertEqual(cats["SSH"]["total"], 1)


class TestCompliancePercentage(unittest.TestCase):
    def test_all_pass(self):
        results = [{"check": f"C{i}", "status": "PASS", "detail": ""} for i in range(5)]
        data = _make_data(results=results)
        self.assertEqual(compliance_percentage(data), 100.0)

    def test_half_pass(self):
        results = [
            {"check": "A", "status": "PASS", "detail": ""},
            {"check": "B", "status": "FAIL", "detail": ""},
        ]
        data = _make_data(results=results)
        self.assertEqual(compliance_percentage(data), 50.0)


class TestRemediationPriority(unittest.TestCase):
    def test_sorted_fail_first(self):
        results = [
            {"check": "A", "status": "WARN", "remediation": "fix A"},
            {"check": "B", "status": "FAIL", "remediation": "fix B"},
            {"check": "C", "status": "PASS", "detail": ""},
        ]
        priority = remediation_priority(results)
        self.assertEqual(len(priority), 2)
        self.assertEqual(priority[0]["status"], "FAIL")
        self.assertEqual(priority[1]["status"], "WARN")

    def test_excludes_pass(self):
        results = [
            {"check": "A", "status": "PASS", "detail": ""},
        ]
        priority = remediation_priority(results)
        self.assertEqual(len(priority), 0)


class TestBaselineComparison(unittest.TestCase):
    def test_no_changes(self):
        results = [{"check": "A", "status": "PASS"}]
        current = _make_data(results=results)
        baseline = _make_data(results=results)
        comp = compare_baselines(current, baseline)
        self.assertEqual(len(comp["regressions"]), 0)
        self.assertEqual(len(comp["improved"]), 0)
        self.assertEqual(len(comp["new_findings"]), 0)

    def test_regression(self):
        baseline = _make_data(results=[{"check": "A", "status": "PASS"}])
        current = _make_data(results=[{"check": "A", "status": "FAIL"}])
        comp = compare_baselines(current, baseline)
        self.assertEqual(len(comp["regressions"]), 1)
        self.assertEqual(comp["regressions"][0]["check"], "A")

    def test_improvement(self):
        baseline = _make_data(results=[{"check": "A", "status": "FAIL"}])
        current = _make_data(results=[{"check": "A", "status": "PASS"}])
        comp = compare_baselines(current, baseline)
        self.assertEqual(len(comp["improved"]), 1)

    def test_new_finding(self):
        baseline = _make_data(results=[])
        current = _make_data(results=[{"check": "A", "status": "FAIL"}])
        comp = compare_baselines(current, baseline)
        self.assertEqual(len(comp["new_findings"]), 1)


class TestBuildResultRow(unittest.TestCase):
    """Tests for the build_result_row() helper."""

    def test_pass_row_contains_badge(self):
        row = build_result_row({"check": "KASLR", "status": "PASS", "detail": ""})
        self.assertIn('class="badge pass"', row)
        self.assertIn("PASS", row)
        self.assertIn("KASLR", row)

    def test_fail_row_contains_remediation(self):
        row = build_result_row({
            "check": "SSH root login",
            "status": "FAIL",
            "detail": "PermitRootLogin yes",
            "remediation": "Set PermitRootLogin no",
        })
        self.assertIn('class="badge fail"', row)
        self.assertIn("FAIL", row)
        self.assertIn("Remediation:", row)
        self.assertIn("Set PermitRootLogin no", row)
        self.assertIn("fail-rem", row)

    def test_warn_row_remediation_class(self):
        row = build_result_row({
            "check": "SMEP not detected",
            "status": "WARN",
            "detail": "CPU flag missing",
            "remediation": "Upgrade hardware",
        })
        self.assertIn('class="badge warn"', row)
        self.assertIn("Remediation:", row)
        self.assertNotIn("fail-rem", row)

    def test_row_with_cis_id(self):
        row = build_result_row({
            "check": "Test",
            "status": "PASS",
            "detail": "ok",
            "cis_id": "CIS 1.2.3",
        })
        self.assertIn("CIS 1.2.3", row)
        self.assertIn("check-cis", row)

    def test_row_with_policy_violation(self):
        row = build_result_row({
            "check": "Test",
            "status": "FAIL",
            "detail": "bad",
            "policy_violation": "Must pass per policy",
        })
        self.assertIn("policy-violation", row)
        self.assertIn("Must pass per policy", row)

    def test_row_without_detail(self):
        row = build_result_row({"check": "debugfs", "status": "PASS", "detail": ""})
        self.assertIn("debugfs", row)
        self.assertNotIn("check-detail", row)

    def test_row_without_remediation(self):
        row = build_result_row({"check": "NX bit", "status": "PASS", "detail": "ok"})
        self.assertNotIn("Remediation:", row)

    def test_html_escaping(self):
        row = build_result_row({
            "check": "Test <script>alert(1)</script>",
            "status": "FAIL",
            "detail": "value & more",
            "remediation": "fix <b>this</b>",
        })
        self.assertNotIn("<script>", row)
        self.assertIn("&lt;script&gt;", row)
        self.assertIn("&amp; more", row)
        self.assertIn("&lt;b&gt;", row)


class TestGenerateReport(unittest.TestCase):
    """Tests for the generate_report() function."""

    def test_empty_results(self):
        data = _make_data(results=[])
        report_html = generate_report(data)
        self.assertIn("<!DOCTYPE html>", report_html)
        self.assertIn("test-gw", report_html)
        self.assertIn(">0<", report_html)

    def test_html_contains_required_sections(self):
        data = _make_data(results=[
            {"check": "A", "status": "PASS", "detail": "ok", "category": "Test"},
        ])
        report_html = generate_report(data)
        self.assertIn("edge-hardener", report_html)
        self.assertIn("Security Audit Report", report_html)
        self.assertIn("Executive Summary", report_html)
        self.assertIn("Per-Category Breakdown", report_html)
        self.assertIn("Remediation Priority", report_html)
        self.assertIn("test-gw", report_html)
        self.assertIn("6.1.0", report_html)
        self.assertIn("aarch64", report_html)
        self.assertIn("Total Checks", report_html)
        self.assertIn("Passed", report_html)
        self.assertIn("Failed", report_html)
        self.assertIn("Warnings", report_html)
        self.assertIn("Failures", report_html)
        self.assertIn("isecwire GmbH", report_html)

    def test_risk_score_in_report(self):
        data = _make_data(results=[
            {"check": "A", "status": "FAIL", "detail": "bad", "category": "Test"},
        ])
        report_html = generate_report(data)
        self.assertIn("Risk", report_html)
        self.assertIn("Compliance Rate", report_html)

    def test_css_is_embedded(self):
        data = _make_data(results=[])
        report_html = generate_report(data)
        self.assertIn("<style>", report_html)
        self.assertIn("--pass:", report_html)
        self.assertIn("--fail:", report_html)
        self.assertIn("--warn:", report_html)
        self.assertNotIn('<link rel="stylesheet"', report_html)

    def test_mixed_pass_fail_warn(self):
        results = [
            {"check": "Check Pass", "status": "PASS", "detail": "good", "category": "A"},
            {"check": "Check Fail", "status": "FAIL", "detail": "bad",
             "remediation": "fix it", "category": "B"},
            {"check": "Check Warn", "status": "WARN", "detail": "meh",
             "remediation": "review", "category": "C"},
        ]
        data = _make_data(results=results)
        report_html = generate_report(data)
        self.assertIn("Check Pass", report_html)
        self.assertIn("Check Fail", report_html)
        self.assertIn("Check Warn", report_html)
        self.assertIn(">3<", report_html)
        self.assertIn('class="badge pass"', report_html)
        self.assertIn('class="badge fail"', report_html)
        self.assertIn('class="badge warn"', report_html)

    def test_results_sorted_fail_first(self):
        results = [
            {"check": "A-Pass", "status": "PASS", "detail": "", "category": "T"},
            {"check": "B-Fail", "status": "FAIL", "detail": "", "category": "T"},
            {"check": "C-Warn", "status": "WARN", "detail": "", "category": "T"},
        ]
        data = _make_data(results=results)
        report_html = generate_report(data)
        fail_pos = report_html.index("B-Fail")
        warn_pos = report_html.index("C-Warn")
        pass_pos = report_html.index("A-Pass")
        self.assertLess(fail_pos, warn_pos)
        self.assertLess(warn_pos, pass_pos)

    def test_hostname_escaping(self):
        data = _make_data(hostname="<evil>host", results=[])
        report_html = generate_report(data)
        self.assertNotIn("<evil>", report_html)
        self.assertIn("&lt;evil&gt;host", report_html)

    def test_javascript_filter_function(self):
        data = _make_data(results=[])
        report_html = generate_report(data)
        self.assertIn("<script>", report_html)
        self.assertIn("filterResults", report_html)

    def test_policy_in_report(self):
        data = _make_data(policy="Industrial Gateway", results=[])
        report_html = generate_report(data)
        self.assertIn("Industrial Gateway", report_html)

    def test_baseline_comparison_in_report(self):
        current = _make_data(results=[
            {"check": "A", "status": "FAIL", "detail": "", "category": "T"},
        ])
        baseline = _make_data(results=[
            {"check": "A", "status": "PASS", "detail": "", "category": "T"},
        ])
        report_html = generate_report(current, baseline_data=baseline)
        self.assertIn("Baseline Comparison", report_html)
        self.assertIn("Regression", report_html)

    def test_version_in_footer(self):
        data = _make_data(version="2.5.0", results=[])
        report_html = generate_report(data)
        self.assertIn("v2.5.0", report_html)

    def test_large_result_set(self):
        results = [
            {"check": f"Check-{i}", "status": ["PASS", "FAIL", "WARN"][i % 3],
             "detail": f"d{i}", "category": f"Cat-{i % 5}"}
            for i in range(100)
        ]
        data = _make_data(results=results)
        report_html = generate_report(data)
        self.assertIn("Check-0", report_html)
        self.assertIn("Check-99", report_html)
        self.assertIn(">100<", report_html)


class TestTextReport(unittest.TestCase):
    """Tests for text report generation."""

    def test_text_report_structure(self):
        results = [
            {"check": "A", "status": "PASS", "detail": "ok", "category": "Test"},
            {"check": "B", "status": "FAIL", "detail": "bad", "category": "Test",
             "remediation": "fix it", "cis_id": "CIS 1.2.3"},
        ]
        data = _make_data(results=results)
        text = generate_text_report(data)
        self.assertIn("EXECUTIVE SUMMARY", text)
        self.assertIn("Risk Score", text)
        self.assertIn("Compliance Rate", text)
        self.assertIn("REMEDIATION PRIORITY", text)
        self.assertIn("Per-Category Pass Rate", text)

    def test_ascii_radar_chart(self):
        categories = {
            "Kernel": {"pass": 8, "fail": 1, "warn": 1, "total": 10},
            "Network": {"pass": 5, "fail": 0, "warn": 0, "total": 5},
        }
        chart = ascii_radar_chart(categories)
        self.assertIn("Kernel", chart)
        self.assertIn("Network", chart)
        self.assertIn("%", chart)


if __name__ == "__main__":
    unittest.main()
