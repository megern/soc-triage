import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from triage import analyze


def event(i, kind="login_failed", minute=0, user="demo"):
    return {"id": str(i), "timestamp": f"2026-01-01T00:{minute:02}:00Z", "kind": kind,
            "user": user, "source_ip": "192.0.2.1"}


class TriageTests(unittest.TestCase):
    def test_success_escalates_with_exact_evidence(self):
        result = analyze([event(i) for i in range(5)] + [event(5, "login_success", 1)])
        high = [f for f in result["findings"] if f["severity"] == "high"]
        self.assertEqual(high[0]["evidence_ids"], ["0", "1", "2", "3", "4", "5"])

    def test_old_or_other_user_failures_do_not_escalate(self):
        events = [event(i, minute=0) for i in range(4)] + [event(5, minute=8), event(6, user="other")]
        self.assertEqual(analyze(events)["findings"], [])

    def test_duplicate_ids_and_missing_timezone_rejected(self):
        with self.assertRaises(ValueError):
            analyze([event(1), event(1)])
        bad = event(2)
        bad["timestamp"] = "2026-01-01T00:00:00"
        with self.assertRaises(ValueError):
            analyze([bad])

    def test_privilege_change_is_review_not_compromise(self):
        result = analyze([event(1, "privilege_granted")])
        self.assertEqual(result["findings"][0]["severity"], "review")

    def test_cli_rejects_input_overwrite_and_symlink_alias(self):
        script = Path(__file__).resolve().with_name("triage.py")
        for alias in (False, True):
            with self.subTest(symlink_alias=alias), tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "events.jsonl"
                original = (json.dumps(event(1)) + "\n").encode()
                source.write_bytes(original)
                output = source
                if alias:
                    output = Path(directory) / "report.json"
                    output.symlink_to(source)
                result = subprocess.run(
                    [sys.executable, "-B", str(script), str(source), "--output", str(output)],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("must not overwrite", result.stderr)
                self.assertEqual(source.read_bytes(), original)
                if alias:
                    self.assertTrue(output.is_symlink())

    def test_cli_distinct_output_preserves_original_events(self):
        script = Path(__file__).resolve().with_name("triage.py")
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "events.jsonl"
            output = Path(directory) / "report.json"
            original = (json.dumps(event(1)) + "\n").encode()
            source.write_bytes(original)
            result = subprocess.run(
                [sys.executable, "-B", str(script), str(source), "--output", str(output)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(output.read_text())["event_count"], 1)
            self.assertEqual(source.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
