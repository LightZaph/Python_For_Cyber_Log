import unittest

from analyze_logs import build_summary, load_events


class AnalyzeLogsTests(unittest.TestCase):
    def test_summary_detects_suspicious_ips(self) -> None:
        events = load_events(__import__("pathlib").Path("samples/auth.log"))
        summary = build_summary(events, threshold=3)

        self.assertEqual(summary["parsed_events"], 10)
        self.assertEqual(summary["failed_attempts"], 8)
        self.assertIn("203.0.113.10", summary["suspicious_ips"])
        self.assertIn("198.51.100.30", summary["suspicious_ips"])
        self.assertEqual(summary["suspicious_ips"]["203.0.113.10"], 4)


if __name__ == "__main__":
    unittest.main()
