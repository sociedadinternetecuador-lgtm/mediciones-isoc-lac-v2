import os
import sys
import unittest
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from backend import phase2_db


class Phase2DatabaseConfigTests(unittest.TestCase):
    def test_not_configured_schema_check_is_non_fatal(self):
        with patch.object(phase2_db, "DATABASE_URL", ""):
            status = phase2_db.check_schema()

        self.assertFalse(status["configured"])
        self.assertEqual(status["status"], "not_configured")
        self.assertIn("analysis_jobs", status["missing_tables"])

    def test_required_tables_include_core_reporting_model(self):
        required = set(phase2_db.REQUIRED_TABLES)
        for table in (
            "app_users",
            "analysis_jobs",
            "domain_snapshots",
            "dnsviz_artifacts",
            "dnssec_findings",
            "infrastructure_entities",
            "reports",
            "report_publications",
            "audit_log",
            "rate_limits",
        ):
            self.assertIn(table, required)


if __name__ == "__main__":
    unittest.main()
