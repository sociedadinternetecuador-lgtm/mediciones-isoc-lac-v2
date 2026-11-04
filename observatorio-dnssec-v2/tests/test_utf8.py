import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from backend import app as obs_app


UTF8_SENTINEL = "Configuración crítica: acción válida"


class UTF8Tests(unittest.TestCase):
    def test_flask_json_preserves_utf8_bytes(self):
        with obs_app.app.app_context():
            response = obs_app.jsonify({"text": UTF8_SENTINEL})
            body = response.get_data()

        self.assertIn(UTF8_SENTINEL.encode("utf-8"), body)
        self.assertNotIn(b"\\u00f3", body)
        self.assertNotIn(b"\\u00ed", body)

    def test_db_save_writes_utf8_not_ascii_escapes(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_file = os.path.join(tmp, "db.json")
            with patch.object(obs_app, "DB_FILE", db_file):
                obs_app._db_save({"logs": [{"msg": UTF8_SENTINEL}]})
                raw = Path(db_file).read_bytes()

        self.assertIn(UTF8_SENTINEL.encode("utf-8"), raw)
        self.assertNotIn(b"\\u00f3", raw)
        self.assertEqual(json.loads(raw.decode("utf-8"))["logs"][0]["msg"], UTF8_SENTINEL)

    def test_public_report_no_longer_exports_json_or_csv(self):
        report_js = Path("frontend/js/report.js").read_text(encoding="utf-8")

        self.assertNotIn("application/json;charset=utf-8", report_js)
        self.assertNotIn("text/csv;charset=utf-8", report_js)
        self.assertNotIn("exportJson", report_js)
        self.assertNotIn("exportCsv", report_js)
        self.assertNotIn("decodeURIComponent", report_js)

        json_payload = json.dumps({"text": UTF8_SENTINEL}, ensure_ascii=False)
        csv_payload = "\ufeff" + f'"{UTF8_SENTINEL}"'
        pdf_text = UTF8_SENTINEL

        self.assertIn(UTF8_SENTINEL, json_payload)
        self.assertIn(UTF8_SENTINEL, csv_payload)
        self.assertEqual(pdf_text, UTF8_SENTINEL)

    def test_active_source_files_have_no_mojibake_markers(self):
        paths = [
            Path("frontend/js/report.js"),
            Path("frontend/js/admin.js"),
            Path("frontend/js/api.js"),
            Path("frontend/data/capa3-explicaciones.json"),
            Path("backend/app.py"),
        ]
        for path in paths:
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=str(path)):
                self.assertNotRegex(text, "[ÃÂâ]")


if __name__ == "__main__":
    unittest.main()
