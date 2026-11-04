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


class EnvAdminBootstrapTests(unittest.TestCase):
    def test_bootstrap_creates_env_admin_without_printing_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_file = os.path.join(tmp, "db.json")
            with patch.object(obs_app, "DB_FILE", db_file), \
                 patch.object(obs_app, "ADMIN_EMAIL", "admin@example.test"), \
                 patch.object(obs_app, "ADMIN_PASS", "super-secret-pass"), \
                 self.assertLogs(obs_app.log, level="INFO") as logs:
                obs_app._db_init()

            db = json.loads(Path(db_file).read_text(encoding="utf-8"))

        admin = next(u for u in db["users"] if u["email"] == "admin@example.test")
        self.assertEqual(admin["role"], "admin")
        self.assertTrue(admin["active"])
        self.assertTrue(obs_app._password_matches("super-secret-pass", admin["password"]))
        joined_logs = "\n".join(logs.output)
        self.assertIn("Admin de entorno activo: admin@example.test", joined_logs)
        self.assertNotIn("super-secret-pass", joined_logs)

    def test_bootstrap_updates_existing_env_admin_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_file = os.path.join(tmp, "db.json")
            existing = {
                "users": [{
                    "id": "u1",
                    "email": "admin@example.test",
                    "password": obs_app._hash("old-pass"),
                    "role": "analyst",
                    "active": False,
                }],
                "analyses": [],
                "domains": [],
                "logs": [],
                "tokens": {},
                "report_texts": {},
            }
            Path(db_file).write_text(json.dumps(existing), encoding="utf-8")
            with patch.object(obs_app, "DB_FILE", db_file), \
                 patch.object(obs_app, "ADMIN_EMAIL", "admin@example.test"), \
                 patch.object(obs_app, "ADMIN_PASS", "new-pass"):
                obs_app._db_init()
            db = json.loads(Path(db_file).read_text(encoding="utf-8"))

        admin = db["users"][0]
        self.assertEqual(admin["role"], "admin")
        self.assertTrue(admin["active"])
        self.assertTrue(obs_app._password_matches("new-pass", admin["password"]))

    def test_env_admin_login_works_after_empty_db_bootstrap(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_file = os.path.join(tmp, "db.json")
            with patch.object(obs_app, "DB_FILE", db_file), \
                 patch.object(obs_app, "ADMIN_EMAIL", "admin@example.test"), \
                 patch.object(obs_app, "ADMIN_PASS", "cloud-pass"), \
                 patch.object(obs_app, "SECRET_KEY", "stable-secret"):
                obs_app._db_init()
                client = obs_app.app.test_client()
                response = client.post("/auth/login", json={
                    "email": "admin@example.test",
                    "password": "cloud-pass",
                })

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["role"], "admin")
        self.assertTrue(body["token"])


if __name__ == "__main__":
    unittest.main()
