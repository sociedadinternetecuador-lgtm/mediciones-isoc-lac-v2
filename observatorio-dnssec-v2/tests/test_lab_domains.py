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


class LabDomainPreparationTests(unittest.TestCase):
    def test_normalizes_urls_www_duplicates_and_classifies_domains(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_file = os.path.join(tmp, "db.json")
            with patch.object(obs_app, "DB_FILE", db_file), \
                 patch.object(obs_app, "ADMIN_EMAIL", "admin@example.test"), \
                 patch.object(obs_app, "ADMIN_PASS", "test-pass"), \
                 patch.object(obs_app, "SECRET_KEY", "stable-secret"):
                obs_app._db_init()
                client = obs_app.app.test_client()
                login = client.post("/auth/login", json={
                    "email": "admin@example.test",
                    "password": "test-pass",
                })
                token = login.get_json()["token"]
                response = client.post(
                    "/lab/domains/normalize",
                    json={
                        "text": "\n".join([
                            "www.corpece.org.ec",
                            "https://dnssec.corpece.org.ec/report",
                            "example.com",
                            "example.com",
                            "bad_domain",
                        ])
                    },
                    headers={"Authorization": f"Bearer {token}"},
                )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["summary"]["received"], 5)
        self.assertEqual(body["summary"]["valid"], 3)
        self.assertEqual(body["summary"]["duplicates"], 1)
        self.assertEqual(body["summary"]["invalid"], 1)
        self.assertEqual(body["summary"]["analysis_unique_domains"], 2)
        self.assertEqual(body["summary"]["analysis_selected"], 2)
        self.assertEqual(body["summary"]["analysis_remaining"], 0)
        self.assertEqual(body["summary"]["subdomains"], 1)
        self.assertEqual(body["summary"]["subdomains_pending_review"], 1)
        self.assertEqual(body["summary"]["by_public_suffix"]["org.ec"], 2)
        self.assertEqual(body["summary"]["by_public_suffix"]["com"], 1)
        self.assertEqual(body["summary"]["by_report_family"]["country_code"], 2)
        self.assertEqual(body["summary"]["by_report_family"]["generic"], 1)
        self.assertEqual(body["summary"]["by_country_code_root"]["ec"], 2)
        self.assertEqual(body["summary"]["by_country_code_group"]["org.ec"], 2)
        self.assertEqual(body["summary"]["by_generic_tld"]["com"], 1)
        self.assertEqual(body["items"][0]["normalized_domain"], "corpece.org.ec")
        self.assertEqual(body["items"][0]["registrable_domain"], "corpece.org.ec")
        self.assertEqual(body["items"][0]["tld_type"], "ccTLD")
        self.assertEqual(body["items"][0]["report_family"], "country_code")
        self.assertEqual(body["items"][0]["report_group"], "org.ec")
        self.assertEqual(body["items"][0]["cc_second_level"], "org")
        self.assertEqual(body["items"][0]["zone_kind"], "base_domain")
        self.assertEqual(body["items"][0]["analysis_domain"], "corpece.org.ec")
        self.assertTrue(body["items"][0]["analysis_candidate"])
        self.assertEqual(body["items"][0]["batch_number"], 1)
        self.assertEqual(body["items"][1]["zone_kind"], "subdomain_needs_review")
        self.assertEqual(body["items"][1]["analysis_domain"], "corpece.org.ec")
        self.assertEqual(body["items"][1]["analysis_recommendation"], "review_subdomain_in_shortlist")
        self.assertEqual(body["items"][2]["tld_type"], "gTLD")
        self.assertEqual(body["items"][2]["report_family"], "generic")
        self.assertEqual(body["items"][2]["report_group"], "com")
        self.assertEqual(body["items"][3]["status"], "duplicate")

    def test_country_code_groups_keep_second_level_categories(self):
        domains = [
            "isoc.org.ec",
            "universidad.edu.ec",
            "institucion.gob.ec",
            "registro.ec",
            "example.net",
        ]
        with tempfile.TemporaryDirectory() as tmp:
            db_file = os.path.join(tmp, "db.json")
            with patch.object(obs_app, "DB_FILE", db_file), \
                 patch.object(obs_app, "ADMIN_EMAIL", "admin@example.test"), \
                 patch.object(obs_app, "ADMIN_PASS", "test-pass"), \
                 patch.object(obs_app, "SECRET_KEY", "stable-secret"):
                obs_app._db_init()
                client = obs_app.app.test_client()
                login = client.post("/auth/login", json={
                    "email": "admin@example.test",
                    "password": "test-pass",
                })
                token = login.get_json()["token"]
                response = client.post(
                    "/lab/domains/normalize",
                    json={"domains": domains},
                    headers={"Authorization": f"Bearer {token}"},
                )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["summary"]["by_country_code_group"]["org.ec"], 1)
        self.assertEqual(body["summary"]["by_country_code_group"]["edu.ec"], 1)
        self.assertEqual(body["summary"]["by_country_code_group"]["gob.ec"], 1)
        self.assertEqual(body["summary"]["by_country_code_group"]["ec"], 1)
        self.assertEqual(body["summary"]["by_generic_tld"]["net"], 1)

    def test_subdomain_delegation_is_not_checked_during_large_inventory_preparation(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_file = os.path.join(tmp, "db.json")
            with patch.object(obs_app, "DB_FILE", db_file), \
                 patch.object(obs_app, "ADMIN_EMAIL", "admin@example.test"), \
                 patch.object(obs_app, "ADMIN_PASS", "test-pass"), \
                 patch.object(obs_app, "SECRET_KEY", "stable-secret"), \
                 patch.object(obs_app, "_has_ns_delegation") as delegated:
                obs_app._db_init()
                client = obs_app.app.test_client()
                login = client.post("/auth/login", json={
                    "email": "admin@example.test",
                    "password": "test-pass",
                })
                token = login.get_json()["token"]
                response = client.post(
                    "/lab/domains/normalize",
                    json={"domains": ["observatorios.corpece.org.ec"]},
                    headers={"Authorization": f"Bearer {token}"},
                )

        self.assertEqual(response.status_code, 200)
        delegated.assert_not_called()
        body = response.get_json()
        item = body["items"][0]
        self.assertEqual(item["zone_kind"], "subdomain_needs_review")
        self.assertEqual(item["analysis_domain"], "corpece.org.ec")
        self.assertEqual(item["analysis_recommendation"], "review_subdomain_in_shortlist")
        self.assertEqual(item["delegation_status"], "not_checked_in_inventory")

    def test_prepares_more_than_100_domains_as_multiple_analysis_batches(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_file = os.path.join(tmp, "db.json")
            with patch.object(obs_app, "DB_FILE", db_file), \
                 patch.object(obs_app, "ADMIN_EMAIL", "admin@example.test"), \
                 patch.object(obs_app, "ADMIN_PASS", "test-pass"), \
                 patch.object(obs_app, "SECRET_KEY", "stable-secret"):
                obs_app._db_init()
                client = obs_app.app.test_client()
                login = client.post("/auth/login", json={
                    "email": "admin@example.test",
                    "password": "test-pass",
                })
                token = login.get_json()["token"]
                response = client.post(
                    "/lab/domains/normalize",
                    json={"domains": [f"example{i}.com" for i in range(101)]},
                    headers={"Authorization": f"Bearer {token}"},
                )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["summary"]["received"], 101)
        self.assertEqual(body["summary"]["valid"], 101)
        self.assertEqual(body["summary"]["analysis_selected"], 100)
        self.assertEqual(body["summary"]["analysis_remaining"], 1)
        self.assertEqual(body["summary"]["batch_count"], 2)
        self.assertEqual(body["summary"]["batches"][0]["count"], 100)
        self.assertEqual(body["summary"]["batches"][1]["count"], 1)
        self.assertTrue(body["items"][99]["analysis_candidate"])
        self.assertFalse(body["items"][100]["analysis_candidate"])
        self.assertEqual(body["items"][100]["batch_number"], 2)

    def test_requires_authentication(self):
        client = obs_app.app.test_client()
        response = client.post("/lab/domains/normalize", json={"text": "example.com"})
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
