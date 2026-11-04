import os
import sys
import json
import tempfile
import unittest
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from backend import app as obs_app


class DNSVizCommandTests(unittest.TestCase):
    def test_env_command_overrides_resolution(self):
        with patch.dict(obs_app.os.environ, {"DNSVIZ_CMD": "python C:\\tools\\dnsviz"}, clear=False):
            self.assertEqual(obs_app.get_dnsviz_command(), ["python", "C:\\tools\\dnsviz"])

    def test_windows_scripts_fallback_uses_python(self):
        fake_python = os.path.join("C:\\Python311", "python.exe")
        expected_script = os.path.join(os.path.dirname(fake_python), "Scripts", "dnsviz")
        with patch.dict(obs_app.os.environ, {}, clear=True), \
             patch.object(obs_app.shutil, "which", return_value=None), \
             patch.object(obs_app.sys, "executable", fake_python), \
             patch.object(obs_app.os.path, "exists", return_value=True):
            self.assertEqual(obs_app.get_dnsviz_command(), [fake_python, expected_script])


class DNSVizRemoteWorkerTests(unittest.TestCase):
    def test_gcloud_command_prefers_cmd_on_windows(self):
        def fake_which(name):
            return {
                "gcloud.cmd": r"C:\CloudSDK\bin\gcloud.cmd",
                "gcloud": None,
                "gcloud.ps1": r"C:\CloudSDK\bin\gcloud.ps1",
            }.get(name)

        with patch.object(obs_app, "GCLOUD_CMD", ""), \
             patch.object(obs_app.shutil, "which", side_effect=fake_which):
            self.assertEqual(obs_app._get_gcloud_command(), [r"C:\CloudSDK\bin\gcloud.cmd"])

    def test_remote_gcp_runner_downloads_artifacts_and_builds_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            local_dir = os.path.join(tmp, "abc123")
            remote_calls = []

            def fake_analysis_dir(aid):
                self.assertEqual(aid, "abc123")
                return local_dir

            def fake_run_gcloud(args, timeout=300):
                remote_calls.append(args)
                if args[0] == "ssh":
                    return obs_app.subprocess.CompletedProcess(
                        args=args,
                        returncode=0,
                        stdout=b"remote ok\n",
                        stderr=b"",
                    )
                if args[0] == "scp":
                    artifact = args[1].rsplit("/", 1)[-1]
                    dst = args[2]
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    if artifact == "grok.json":
                        data = {
                            "example.com.": {
                                "queries": {}
                            }
                        }
                        with open(dst, "w", encoding="utf-8") as f:
                            json.dump(data, f)
                    elif artifact == "graph.html":
                        with open(dst, "w", encoding="utf-8") as f:
                            f.write("<html></html>")
                    elif artifact == "graph.png":
                        with open(dst, "wb") as f:
                            f.write(b"\x89PNG\r\n\x1a\n")
                    elif artifact == "graph.svg":
                        with open(dst, "w", encoding="utf-8") as f:
                            f.write("<svg></svg>")
                    else:
                        with open(dst, "w", encoding="utf-8") as f:
                            f.write("")
                    return obs_app.subprocess.CompletedProcess(
                        args=args,
                        returncode=0,
                        stdout=b"",
                        stderr=b"",
                    )
                raise AssertionError(args)

            with patch.object(obs_app, "DNSVIZ_REMOTE", True), \
                 patch.object(obs_app, "_analysis_dir", side_effect=fake_analysis_dir), \
                 patch.object(obs_app, "_run_gcloud", side_effect=fake_run_gcloud):
                result = obs_app._run_dnsviz("example.com", "abc123")

            self.assertEqual(result["dnsviz"]["runner"], "gcp_ssh_worker")
            self.assertEqual(result["dnsviz"]["worker"]["vm"], "dnsviz-lab")
            self.assertTrue(os.path.exists(os.path.join(local_dir, "probe.json")))
            self.assertTrue(os.path.exists(os.path.join(local_dir, "grok.json")))
            self.assertTrue(os.path.exists(os.path.join(local_dir, "graph.html")))
            self.assertTrue(os.path.exists(os.path.join(local_dir, "graph.png")))
            self.assertTrue(os.path.exists(os.path.join(local_dir, "graph.svg")))
            self.assertTrue(os.path.exists(os.path.join(local_dir, "print.txt")))
            self.assertEqual(remote_calls[0][0], "ssh")
            self.assertEqual([call[0] for call in remote_calls].count("scp"), 6)


if __name__ == "__main__":
    unittest.main()
