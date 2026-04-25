import json
import os
import sys
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from harvester import SSHHarvester, IdentityMatcher, _compute_fingerprint
from visualizer import FoxVisualizer


# ── Unit tests ────────────────────────────────────────────────────────────────

class TestComputeFingerprint(unittest.TestCase):
    def test_returns_none_on_garbage(self):
        self.assertIsNone(_compute_fingerprint("notakey"))

    def test_returns_none_on_empty(self):
        self.assertIsNone(_compute_fingerprint(""))

    def test_returns_colon_separated_hex(self):
        # ed25519 public key (real format, minimal)
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBkdXQC4L0E1jWEhsYMrQwJ3BtKPlh4b6aXCkQCP5BKL test"
        fp = _compute_fingerprint(key)
        self.assertIsNotNone(fp)
        parts = fp.split(":")
        self.assertEqual(len(parts), 16)
        self.assertTrue(all(len(p) == 2 for p in parts))


class TestParseKnownHosts(unittest.TestCase):
    def _harvester_with_file(self, content):
        h = SSHHarvester(ssh_dir="/nonexistent")
        with tempfile.NamedTemporaryFile(mode="w", suffix="known_hosts", delete=False) as f:
            f.write(content)
            fname = f.name
        result = h._parse_known_hosts(fname)
        os.unlink(fname)
        return result

    def test_plain_host(self):
        hosts = self._harvester_with_file("github.com ssh-rsa AAAA\n")
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["host"], "github.com")
        self.assertFalse(hosts[0]["is_hashed"])

    def test_hashed_host(self):
        hosts = self._harvester_with_file("|1|abc123|xyz456 ssh-rsa AAAA\n")
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["host"], "HASHED_ADDR")
        self.assertTrue(hosts[0]["is_hashed"])

    def test_comments_skipped(self):
        hosts = self._harvester_with_file("# comment\ngithub.com ssh-rsa AAAA\n")
        self.assertEqual(len(hosts), 1)

    def test_empty_file(self):
        hosts = self._harvester_with_file("")
        self.assertEqual(hosts, [])


class TestParseAuthorizedKeys(unittest.TestCase):
    def _parse(self, content):
        h = SSHHarvester(ssh_dir="/nonexistent")
        with tempfile.NamedTemporaryFile(mode="w", suffix="authorized_keys", delete=False) as f:
            f.write(content)
            fname = f.name
        result = h._parse_authorized_keys(fname)
        os.unlink(fname)
        return result

    def test_comment_field_extracted(self):
        keys = self._parse("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA user@host\n")
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0]["comment"], "user@host")

    def test_comments_skipped(self):
        keys = self._parse("# this is a comment\nssh-ed25519 AAAA user@host\n")
        self.assertEqual(len(keys), 1)

    def test_source_field(self):
        keys = self._parse("ssh-ed25519 AAAA user@host\n")
        self.assertEqual(keys[0]["source"], "authorized_keys")


class TestParseSshConfig(unittest.TestCase):
    def _parse(self, content):
        h = SSHHarvester(ssh_dir="/nonexistent")
        with tempfile.NamedTemporaryFile(mode="w", suffix="config", delete=False) as f:
            f.write(content)
            fname = f.name
        result = h._parse_ssh_config(fname)
        os.unlink(fname)
        return result

    def test_basic_identity_mapping(self):
        entries = self._parse("Host myserver\n    IdentityFile ~/.ssh/id_rsa\n")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["host_pattern"], "myserver")

    def test_multiple_hosts(self):
        entries = self._parse(
            "Host server1\n    IdentityFile ~/.ssh/key1\n"
            "Host server2\n    IdentityFile ~/.ssh/key2\n"
        )
        self.assertEqual(len(entries), 2)

    def test_no_identityfile_ignored(self):
        entries = self._parse("Host myserver\n    User foo\n")
        self.assertEqual(entries, [])


class TestStaleAlerts(unittest.TestCase):
    def test_stale_alert_generated(self):
        h = SSHHarvester(stale_days=10)
        h.results["private_keys"] = [{"name": "id_rsa", "path": "/tmp/id_rsa", "age_days": 200}]
        h.results["blast_radius"] = {}
        h._generate_alerts()
        levels = [a["level"] for a in h.results["risk_alerts"]]
        self.assertIn("LOW", levels)

    def test_no_stale_alert_when_fresh(self):
        h = SSHHarvester(stale_days=180)
        h.results["private_keys"] = [{"name": "id_rsa", "path": "/tmp/id_rsa", "age_days": 5}]
        h.results["blast_radius"] = {}
        h._generate_alerts()
        self.assertEqual(h.results["risk_alerts"], [])


class TestBlastRadiusAlert(unittest.TestCase):
    def test_high_alert_above_80_percent(self):
        h = SSHHarvester()
        h.results["private_keys"] = [{"name": "id_ed25519", "path": "/tmp/id_ed25519", "age_days": 1}]
        h.results["blast_radius"] = {"id_ed25519": {"count": 30, "percentage": 100.0, "targets": []}}
        h._generate_alerts()
        highs = [a for a in h.results["risk_alerts"] if a["level"] == "HIGH"]
        self.assertEqual(len(highs), 1)


class TestIdentityMatcher(unittest.TestCase):
    def test_match_found(self):
        matcher = IdentityMatcher()
        matcher._cache["testuser"] = ["aa:bb:cc"]
        local_keys = [{"fingerprint": "aa:bb:cc", "comment": "user@host", "source": "authorized_keys"}]
        matches = matcher.match_against_local("testuser", local_keys)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["github_user"], "testuser")

    def test_no_match(self):
        matcher = IdentityMatcher()
        matcher._cache["testuser"] = ["aa:bb:cc"]
        local_keys = [{"fingerprint": "11:22:33", "comment": "other", "source": "public_keys"}]
        matches = matcher.match_against_local("testuser", local_keys)
        self.assertEqual(matches, [])


# ── Integration test ──────────────────────────────────────────────────────────

class TestFullFlow(unittest.TestCase):
    def test_harvester_result_structure(self):
        harvester = SSHHarvester()
        findings = harvester.harvest()
        for key in ("private_keys", "public_keys", "authorized_keys",
                    "known_hosts", "blast_radius", "github_matches", "risk_alerts"):
            self.assertIn(key, findings)

    def test_json_round_trip(self):
        harvester = SSHHarvester()
        findings = harvester.harvest()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "findings.json")
            self.assertTrue(harvester.save_json(path))
            with open(path) as f:
                saved = json.load(f)
            self.assertEqual(saved, findings)

    def test_visualizer_generates_html(self):
        harvester = SSHHarvester()
        harvester.harvest()
        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = os.path.join(tmpdir, "findings.json")
            html_path = os.path.join(tmpdir, "shadow_map.html")
            harvester.save_json(json_path)
            viz = FoxVisualizer(data_path=json_path, output_path=html_path)
            with mock.patch("webbrowser.open"):
                result = viz.generate()
            if result:
                self.assertTrue(os.path.exists(html_path))
                with open(html_path) as f:
                    content = f.read()
                self.assertIn("FOX-TRACE", content)
                self.assertIn("d3.js", content.lower() + "d3.js")


if __name__ == "__main__":
    unittest.main()
