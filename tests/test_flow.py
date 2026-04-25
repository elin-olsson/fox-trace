import json
import os
import sys
import stat
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from harvester import SSHHarvester, IdentityMatcher, _compute_fingerprint
from visualizer import FoxVisualizer


# ── Fingerprint ───────────────────────────────────────────────────────────────

class TestComputeFingerprint(unittest.TestCase):
    def test_returns_none_on_garbage(self):
        self.assertIsNone(_compute_fingerprint("notakey"))

    def test_returns_none_on_empty(self):
        self.assertIsNone(_compute_fingerprint(""))

    def test_sha256_format(self):
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBkdXQC4L0E1jWEhsYMrQwJ3BtKPlh4b6aXCkQCP5BKL test"
        fp = _compute_fingerprint(key)
        self.assertIsNotNone(fp)
        self.assertTrue(fp.startswith("SHA256:"), f"Expected SHA256: prefix, got: {fp}")

    def test_consistent(self):
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBkdXQC4L0E1jWEhsYMrQwJ3BtKPlh4b6aXCkQCP5BKL test"
        self.assertEqual(_compute_fingerprint(key), _compute_fingerprint(key))


# ── Known hosts parser ────────────────────────────────────────────────────────

class TestParseKnownHosts(unittest.TestCase):
    def _parse(self, content):
        h = SSHHarvester(ssh_dir="/nonexistent")
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write(content)
            fname = f.name
        result = h._parse_known_hosts(Path(fname))
        os.unlink(fname)
        return result

    def test_plain_host(self):
        hosts = self._parse("github.com ssh-rsa AAAA\n")
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["host"], "github.com")
        self.assertFalse(hosts[0]["is_hashed"])

    def test_hashed_host(self):
        hosts = self._parse("|1|abc123|xyz456 ssh-rsa AAAA\n")
        self.assertEqual(hosts[0]["host"], "HASHED_ADDR")
        self.assertTrue(hosts[0]["is_hashed"])

    def test_comments_skipped(self):
        hosts = self._parse("# comment\ngithub.com ssh-rsa AAAA\n")
        self.assertEqual(len(hosts), 1)

    def test_empty_file(self):
        self.assertEqual(self._parse(""), [])


# ── Authorized keys parser ────────────────────────────────────────────────────

class TestParseAuthorizedKeys(unittest.TestCase):
    def _parse(self, content):
        h = SSHHarvester(ssh_dir="/nonexistent")
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write(content)
            fname = f.name
        result = h._parse_authorized_keys(Path(fname))
        os.unlink(fname)
        return result

    def test_comment_extracted(self):
        keys = self._parse("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA user@host\n")
        self.assertEqual(keys[0]["comment"], "user@host")

    def test_comments_line_skipped(self):
        keys = self._parse("# comment line\nssh-ed25519 AAAA user@host\n")
        self.assertEqual(len(keys), 1)

    def test_source_field(self):
        keys = self._parse("ssh-ed25519 AAAA user@host\n")
        self.assertEqual(keys[0]["source"], "authorized_keys")


# ── SSH config parser ─────────────────────────────────────────────────────────

class TestParseSshConfig(unittest.TestCase):
    def _parse(self, content):
        h = SSHHarvester(ssh_dir="/nonexistent")
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write(content)
            fname = f.name
        entries, fwd = h._parse_ssh_config(Path(fname))
        os.unlink(fname)
        return entries, fwd

    def test_basic_identity_mapping(self):
        entries, _ = self._parse("Host myserver\n    IdentityFile ~/.ssh/id_rsa\n")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["host_pattern"], "myserver")

    def test_multiple_hosts(self):
        entries, _ = self._parse(
            "Host s1\n    IdentityFile ~/.ssh/k1\n"
            "Host s2\n    IdentityFile ~/.ssh/k2\n"
        )
        self.assertEqual(len(entries), 2)

    def test_no_identityfile_ignored(self):
        entries, _ = self._parse("Host myserver\n    User foo\n")
        self.assertEqual(entries, [])

    def test_forward_agent_detected(self):
        _, fwd = self._parse("Host jumphost\n    ForwardAgent yes\n")
        self.assertIn("jumphost", fwd)

    def test_no_forward_agent(self):
        _, fwd = self._parse("Host myserver\n    User foo\n")
        self.assertEqual(fwd, [])


# ── Passphrase detection ──────────────────────────────────────────────────────

class TestPassphraseDetection(unittest.TestCase):
    def test_old_pem_encrypted(self):
        h = SSHHarvester()
        content = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,...\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
            f.write(content)
            p = Path(f.name)
        result = h._is_key_encrypted(p)
        p.unlink()
        self.assertTrue(result)

    def test_old_pem_unencrypted(self):
        h = SSHHarvester()
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK...\n-----END RSA PRIVATE KEY-----\n"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
            f.write(content)
            p = Path(f.name)
        result = h._is_key_encrypted(p)
        p.unlink()
        self.assertFalse(result)


# ── Permissions ───────────────────────────────────────────────────────────────

class TestPermissions(unittest.TestCase):
    def test_correct_permissions_detected(self):
        h = SSHHarvester()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            p = Path(f.name)
        os.chmod(p, 0o600)
        self.assertEqual(h._get_permissions(p), "600")
        p.unlink()

    def test_wrong_permissions_detected(self):
        h = SSHHarvester()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            p = Path(f.name)
        os.chmod(p, 0o644)
        self.assertNotEqual(h._get_permissions(p), "600")
        p.unlink()


# ── Stale alerts ──────────────────────────────────────────────────────────────

class TestStaleAlerts(unittest.TestCase):
    def test_stale_alert_generated(self):
        h = SSHHarvester(stale_days=10)
        h.results["private_keys"] = [{"name": "id_rsa", "path": "/tmp/id_rsa",
                                       "age_days": 200, "permissions": "600",
                                       "encrypted": True, "key_type": "RSA"}]
        h.results["blast_radius"] = {}
        h._generate_alerts()
        self.assertIn("LOW", [a["level"] for a in h.results["risk_alerts"]])

    def test_no_stale_alert_when_fresh(self):
        h = SSHHarvester(stale_days=180)
        h.results["private_keys"] = [{"name": "id_rsa", "path": "/tmp/id_rsa",
                                       "age_days": 5, "permissions": "600",
                                       "encrypted": True, "key_type": "RSA"}]
        h.results["blast_radius"] = {}
        h._generate_alerts()
        self.assertEqual(h.results["risk_alerts"], [])


# ── Passphrase alert ──────────────────────────────────────────────────────────

class TestPassphraseAlert(unittest.TestCase):
    def test_high_alert_for_unencrypted_key(self):
        h = SSHHarvester()
        h.results["private_keys"] = [{"name": "id_rsa", "path": "/tmp/id_rsa",
                                       "age_days": 1, "permissions": "600",
                                       "encrypted": False, "key_type": "RSA"}]
        h.results["blast_radius"] = {}
        h._generate_alerts()
        highs = [a for a in h.results["risk_alerts"] if a["level"] == "HIGH"]
        self.assertTrue(any("passphrase" in a["message"] for a in highs))
        self.assertTrue(any(a.get("remediation") for a in highs))

    def test_no_passphrase_alert_for_encrypted_key(self):
        h = SSHHarvester()
        h.results["private_keys"] = [{"name": "id_rsa", "path": "/tmp/id_rsa",
                                       "age_days": 1, "permissions": "600",
                                       "encrypted": True, "key_type": "RSA"}]
        h.results["blast_radius"] = {}
        h._generate_alerts()
        self.assertFalse(any("passphrase" in a["message"] for a in h.results["risk_alerts"]))


# ── Permissions alert ─────────────────────────────────────────────────────────

class TestPermissionsAlert(unittest.TestCase):
    def test_wrong_perms_generates_high_alert(self):
        h = SSHHarvester()
        h.results["private_keys"] = [{"name": "id_rsa", "path": "/tmp/id_rsa",
                                       "age_days": 1, "permissions": "644",
                                       "encrypted": True, "key_type": "RSA"}]
        h.results["blast_radius"] = {}
        h._generate_alerts()
        highs = [a for a in h.results["risk_alerts"] if a["level"] == "HIGH"]
        self.assertTrue(any("permissions" in a["message"] for a in highs))


# ── DSA alert ─────────────────────────────────────────────────────────────────

class TestDSAAlert(unittest.TestCase):
    def test_dsa_generates_high_alert(self):
        h = SSHHarvester()
        h.results["private_keys"] = [{"name": "id_dsa", "path": "/tmp/id_dsa",
                                       "age_days": 1, "permissions": "600",
                                       "encrypted": True, "key_type": "DSA"}]
        h.results["blast_radius"] = {}
        h._generate_alerts()
        highs = [a for a in h.results["risk_alerts"] if a["level"] == "HIGH"]
        self.assertTrue(any("DSA" in a["message"] for a in highs))


# ── Blast radius ──────────────────────────────────────────────────────────────

class TestBlastRadius(unittest.TestCase):
    def test_potential_when_no_config(self):
        h = SSHHarvester()
        h.results["private_keys"] = [{"name": "id_ed25519", "path": "/tmp/id_ed25519", "age_days": 1}]
        h.results["known_hosts"] = [{"host": f"host{i}"} for i in range(10)]
        h.results["config_entries"] = []
        radius = h._calculate_blast_radius()
        self.assertEqual(radius["id_ed25519"]["confidence"], "potential")

    def test_confirmed_when_config_present(self):
        h = SSHHarvester()
        h.results["private_keys"] = [{"name": "id_ed25519", "path": "/tmp/id_ed25519", "age_days": 1}]
        h.results["known_hosts"] = [{"host": "server1"}, {"host": "server2"}]
        h.results["config_entries"] = [{"host_pattern": "server1", "identity_file": "/tmp/id_ed25519"}]
        radius = h._calculate_blast_radius()
        self.assertEqual(radius["id_ed25519"]["confidence"], "confirmed")
        self.assertEqual(radius["id_ed25519"]["count"], 1)

    def test_high_alert_above_80_percent(self):
        h = SSHHarvester()
        h.results["private_keys"] = [{"name": "id_ed25519", "path": "/tmp/id_ed25519",
                                       "age_days": 1, "permissions": "600",
                                       "encrypted": True, "key_type": "ssh-ed25519"}]
        h.results["blast_radius"] = {"id_ed25519": {"count": 30, "percentage": 100.0,
                                                      "targets": [], "confidence": "potential"}}
        h._generate_alerts()
        self.assertTrue(any(a["level"] == "HIGH" for a in h.results["risk_alerts"]))


# ── Risk score ────────────────────────────────────────────────────────────────

class TestRiskScore(unittest.TestCase):
    def test_zero_when_no_keys(self):
        h = SSHHarvester()
        h.results["blast_radius"] = {}
        self.assertEqual(h._compute_risk_score(), 0)

    def test_high_score_for_unencrypted_key(self):
        h = SSHHarvester()
        h.results["private_keys"] = [{"name": "id_rsa", "encrypted": False,
                                       "permissions": "644", "key_type": "RSA", "age_days": 1}]
        h.results["blast_radius"] = {"id_rsa": {"percentage": 50}}
        score = h._compute_risk_score()
        self.assertGreater(score, 50)

    def test_capped_at_100(self):
        h = SSHHarvester()
        h.results["private_keys"] = [
            {"name": f"id_{i}", "encrypted": False, "permissions": "644",
             "key_type": "DSA", "age_days": 500}
            for i in range(5)
        ]
        h.results["blast_radius"] = {f"id_{i}": {"percentage": 100} for i in range(5)}
        self.assertEqual(h._compute_risk_score(), 100)


# ── Identity matcher ──────────────────────────────────────────────────────────

class TestIdentityMatcher(unittest.TestCase):
    def test_match_found(self):
        m = IdentityMatcher()
        m._cache["user"] = ["SHA256:abc123"]
        local = [{"fingerprint": "SHA256:abc123", "comment": "u@h", "source": "authorized_keys"}]
        matches = m.match_against_local("user", local)
        self.assertEqual(len(matches), 1)

    def test_no_match(self):
        m = IdentityMatcher()
        m._cache["user"] = ["SHA256:abc123"]
        local = [{"fingerprint": "SHA256:zzz999", "comment": "other", "source": "public_keys"}]
        self.assertEqual(m.match_against_local("user", local), [])


# ── Integration ───────────────────────────────────────────────────────────────

class TestFullFlow(unittest.TestCase):
    def test_harvester_result_structure(self):
        findings = SSHHarvester().harvest()
        for key in ("private_keys", "public_keys", "authorized_keys", "known_hosts",
                    "blast_radius", "github_matches", "risk_alerts", "risk_score",
                    "forward_agent_hosts"):
            self.assertIn(key, findings)

    def test_json_round_trip(self):
        h = SSHHarvester()
        findings = h.harvest()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "findings.json")
            self.assertTrue(h.save_json(path))
            with open(path) as f:
                saved = json.load(f)
            self.assertEqual(saved, findings)

    def test_visualizer_generates_html(self):
        h = SSHHarvester()
        h.harvest()
        with tempfile.TemporaryDirectory() as tmp:
            jp = os.path.join(tmp, "findings.json")
            hp = os.path.join(tmp, "shadow_map.html")
            h.save_json(jp)
            with mock.patch("webbrowser.open"):
                result = FoxVisualizer(data_path=jp, output_path=hp).generate()
            if result:
                with open(hp) as f:
                    content = f.read()
                self.assertIn("FOX-TRACE", content)
                self.assertIn("RISK SCORE", content)


if __name__ == "__main__":
    unittest.main()
