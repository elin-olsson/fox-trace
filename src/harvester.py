import os
import hashlib
import base64
import urllib.request
import json
import time
import re
import argparse
from pathlib import Path


def _compute_fingerprint(key_string):
    """Compute MD5 fingerprint from a public key string."""
    try:
        parts = key_string.split()
        if len(parts) < 2:
            return None
        key_data = base64.b64decode(parts[1])
        fp_plain = hashlib.md5(key_data).hexdigest()
        return ":".join(fp_plain[i:i+2] for i in range(0, len(fp_plain), 2))
    except Exception:
        return None


class IdentityMatcher:
    def __init__(self):
        self._cache = {}

    def fetch_github_keys(self, username):
        if username in self._cache:
            return self._cache[username]
        url = f"https://api.github.com/users/{username}/keys"
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                keys_data = json.loads(response.read().decode())
                fps = [_compute_fingerprint(k["key"]) for k in keys_data]
                self._cache[username] = [fp for fp in fps if fp]
                return self._cache[username]
        except Exception as e:
            print(f"Error fetching GitHub keys for {username}: {e}")
            return []

    def match_against_local(self, username, local_keys):
        """Return local keys whose fingerprints appear in the GitHub user's key set."""
        github_fps = set(self.fetch_github_keys(username))
        return [
            {"github_user": username, "fingerprint": k["fingerprint"],
             "comment": k.get("comment", ""), "source": k.get("source", "")}
            for k in local_keys
            if k.get("fingerprint") in github_fps
        ]


class SSHHarvester:
    def __init__(self, ssh_dir=None, stale_days=180):
        self.ssh_dir = ssh_dir or os.path.expanduser("~/.ssh")
        self.stale_days = stale_days
        self.results = {
            "private_keys": [],
            "public_keys": [],
            "authorized_keys": [],
            "known_hosts": [],
            "config_entries": [],
            "active_agents": [],
            "risk_alerts": [],
            "blast_radius": {},
            "github_matches": []
        }

    def _get_file_age_days(self, file_path):
        try:
            mtime = os.path.getmtime(file_path)
            return int((time.time() - mtime) / (24 * 3600))
        except Exception:
            return 0

    def _detect_agents(self):
        agents = []
        try:
            for sock in Path("/tmp").glob("ssh-*/agent.*"):
                try:
                    st = sock.stat()
                    agents.append({
                        "path": str(sock),
                        "owner_uid": st.st_uid,
                        "permissions": oct(st.st_mode)[-3:]
                    })
                except Exception:
                    continue
        except Exception:
            pass
        return agents

    def _parse_ssh_config(self, file_path):
        entries = []
        current_host = None
        try:
            with open(file_path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    m = re.match(r"(?i)^Host\s+(.+)", line)
                    if m:
                        current_host = m.group(1)
                        continue
                    m = re.match(r"(?i)^IdentityFile\s+(.+)", line)
                    if m and current_host:
                        entries.append({
                            "host_pattern": current_host,
                            "identity_file": m.group(1).replace("~", os.path.expanduser("~"))
                        })
        except Exception:
            pass
        return entries

    def _parse_known_hosts(self, file_path):
        hosts = []
        try:
            with open(file_path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if not parts:
                        continue
                    is_hashed = parts[0].startswith("|1|")
                    hosts.append({
                        "host": "HASHED_ADDR" if is_hashed else parts[0],
                        "is_hashed": is_hashed,
                        "key_type": parts[1] if len(parts) > 1 else "Unknown"
                    })
        except Exception:
            pass
        return hosts

    def _parse_authorized_keys(self, file_path):
        keys = []
        try:
            with open(file_path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    keys.append({
                        "fingerprint": _compute_fingerprint(line),
                        "comment": parts[-1] if len(parts) > 2 else "None",
                        "source": "authorized_keys"
                    })
        except Exception:
            pass
        return keys

    def _calculate_blast_radius(self):
        radius = {}
        all_hosts = [h["host"] for h in self.results["known_hosts"]]
        for priv in self.results["private_keys"]:
            accessible = []
            for entry in self.results["config_entries"]:
                mapped = (entry["identity_file"] == priv["path"] or
                          Path(entry["identity_file"]).name == priv["name"])
                if mapped:
                    if entry["host_pattern"] == "*":
                        accessible = all_hosts
                        break
                    else:
                        accessible.append(entry["host_pattern"])
            if not accessible:
                accessible = all_hosts
            radius[priv["name"]] = {
                "count": len(accessible),
                "percentage": round((len(accessible) / len(all_hosts) * 100) if all_hosts else 0, 1),
                "targets": accessible[:10]
            }
        return radius

    def harvest(self):
        self.results["active_agents"] = self._detect_agents()
        p = Path(self.ssh_dir)
        if not p.exists():
            return self.results

        for item in p.iterdir():
            if not item.is_file():
                continue
            age = self._get_file_age_days(item)
            try:
                header = item.read_text(errors="ignore")[:100]
            except Exception:
                continue

            if "PRIVATE KEY" in header:
                self.results["private_keys"].append({
                    "path": str(item), "name": item.name, "age_days": age
                })
            elif item.suffix == ".pub":
                content = item.read_text(errors="ignore").strip()
                parts = content.split()
                self.results["public_keys"].append({
                    "path": str(item), "name": item.name,
                    "fingerprint": _compute_fingerprint(content),
                    "comment": parts[-1] if len(parts) > 2 else "None",
                    "age_days": age, "source": "public_keys"
                })
            elif item.name == "authorized_keys":
                self.results["authorized_keys"] = self._parse_authorized_keys(item)
            elif item.name == "known_hosts":
                self.results["known_hosts"] = self._parse_known_hosts(item)
            elif item.name == "config":
                self.results["config_entries"] = self._parse_ssh_config(item)

        self.results["blast_radius"] = self._calculate_blast_radius()
        self._generate_alerts()
        return self.results

    def _generate_alerts(self):
        alerts = self.results["risk_alerts"]
        if self.results["active_agents"]:
            alerts.append({
                "level": "MEDIUM",
                "message": "Active SSH agent sockets found. Potential session hijacking risk.",
                "key": None
            })
        for key_name, r in self.results["blast_radius"].items():
            if r["percentage"] > 80:
                alerts.append({
                    "level": "HIGH",
                    "message": f"Key '{key_name}' has a Blast Radius of {r['percentage']}%.",
                    "key": key_name
                })
        for priv in self.results["private_keys"]:
            if priv["age_days"] > self.stale_days:
                alerts.append({
                    "level": "LOW",
                    "message": f"Private key '{priv['name']}' is stale ({priv['age_days']} days old).",
                    "key": priv["name"]
                })

    def add_github_matches(self, username):
        matcher = IdentityMatcher()
        local_keys = self.results["public_keys"] + self.results["authorized_keys"]
        matches = matcher.match_against_local(username, local_keys)
        self.results["github_matches"] = matches
        return matches

    def save_json(self, output_path="data/findings.json"):
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(self.results, f, indent=4)
        return True


def _print_results(findings, github_user=None):
    total = sum(len(findings[k]) for k in
                ("private_keys", "public_keys", "authorized_keys", "known_hosts", "active_agents"))
    print("\n══════════════════════════════════════════════════════════════")
    print("  FOX-TRACE  —  SSH Trust & Lateral Movement Mapper")
    print("══════════════════════════════════════════════════════════════")
    print(f"  Findings    {total} artifacts identified\n")
    print(f"Found {len(findings['private_keys'])} private key(s).")
    print(f"Found {len(findings['public_keys'])} public key(s).")
    print(f"Found {len(findings['authorized_keys'])} authorized_keys entry(s).")
    print(f"Found {len(findings['known_hosts'])} known host(s).")
    print(f"Found {len(findings['active_agents'])} active SSH agent(s).")

    if findings["blast_radius"]:
        print("\n--- Blast Radius Analysis ---")
        for key, r in findings["blast_radius"].items():
            print(f"Key: {key} -> Accesses {r['count']} hosts ({r['percentage']}%)")

    if findings["risk_alerts"]:
        print("\n--- Risk Alerts ---")
        for alert in findings["risk_alerts"]:
            print(f"[{alert['level']}] {alert['message']}")

    if findings.get("github_matches"):
        print(f"\n--- Identity Matching (GitHub: {github_user}) ---")
        for m in findings["github_matches"]:
            print(f"[MATCH] Key found in {m['source']}! (Comment: {m['comment']})")

    print("══════════════════════════════════════════════════════════════")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Fox-trace — SSH Trust & Lateral Movement Mapper"
    )
    parser.add_argument("--json", metavar="FILE", default="data/findings.json",
                        help="Write findings to JSON (default: data/findings.json)")
    parser.add_argument("--html", metavar="FILE", nargs="?", const="data/shadow_map.html",
                        help="Generate interactive Shadow Map HTML")
    parser.add_argument("--github", metavar="USER",
                        help="Match local keys against a GitHub user's public keys")
    parser.add_argument("--stale", metavar="DAYS", type=int, default=180,
                        help="Flag private keys older than DAYS days (default: 180)")
    args = parser.parse_args()

    harvester = SSHHarvester(stale_days=args.stale)
    findings = harvester.harvest()

    if args.github:
        harvester.add_github_matches(args.github)

    _print_results(findings, github_user=args.github)
    harvester.save_json(args.json)
    print(f"[SUCCESS] Results saved to {args.json}")

    if args.html is not None:
        from visualizer import FoxVisualizer
        FoxVisualizer(data_path=args.json, output_path=args.html).generate()
