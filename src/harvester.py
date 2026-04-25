import os
import hashlib
import base64
import urllib.request
import json
import time
import re
from pathlib import Path

class IdentityMatcher:
    def __init__(self):
        self.identity_cache = {}

    def fetch_github_keys(self, username):
        """Fetches public keys for a GitHub user and returns their fingerprints."""
        if username in self.identity_cache:
            return self.identity_cache[username]
        
        url = f"https://api.github.com/users/{username}/keys"
        try:
            with urllib.request.urlopen(url) as response:
                keys_data = json.loads(response.read().decode())
                fingerprints = []
                for k in keys_data:
                    fp = self._generate_fingerprint_from_raw(k['key'])
                    if fp:
                        fingerprints.append(fp)
                self.identity_cache[username] = fingerprints
                return fingerprints
        except Exception as e:
            print(f"Error fetching GitHub keys for {username}: {e}")
            return []

    def _generate_fingerprint_from_raw(self, key_string):
        """Helper to get fingerprint from a standard public key string."""
        try:
            parts = key_string.split()
            if len(parts) < 2: return None
            key_data = base64.b64decode(parts[1])
            fp_plain = hashlib.md5(key_data).hexdigest()
            return ":".join(fp_plain[i:i+2] for i in range(0, len(fp_plain), 2))
        except Exception:
            return None

class SSHHarvester:
    def __init__(self, ssh_dir=None):
        self.ssh_dir = ssh_dir or os.path.expanduser("~/.ssh")
        self.results = {
            "private_keys": [],
            "public_keys": [],
            "authorized_keys": [],
            "known_hosts": [],
            "config_entries": [],
            "active_agents": [],
            "risk_alerts": [],
            "blast_radius": {}
        }

    def _get_fingerprint(self, key_content):
        """Generates an MD5 fingerprint for a public key."""
        try:
            parts = key_content.split()
            if len(parts) < 2:
                return None
            key_data = base64.b64decode(parts[1])
            fp_plain = hashlib.md5(key_data).hexdigest()
            return ":".join(fp_plain[i:i+2] for i in range(0, len(fp_plain), 2))
        except Exception:
            return None

    def _get_file_age_days(self, file_path):
        """Returns the age of a file in days."""
        try:
            mtime = os.path.getmtime(file_path)
            return int((time.time() - mtime) / (24 * 3600))
        except Exception:
            return 0

    def _detect_agents(self):
        """Searches for active SSH agent sockets in /tmp."""
        agents = []
        tmp_dir = Path("/tmp")
        try:
            for agent_sock in tmp_dir.glob("ssh-*/agent.*"):
                try:
                    stat_info = agent_sock.stat()
                    agents.append({
                        "path": str(agent_sock),
                        "owner_uid": stat_info.st_uid,
                        "permissions": oct(stat_info.st_mode)[-3:]
                    })
                except Exception:
                    continue
        except Exception:
            pass
        return agents

    def _parse_ssh_config(self, file_path):
        """Parses SSH config to find IdentityFile mappings."""
        entries = []
        current_host = None
        try:
            with open(file_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"): continue
                    
                    match_host = re.match(r"(?i)^Host\s+(.+)", line)
                    if match_host:
                        current_host = match_host.group(1)
                        continue
                    
                    match_id = re.match(r"(?i)^IdentityFile\s+(.+)", line)
                    if match_id and current_host:
                        entries.append({
                            "host_pattern": current_host,
                            "identity_file": match_id.group(1).replace("~", os.path.expanduser("~"))
                        })
        except Exception:
            pass
        return entries

    def _calculate_blast_radius(self):
        """Calculates how many hosts each private key can access."""
        radius = {}
        all_hosts = [h["host"] for h in self.results["known_hosts"]]
        
        for priv in self.results["private_keys"]:
            accessible = []
            # Check config mappings
            for entry in self.results["config_entries"]:
                if entry["identity_file"] == priv["path"] or Path(entry["identity_file"]).name == priv["name"]:
                    if entry["host_pattern"] == "*":
                        accessible = all_hosts
                        break
                    else:
                        accessible.append(entry["host_pattern"])
            
            # If no specific mapping, assume it's a default key for all hosts
            if not accessible:
                accessible = all_hosts
                
            radius[priv["name"]] = {
                "count": len(accessible),
                "percentage": round((len(accessible) / len(all_hosts) * 100) if all_hosts else 0, 1),
                "targets": accessible[:10] # Cap for summary
            }
        return radius

    def harvest(self):
        """Main method to collect all SSH traces."""
        p = Path(self.ssh_dir)
        self.results["active_agents"] = self._detect_agents()
        
        if not p.exists(): return self.results

        for item in p.iterdir():
            if item.is_file():
                age = self._get_file_age_days(item)
                if "PRIVATE KEY" in item.read_text(errors='ignore')[:100]:
                    self.results["private_keys"].append({"path": str(item), "name": item.name, "age_days": age})
                elif item.suffix == ".pub":
                    content = item.read_text(errors='ignore').strip()
                    self.results["public_keys"].append({
                        "path": str(item), "name": item.name, "fingerprint": self._get_fingerprint(content),
                        "comment": content.split()[-1] if len(content.split()) > 2 else "None", "age_days": age
                    })
                elif item.name == "authorized_keys":
                    self.results["authorized_keys"] = self._parse_authorized_keys(item)
                elif item.name == "known_hosts":
                    self.results["known_hosts"] = self._parse_known_hosts(item)
                elif item.name == "config":
                    self.results["config_entries"] = self._parse_ssh_config(item)

        # Post-processing
        self.results["blast_radius"] = self._calculate_blast_radius()
        
        # Risk Alerts
        if self.results["active_agents"]:
            self.results["risk_alerts"].append({"level": "MEDIUM", "message": f"Active agents found. Potential hijack risk."})
        for key, r in self.results["blast_radius"].items():
            if r["percentage"] > 80:
                self.results["risk_alerts"].append({"level": "HIGH", "message": f"Key '{key}' has a Blast Radius of {r['percentage']}%."})

        return self.results

    def _parse_known_hosts(self, file_path):
        hosts = []
        try:
            with open(file_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split()
                        if parts:
                            hosts.append({"host": parts[0] if not parts[0].startswith("|1|") else "HASHED_ADDR", "is_hashed": parts[0].startswith("|1|"), "key_type": parts[1] if len(parts) > 1 else "Unknown"})
        except Exception: pass
        return hosts

    def _parse_authorized_keys(self, file_path):
        keys = []
        try:
            with open(file_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        keys.append({"fingerprint": self._get_fingerprint(line), "comment": line.split()[-1] if len(line.split()) > 2 else "None"})
        except Exception: pass
        return keys

    def save_json(self, output_path="data/findings.json"):
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f: json.dump(self.results, f, indent=4)
        return True

if __name__ == "__main__":
    harvester = SSHHarvester()
    matcher = IdentityMatcher()
    findings = harvester.harvest()
    
    print(f"--- Fox-trace Harvester (Phase 3) ---")
    print(f"Private Keys: {len(findings['private_keys'])}")
    print(f"Known Hosts:  {len(findings['known_hosts'])}")
    
    print(f"\n--- Blast Radius Analysis ---")
    for key, r in findings["blast_radius"].items():
        print(f"Key: {key} -> Accesses {r['count']} hosts ({r['percentage']}%)")
    
    if findings['risk_alerts']:
        print(f"\n--- Risk Alerts ---")
        for alert in findings['risk_alerts']:
            print(f"[{alert['level']}] {alert['message']}")

    harvester.save_json()
