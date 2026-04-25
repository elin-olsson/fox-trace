import os
import hashlib
import base64
import urllib.request
import json
import time
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
            "config_files": [],
            "active_agents": [],
            "risk_alerts": []
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
            # Look for ssh-XXXXXX/agent.XXXX patterns
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

    def harvest(self):
        """Main method to collect all SSH traces."""
        p = Path(self.ssh_dir)
        
        # Phase 2: Detect Active Agents
        self.results["active_agents"] = self._detect_agents()
        if self.results["active_agents"]:
            self.results["risk_alerts"].append({
                "level": "MEDIUM",
                "message": f"Found {len(self.results['active_agents'])} active SSH agent sockets in /tmp. These could potentially be hijacked."
            })

        if not p.exists():
            return self.results

        for item in p.iterdir():
            if item.is_file():
                age = self._get_file_age_days(item)
                
                # Detect private keys
                if "PRIVATE KEY" in item.read_text(errors='ignore')[:100]:
                    self.results["private_keys"].append({
                        "path": str(item),
                        "name": item.name,
                        "age_days": age
                    })
                    if age > 180:
                        self.results["risk_alerts"].append({
                            "level": "LOW",
                            "message": f"Private key '{item.name}' is stale ({age} days old)."
                        })
                
                # Detect public keys
                elif item.suffix == ".pub":
                    content = item.read_text(errors='ignore').strip()
                    self.results["public_keys"].append({
                        "path": str(item),
                        "name": item.name,
                        "fingerprint": self._get_fingerprint(content),
                        "comment": content.split()[-1] if len(content.split()) > 2 else "None",
                        "age_days": age
                    })

                # Specific files
                elif item.name == "authorized_keys":
                    self.results["authorized_keys"] = self._parse_authorized_keys(item)
                elif item.name == "known_hosts":
                    self.results["known_hosts"] = self._parse_known_hosts(item)
                elif item.name == "config":
                    self.results["config_files"].append(str(item))

        return self.results

    def _parse_known_hosts(self, file_path):
        hosts = []
        try:
            with open(file_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split()
                        if not parts: continue
                        host_part = parts[0]
                        is_hashed = host_part.startswith("|1|")
                        hosts.append({
                            "host": host_part if not is_hashed else "HASHED_ADDR",
                            "is_hashed": is_hashed,
                            "key_type": parts[1] if len(parts) > 1 else "Unknown"
                        })
        except Exception:
            pass
        return hosts

    def _parse_authorized_keys(self, file_path):
        keys = []
        try:
            with open(file_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        keys.append({
                            "content": line[:50] + "...",
                            "fingerprint": self._get_fingerprint(line),
                            "comment": line.split()[-1] if len(line.split()) > 2 else "None"
                        })
        except Exception:
            pass
        return keys

    def save_json(self, output_path="data/findings.json"):
        """Saves the harvested data to a JSON file."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        try:
            with open(output_path, "w") as f:
                json.dump(self.results, f, indent=4)
            return True
        except Exception as e:
            print(f"Error saving JSON: {e}")
            return False

if __name__ == "__main__":
    harvester = SSHHarvester()
    matcher = IdentityMatcher()
    
    findings = harvester.harvest()
    github_user = "elin-olsson"
    my_github_fingerprints = matcher.fetch_github_keys(github_user)
    
    print(f"--- Fox-trace Harvester Results ---")
    print(f"Found {len(findings['private_keys'])} private keys.")
    print(f"Found {len(findings['public_keys'])} public keys.")
    print(f"Found {len(findings['authorized_keys'])} entries in authorized_keys.")
    print(f"Found {len(findings['known_hosts'])} known hosts (connections).")
    print(f"Found {len(findings['active_agents'])} active SSH agents.")
    
    if findings['risk_alerts']:
        print(f"\n--- Risk Alerts ---")
        for alert in findings['risk_alerts']:
            print(f"[{alert['level']}] {alert['message']}")
    
    if my_github_fingerprints:
        print(f"\n--- Identity Matching (GitHub: {github_user}) ---")
        for entry in findings['authorized_keys']:
            if entry['fingerprint'] in my_github_fingerprints:
                print(f"[MATCH] Found your GitHub key in authorized_keys! (Comment: {entry['comment']})")
            else:
                print(f"[UNKNOWN] External key found: {entry['fingerprint']} ({entry['comment']})")
    
    if harvester.save_json():
        print(f"\n[SUCCESS] Results saved to data/findings.json")
