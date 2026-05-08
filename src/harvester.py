import os
import re
import hashlib
import base64
import struct
import urllib.request
import json
import time
import argparse
from pathlib import Path

__version__ = "1.3.0"

_REPO_ROOT = Path(__file__).parent.parent
_DEFAULT_JSON = str(_REPO_ROOT / "data" / "findings.json")
_DEFAULT_HTML = str(_REPO_ROOT / "data" / "shadow_map.html")
_DEFAULT_MULTI_JSON = str(_REPO_ROOT / "data" / "multi_findings.json")
_DEFAULT_MULTI_HTML = str(_REPO_ROOT / "data" / "multi_shadow_map.html")


def _get_rsa_key_bits(pub_content):
    """Return RSA modulus size in bits from a public key string, or None."""
    try:
        parts = pub_content.strip().split()
        if len(parts) < 2 or parts[0] != "ssh-rsa":
            return None
        raw = base64.b64decode(parts[1])
        offset = 0
        def read_field():
            nonlocal offset
            (length,) = struct.unpack(">I", raw[offset:offset + 4])
            offset += 4
            value = raw[offset:offset + length]
            offset += length
            return value
        read_field()   # key type ("ssh-rsa")
        read_field()   # public exponent (e)
        modulus = read_field()
        # strip leading zero sign byte if present
        if modulus and modulus[0] == 0:
            modulus = modulus[1:]
        return len(modulus) * 8
    except Exception:
        return None


def _compute_fingerprint(key_string):
    """Compute SHA256 fingerprint matching ssh-keygen -lf output."""
    try:
        parts = key_string.split()
        if len(parts) < 2:
            return None
        key_data = base64.b64decode(parts[1])
        digest = hashlib.sha256(key_data).digest()
        return "SHA256:" + base64.b64encode(digest).rstrip(b"=").decode()
    except Exception:
        return None


class IdentityMatcher:
    def __init__(self):
        self._cache = {}

    def fetch_github_keys(self, username):
        if username in self._cache:
            return self._cache[username]
        try:
            url = f"https://api.github.com/users/{username}/keys"
            with urllib.request.urlopen(url, timeout=10) as r:
                data = json.loads(r.read().decode())
                fps = [_compute_fingerprint(k["key"]) for k in data]
                self._cache[username] = [fp for fp in fps if fp]
                return self._cache[username]
        except Exception as e:
            print(f"  Error fetching GitHub keys for {username}: {e}")
            return []

    def match_against_local(self, username, local_keys):
        github_fps = set(self.fetch_github_keys(username))
        return [
            {"github_user": username, "fingerprint": k["fingerprint"],
             "comment": k.get("comment", ""), "source": k.get("source", "")}
            for k in local_keys
            if k.get("fingerprint") in github_fps
        ]


class SSHHarvester:

    _KEY_MARKERS = {
        "BEGIN RSA PRIVATE KEY":     "RSA",
        "BEGIN EC PRIVATE KEY":      "ECDSA",
        "BEGIN DSA PRIVATE KEY":     "DSA",
        "BEGIN OPENSSH PRIVATE KEY": "OpenSSH",
    }

    def __init__(self, ssh_dir=None, stale_days=180):
        self.ssh_dir = Path(ssh_dir or os.path.expanduser("~/.ssh"))
        self.stale_days = stale_days
        self.results = {
            "private_keys": [],
            "public_keys": [],
            "authorized_keys": [],
            "known_hosts": [],
            "config_entries": [],
            "forward_agent_hosts": [],
            "active_agents": [],
            "dir_permissions": None,
            "risk_score": 0,
            "risk_alerts": [],
            "blast_radius": {},
            "github_matches": [],
        }

    # ── Low-level helpers ─────────────────────────────────────────────────────

    def _get_file_age_days(self, path):
        try:
            return int((time.time() - os.path.getmtime(path)) / 86400)
        except Exception:
            return 0

    def _get_permissions(self, path):
        try:
            return oct(os.stat(path).st_mode)[-3:]
        except Exception:
            return "???"

    def _detect_key_type(self, content):
        for marker, ktype in self._KEY_MARKERS.items():
            if marker in content:
                return ktype
        return "Unknown"

    def _is_key_encrypted(self, path):
        """Return True if the private key is passphrase-protected."""
        try:
            content = path.read_text(errors="ignore")
            # Old PEM format
            if "Proc-Type: 4,ENCRYPTED" in content or "DEK-Info:" in content:
                return True
            # New OpenSSH format — check cipher field in binary header
            if "BEGIN OPENSSH PRIVATE KEY" in content:
                b64 = re.sub(r"-----.+?-----|[ \t\n\r]", "", content)
                raw = base64.b64decode(b64 + "==")
                # "openssh-key-v1\0" magic = 15 bytes
                offset = 15
                if len(raw) > offset + 4:
                    clen = int.from_bytes(raw[offset:offset + 4], "big")
                    if len(raw) >= offset + 4 + clen:
                        cipher = raw[offset + 4:offset + 4 + clen].decode("ascii", errors="replace")
                        return cipher != "none"
            return False
        except Exception:
            return False

    # ── Parsers ───────────────────────────────────────────────────────────────

    def _detect_agents(self):
        agents = []
        try:
            for sock in Path("/tmp").glob("ssh-*/agent.*"):
                try:
                    st = sock.stat()
                    agents.append({
                        "path": str(sock),
                        "owner_uid": st.st_uid,
                        "permissions": oct(st.st_mode)[-3:],
                    })
                except Exception:
                    continue
        except Exception:
            pass
        return agents

    def _parse_ssh_config(self, path):
        entries = []
        forward_hosts = []
        current_host = None
        forward_agent = False
        try:
            for line in path.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"(?i)^Host\s+(.+)", line)
                if m:
                    if current_host and forward_agent:
                        forward_hosts.append(current_host)
                    current_host = m.group(1)
                    forward_agent = False
                    continue
                m = re.match(r"(?i)^IdentityFile\s+(.+)", line)
                if m and current_host:
                    entries.append({
                        "host_pattern": current_host,
                        "identity_file": m.group(1).replace("~", str(Path.home())),
                    })
                if re.match(r"(?i)^ForwardAgent\s+yes\b", line):
                    forward_agent = True
            if current_host and forward_agent:
                forward_hosts.append(current_host)
        except Exception:
            pass
        return entries, forward_hosts

    def _parse_known_hosts(self, path):
        hosts = []
        try:
            for line in path.read_text().splitlines():
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
                    "key_type": parts[1] if len(parts) > 1 else "Unknown",
                })
        except Exception:
            pass
        return hosts

    def _parse_authorized_keys(self, path):
        keys = []
        try:
            for line in path.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                keys.append({
                    "fingerprint": _compute_fingerprint(line),
                    "comment": parts[-1] if len(parts) > 2 else "None",
                    "source": "authorized_keys",
                })
        except Exception:
            pass
        return keys

    # ── Analysis ──────────────────────────────────────────────────────────────

    def _calculate_blast_radius(self):
        radius = {}
        all_hosts = [h["host"] for h in self.results["known_hosts"]]
        if not all_hosts:
            return radius

        # Build config-confirmed mappings
        config_map = {}
        for entry in self.results["config_entries"]:
            key_name = Path(entry["identity_file"]).name
            config_map.setdefault(key_name, [])
            if entry["host_pattern"] == "*":
                config_map[key_name] = list(all_hosts)
            else:
                config_map[key_name].append(entry["host_pattern"])

        for priv in self.results["private_keys"]:
            name = priv["name"]
            if name in config_map:
                accessible = config_map[name]
                confidence = "confirmed"
            else:
                accessible = list(all_hosts)
                confidence = "potential"
            radius[name] = {
                "count": len(accessible),
                "percentage": round(len(accessible) / len(all_hosts) * 100, 1),
                "targets": accessible[:10],
                "confidence": confidence,
            }
        return radius

    def _generate_alerts(self):
        alerts = self.results["risk_alerts"]

        if self.results["dir_permissions"] not in ("700", None):
            alerts.append({
                "level": "HIGH", "key": None,
                "message": f"~/.ssh directory permissions are {self.results['dir_permissions']} — should be 700.",
                "remediation": "Run: chmod 700 ~/.ssh",
            })

        if self.results["active_agents"]:
            alerts.append({
                "level": "MEDIUM", "key": None,
                "message": "Active SSH agent sockets found. Potential session hijacking risk.",
                "remediation": "Kill stale agents: ssh-add -D && pkill ssh-agent",
            })

        for host in self.results["forward_agent_hosts"]:
            alerts.append({
                "level": "MEDIUM", "key": None,
                "message": f"ForwardAgent enabled for '{host}' — your agent keys are exposed to that server.",
                "remediation": f"Remove 'ForwardAgent yes' for '{host}' in ~/.ssh/config. Use ProxyJump instead.",
            })

        for priv in self.results["private_keys"]:
            name = priv["name"]

            if priv.get("permissions") not in ("600", "400"):
                alerts.append({
                    "level": "HIGH", "key": name,
                    "message": f"Key '{name}' has permissions {priv.get('permissions', '???')} — should be 600.",
                    "remediation": f"Run: chmod 600 ~/.ssh/{name}",
                })

            if not priv.get("encrypted"):
                alerts.append({
                    "level": "HIGH", "key": name,
                    "message": f"Key '{name}' has no passphrase — usable immediately if stolen.",
                    "remediation": f"Add a passphrase: ssh-keygen -p -f ~/.ssh/{name}",
                })

            if priv.get("key_type") == "DSA":
                alerts.append({
                    "level": "HIGH", "key": name,
                    "message": f"Key '{name}' is DSA — deprecated, fixed 1024-bit, cryptographically broken.",
                    "remediation": "Generate a new key: ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519. Update authorized_keys on all servers, then delete the DSA key.",
                })

            bits = priv.get("key_bits")
            if priv.get("key_type") == "RSA" and bits is not None:
                if bits < 2048:
                    alerts.append({
                        "level": "HIGH", "key": name,
                        "message": f"Key '{name}' is RSA {bits}-bit — below minimum of 2048, cryptographically weak.",
                        "remediation": "Generate a new key: ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519. Update authorized_keys on all servers, then delete the weak key.",
                    })
                elif bits < 3072:
                    alerts.append({
                        "level": "MEDIUM", "key": name,
                        "message": f"Key '{name}' is RSA {bits}-bit — below NIST recommendation of 3072 bits.",
                        "remediation": f"Consider rotating to a stronger key: ssh-keygen -t ed25519 or ssh-keygen -t rsa -b 4096 -f ~/.ssh/{name}",
                    })

            if priv["age_days"] > self.stale_days:
                alerts.append({
                    "level": "LOW", "key": name,
                    "message": f"Key '{name}' is stale ({priv['age_days']} days old).",
                    "remediation": f"Review whether '{name}' is still in use. Rotate with: ssh-keygen -t ed25519. Remove old key from all authorized_keys.",
                })

            r = self.results["blast_radius"].get(name, {})
            if r.get("percentage", 0) > 80:
                conf_note = "" if r["confidence"] == "confirmed" else " (potential — no SSH config mapping)"
                alerts.append({
                    "level": "HIGH", "key": name,
                    "message": f"Key '{name}' blast radius {r['percentage']}% — {r['count']} hosts{conf_note}.",
                    "remediation": "Use per-host keys in ~/.ssh/config (IdentityFile). Audit and remove this key from authorized_keys on servers where it is no longer needed.",
                })

    def _compute_risk_score(self):
        """Aggregate 0–100 risk score for this system."""
        score = 0
        dir_perm = self.results["dir_permissions"]
        if dir_perm and dir_perm != "700":
            score += 10
        if self.results["active_agents"]:
            score += 10
        score += len(self.results["forward_agent_hosts"]) * 10

        for priv in self.results["private_keys"]:
            if not priv.get("encrypted"):
                score += 40
            if priv.get("permissions") not in ("600", "400"):
                score += 20
            if priv.get("key_type") == "DSA":
                score += 15
            bits = priv.get("key_bits")
            if priv.get("key_type") == "RSA" and bits is not None:
                if bits < 2048:
                    score += 20
                elif bits < 3072:
                    score += 10
            if priv["age_days"] > self.stale_days:
                score += 5
            r = self.results["blast_radius"].get(priv["name"], {})
            score += r.get("percentage", 0) * 0.2

        return min(100, round(score))

    def _build_attack_narrative(self):
        """Return a plain-language description of the highest-risk attack path."""
        if not self.results["private_keys"]:
            return None

        def risk_weight(k):
            s = 0
            if not k.get("encrypted"):      s += 40
            if k.get("permissions") not in ("600", "400"): s += 20
            if k.get("key_type") == "DSA":  s += 15
            if k["age_days"] > self.stale_days: s += 5
            r = self.results["blast_radius"].get(k["name"], {})
            s += r.get("percentage", 0) * 0.3
            return s

        worst = max(self.results["private_keys"], key=risk_weight)
        r = self.results["blast_radius"].get(worst["name"], {})

        enc = ("no passphrase — usable immediately if stolen"
               if not worst.get("encrypted")
               else "passphrase-protected")
        perm = worst.get("permissions", "???")
        perm_note = "(INSECURE)" if perm not in ("600", "400") else "(OK)"
        conf = ("confirmed via SSH config"
                if r.get("confidence") == "confirmed"
                else "potential — no SSH config mapping found")

        lines = [
            f"Key:          {worst['name']} ({worst.get('key_type', 'Unknown')})",
            f"Passphrase:   {enc}",
            f"Permissions:  {perm} {perm_note}",
            f"Age:          {worst['age_days']} days",
            f"Blast Radius: {r.get('count', 0)} hosts ({r.get('percentage', 0)}%) — {conf}",
        ]
        if r.get("targets"):
            visible = [h for h in r["targets"] if h != "HASHED_ADDR"]
            if visible:
                lines.append(f"Example targets: {', '.join(visible[:5])}")

        return "\n  ".join(lines)

    # ── Main harvest ──────────────────────────────────────────────────────────

    def harvest(self):
        self.results["active_agents"] = self._detect_agents()

        if not self.ssh_dir.exists():
            return self.results

        self.results["dir_permissions"] = self._get_permissions(self.ssh_dir)
        pub_by_stem = {}

        for item in self.ssh_dir.iterdir():
            if not item.is_file():
                continue
            age = self._get_file_age_days(item)
            try:
                header = item.read_text(errors="ignore")[:200]
            except Exception:
                continue

            if any(m in header for m in self._KEY_MARKERS):
                self.results["private_keys"].append({
                    "path": str(item),
                    "name": item.name,
                    "age_days": age,
                    "permissions": self._get_permissions(item),
                    "encrypted": self._is_key_encrypted(item),
                    "key_type": self._detect_key_type(header),
                })
            elif item.suffix == ".pub":
                content = item.read_text(errors="ignore").strip()
                parts = content.split()
                fp = _compute_fingerprint(content)
                key_type_from_pub = parts[0] if parts else "Unknown"
                key_bits = _get_rsa_key_bits(content)
                pub_by_stem[item.stem] = {"key_type": key_type_from_pub, "bits": key_bits}
                self.results["public_keys"].append({
                    "path": str(item),
                    "name": item.name,
                    "fingerprint": fp,
                    "key_type": key_type_from_pub,
                    "key_bits": key_bits,
                    "comment": parts[-1] if len(parts) > 2 else "None",
                    "age_days": age,
                    "source": "public_keys",
                })
            elif item.name == "authorized_keys":
                self.results["authorized_keys"] = self._parse_authorized_keys(item)
            elif item.name == "known_hosts":
                self.results["known_hosts"] = self._parse_known_hosts(item)
            elif item.name == "config":
                entries, fwd = self._parse_ssh_config(item)
                self.results["config_entries"] = entries
                self.results["forward_agent_hosts"] = fwd

        # Enrich private key type and bits using corresponding .pub
        for priv in self.results["private_keys"]:
            stem = Path(priv["name"]).stem
            if stem in pub_by_stem:
                pub_info = pub_by_stem[stem]
                if priv["key_type"] == "OpenSSH":
                    priv["key_type"] = pub_info["key_type"]
                priv["key_bits"] = pub_info["bits"]

        self.results["blast_radius"] = self._calculate_blast_radius()
        self._generate_alerts()
        self.results["risk_score"] = self._compute_risk_score()
        return self.results

    def add_github_matches(self, username):
        matcher = IdentityMatcher()
        local_keys = self.results["public_keys"] + self.results["authorized_keys"]
        self.results["github_matches"] = matcher.match_against_local(username, local_keys)
        return self.results["github_matches"]

    def save_json(self, output_path="data/findings.json"):
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(self.results, f, indent=4)
        return True


def _risk_bar(score):
    filled = round(score / 5)
    bar = "█" * filled + "░" * (20 - filled)
    label = "LOW" if score < 30 else "MEDIUM" if score < 60 else "HIGH"
    return f"{bar}  {score}/100  [{label}]"


def _print_results(findings, github_user=None):
    total = sum(len(findings[k]) for k in
                ("private_keys", "public_keys", "authorized_keys", "known_hosts", "active_agents"))

    print("\n══════════════════════════════════════════════════════════════")
    print("  FOX-TRACE  —  SSH Trust & Lateral Movement Mapper")
    print("══════════════════════════════════════════════════════════════")
    score = findings.get("risk_score", 0)
    print(f"  Risk Score  {_risk_bar(score)}")
    print(f"  Findings    {total} artifacts identified\n")

    print(f"Found {len(findings['private_keys'])} private key(s).")
    print(f"Found {len(findings['public_keys'])} public key(s).")
    print(f"Found {len(findings['authorized_keys'])} authorized_keys entry(s).")
    print(f"Found {len(findings['known_hosts'])} known host(s).")
    print(f"Found {len(findings['active_agents'])} active SSH agent(s).")
    if findings["dir_permissions"]:
        ok = findings["dir_permissions"] == "700"
        print(f"~/.ssh permissions: {findings['dir_permissions']} ({'OK' if ok else 'WARN — should be 700'})")

    if findings["private_keys"]:
        print("\n--- Private Keys ---")
        for k in findings["private_keys"]:
            enc = "encrypted" if k.get("encrypted") else "NO PASSPHRASE"
            print(f"  {k['name']:20} {k.get('key_type', '?'):12} perm:{k.get('permissions', '?')}  {enc}  age:{k['age_days']}d")

    if findings["blast_radius"]:
        print("\n--- Blast Radius Analysis ---")
        for key, r in findings["blast_radius"].items():
            conf = "" if r["confidence"] == "confirmed" else " [potential]"
            print(f"  {key} → {r['count']} hosts ({r['percentage']}%){conf}")

    if findings["risk_alerts"]:
        print("\n--- Risk Alerts & Remediations ---")
        for alert in findings["risk_alerts"]:
            print(f"  [{alert['level']:6}] {alert['message']}")
            if alert.get("remediation"):
                print(f"           → Fix: {alert['remediation']}")

    if findings.get("forward_agent_hosts"):
        print("\n--- ForwardAgent ---")
        for h in findings["forward_agent_hosts"]:
            print(f"  ForwardAgent enabled for: {h}")

    if findings.get("github_matches"):
        print(f"\n--- Identity Matching (GitHub: {github_user}) ---")
        for m in findings["github_matches"]:
            print(f"  [MATCH] Key in {m['source']} — comment: {m['comment']}")

    # Attack narrative — the unique part
    harvester = SSHHarvester.__new__(SSHHarvester)
    harvester.results = findings
    harvester.stale_days = 180
    narrative = harvester._build_attack_narrative()
    if narrative:
        print("\n──────────────────────────────────────────────────────────────")
        print("  MOST CRITICAL ATTACK PATH")
        print("──────────────────────────────────────────────────────────────")
        print(f"  {narrative}")

    print("══════════════════════════════════════════════════════════════")


class TrustGraphAnalyzer:
    """Build a directed SSH trust graph from multi-host findings and detect cycles."""

    def build_graph(self, multi_findings: dict) -> dict:
        """
        Returns adjacency dict: {label: set_of_reachable_labels}.
        Edge A→B exists when any blast_radius target of host A matches
        a known hostname associated with host B.
        """
        labels = list(multi_findings.keys())
        graph = {label: set() for label in labels}

        # Map every hostname/IP we know about for each label
        label_hostnames: dict[str, set] = {}
        for label, findings in multi_findings.items():
            names: set = {label}
            for kh in findings.get("known_hosts", []):
                names.add(kh["host"])
            label_hostnames[label] = names

        for src_label, findings in multi_findings.items():
            all_targets: set = set()
            for br in findings.get("blast_radius", {}).values():
                all_targets.update(br.get("targets", []))

            for dst_label in labels:
                if dst_label == src_label:
                    continue
                if all_targets & label_hostnames[dst_label]:
                    graph[src_label].add(dst_label)

        return graph

    def find_cycles(self, graph: dict) -> list:
        """Find all simple cycles using DFS. Returns list of cycle paths."""
        cycles: list = []
        seen_sets: list = []

        def dfs(start, node, path, visited):
            for neighbor in sorted(graph.get(node, set())):
                if neighbor == start and len(path) >= 2:
                    key = frozenset(path)
                    if key not in seen_sets:
                        seen_sets.append(key)
                        cycles.append(path + [start])
                elif neighbor not in visited:
                    visited.add(neighbor)
                    dfs(start, neighbor, path + [neighbor], visited)
                    visited.discard(neighbor)

        for node in sorted(graph):
            dfs(node, node, [node], {node})

        return cycles

    def generate_alerts(self, cycles: list) -> list:
        return [
            {
                "level": "CRITICAL",
                "key": "circular_trust",
                "message": f"Circular trust detected: {' → '.join(cycle)}",
                "remediation": (
                    "Review authorized_keys and SSH configs on each host in the chain. "
                    "Remove keys that enable unintended access."
                ),
            }
            for cycle in cycles
        ]


def _parse_targets_file(path: str) -> list:
    """Parse a targets file into [(label, ssh_dir_path)] pairs."""
    targets = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                label, ssh_path = line.split(":", 1)
                label, ssh_path = label.strip(), ssh_path.strip()
            else:
                ssh_path = line
                p = Path(line)
                label = p.parent.name if p.name == ".ssh" else p.name
            targets.append((label, ssh_path))
    return targets


def _multi_host_mode(args) -> None:
    targets = _parse_targets_file(args.targets)
    if not targets:
        import sys
        print("Error: --targets file is empty or has no valid entries.", file=sys.stderr)
        sys.exit(1)

    print(f"\n  FOX-TRACE Multi-Host Scan ({len(targets)} host(s))")
    print("══════════════════════════════════════════════════════════════")

    multi_findings: dict = {}
    for label, ssh_path in targets:
        print(f"  Scanning [{label}] → {ssh_path}")
        h = SSHHarvester(ssh_dir=ssh_path, stale_days=args.stale)
        findings = h.harvest()
        multi_findings[label] = findings
        score = findings.get("risk_score", 0)
        n_priv = len(findings["private_keys"])
        n_kh = len(findings["known_hosts"])
        print(f"    Risk: {score}/100  Private keys: {n_priv}  Known hosts: {n_kh}")

    print()
    analyzer = TrustGraphAnalyzer()
    graph = analyzer.build_graph(multi_findings)
    cycles = analyzer.find_cycles(graph)
    circular_alerts = analyzer.generate_alerts(cycles)

    if cycles:
        print("  [!] CIRCULAR TRUST DETECTED")
        for alert in circular_alerts:
            print(f"  [CRITICAL] {alert['message']}")
            print(f"             → {alert['remediation']}")
    else:
        print("  [OK] No circular trust chains detected.")

    has_edges = any(dsts for dsts in graph.values())
    if has_edges:
        print("\n  Trust Relationships:")
        for src, dsts in sorted(graph.items()):
            for dst in sorted(dsts):
                marker = " ◄► (circular)" if any(
                    set(c[:-1]) == {src, dst} for c in cycles
                ) else ""
                print(f"    {src} → {dst}{marker}")

    multi_out = getattr(args, "json", None) or _DEFAULT_MULTI_JSON
    multi_out = multi_out.replace("findings.json", "multi_findings.json")
    os.makedirs(os.path.dirname(multi_out), exist_ok=True)
    with open(multi_out, "w") as f:
        json.dump({
            "hosts": multi_findings,
            "trust_graph": {k: sorted(v) for k, v in graph.items()},
            "circular_chains": cycles,
            "circular_alerts": circular_alerts,
        }, f, indent=4)
    print(f"\n[SUCCESS] Multi-host results saved to {multi_out}")

    if getattr(args, "html", None) is not None:
        from visualizer import FoxVisualizer
        html_out = args.html or _DEFAULT_MULTI_HTML
        FoxVisualizer(data_path=multi_out, output_path=html_out).generate_multi()
        print(f"[SUCCESS] Multi-host Shadow Map saved to {html_out}")

    print("══════════════════════════════════════════════════════════════")


if __name__ == "__main__":
    import sys
    parser = argparse.ArgumentParser(
        description="Fox-trace — SSH Trust & Lateral Movement Mapper"
    )
    parser.add_argument("--json", metavar="FILE", default=_DEFAULT_JSON,
                        help=f"Write findings to JSON (default: {_DEFAULT_JSON})")
    parser.add_argument("--html", metavar="FILE", nargs="?", const=_DEFAULT_HTML,
                        help="Generate interactive Shadow Map HTML")
    parser.add_argument("--github", metavar="USER",
                        help="Match local keys against a GitHub user's public keys")
    parser.add_argument("--stale", metavar="DAYS", type=int, default=180,
                        help="Flag private keys older than DAYS days (default: 180)")
    parser.add_argument("--ssh-dir", metavar="DIR",
                        help="Path to SSH directory (default: ~/.ssh)")
    parser.add_argument("--targets", metavar="FILE",
                        help="Scan multiple SSH directories — file with 'label:path' per line")
    args = parser.parse_args()

    if args.targets:
        _multi_host_mode(args)
        sys.exit(0)

    harvester = SSHHarvester(ssh_dir=args.ssh_dir, stale_days=args.stale)
    findings = harvester.harvest()

    if args.github:
        harvester.add_github_matches(args.github)

    _print_results(findings, github_user=args.github)
    harvester.save_json(args.json)
    print(f"\n[SUCCESS] Results saved to {args.json}")

    if args.html is not None:
        from visualizer import FoxVisualizer
        FoxVisualizer(data_path=args.json, output_path=args.html).generate()
