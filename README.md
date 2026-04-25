![Fox-trace banner](banner.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) [![CI](https://github.com/elin-olsson/fox-trace/actions/workflows/ci.yml/badge.svg)](https://github.com/elin-olsson/fox-trace/actions/workflows/ci.yml)

A lightweight security tool designed to map and visualize SSH trust relationships on Linux systems. 

Fox-trace identifies "Shadow Paths" — the potential routes an attacker could take to move laterally through a network by exploiting local SSH artifacts like keys, config files, and connection history.

## Prerequisites

- Python 3.10 or later
- No external packages required at runtime — stdlib only

Check your Python version:
```bash
python3 --version
```

## Installation

Clone the repository and navigate to the tool directory:
```bash
git clone https://github.com/elin-olsson/fox-trace.git
cd fox-trace
```

No dependencies to install. Run directly:
```bash
python3 src/harvester.py
```

## Usage

```bash
python3 src/harvester.py [options]
```

```bash
# Run the harvester to scan the default ~/.ssh directory
python3 src/harvester.py

# Generate the interactive Shadow Map (HTML)
python3 src/visualizer.py

# Save results to a custom JSON path
python3 src/harvester.py --json data/custom_findings.json
```

### Flags (Planned/Implemented)

| Flag | Description | Status |
|---|---|---|
| `--json FILE` | Write structured findings to JSON | ✅ Implemented |
| `--html FILE` | Generate interactive D3.js Shadow Map | ✅ Implemented |
| `--github USER` | Match keys against GitHub public API | ✅ Implemented |
| `--stale DAYS` | Flag keys older than X days (default: 180) | ✅ Implemented |

## What it checks

Fox-trace performs a multi-stage audit of your SSH environment to uncover hidden risks.

| Check | How | Insight |
|---|---|---|
| **Private Keys** | Scans `~/.ssh/` for private key headers | Identifies the "passports" available on the system. |
| **Known Hosts** | Parses `known_hosts` (plain-text and hashed) | Maps the destinations where this user has gone before. |
| **Authorized Keys** | Reads fingerprints and comments | Identifies who has inbound access to this system. |
| **Identity Match** | GitHub API correlation | Verifies if an anonymous key belongs to a known GitHub identity. |
| **Active Agents** | Scans `/tmp/` for active SSH agent sockets | Warns of potential session hijacking risks. |
| **Blast Radius** | Correlates SSH config with known hosts | Calculates how many servers a leaked key can access. |

## Example output

Running the harvester on a local system:

```
══════════════════════════════════════════════════════════════
  FOX-TRACE  —  SSH Trust & Lateral Movement Mapper
══════════════════════════════════════════════════════════════
  Generated   2026-04-25 12:45:00
  Findings    34 artifacts identified

--- Fox-trace Harvester Results ---
Found 1 private keys.
Found 1 public keys.
Found 1 entries in authorized_keys.
Found 30 known hosts (connections).
Found 0 active SSH agents.

--- Blast Radius Analysis ---
Key: id_ed25519 -> Accesses 30 hosts (100.0%)

--- Risk Alerts ---
[HIGH] Key 'id_ed25519' has a Blast Radius of 100.0%.
[LOW] Private key 'id_ed25519' is stale (240 days old).

--- Identity Matching (GitHub: elin-olsson) ---
[MATCH] Found your GitHub key in authorized_keys! (Comment: elin-olsson@hotmail.com)

[SUCCESS] Results saved to data/findings.json
[SUCCESS] Shadow Map generated: data/shadow_map.html
══════════════════════════════════════════════════════════════
```

## Shadow Map Visualization

Fox-trace includes a built-in visualizer that generates an interactive, force-directed graph using **D3.js**. 

- **Local Machine (Origin):** The starting point of the audit.
- **SSH Keys:** Represented by nodes that scale based on their **Blast Radius**.
- **Known Hosts:** Destinations identified in the trust network.
- **Risks/Alerts:** Critical findings highlighted with red glow and alert badges.

## Dependencies

No runtime dependencies — stdlib only.

| Package | Version | Purpose |
|---|---|---|
| `json` | stdlib | Data export and visualization input |
| `urllib` | stdlib | GitHub Public Key API communication |
| `hashlib` | stdlib | SSH key fingerprinting (MD5) |
| `d3.js` | v7 (CDN) | Interactive graph rendering (via visualizer.py) |

---

<p align="center">
  <img src="logo.png" alt="Fox-trace logo" width="200">
</p>

<p align="center">
  <sub>The banner and logo are &copy; 2026 shadowfox.se — all rights reserved, not covered by the MIT license.</sub>
</p>
