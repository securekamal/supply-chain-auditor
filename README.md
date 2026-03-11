# 🔗 Supply Chain Auditor

> Software supply chain security scanner — detects dependency confusion, typosquatting, malicious packages, compromised maintainers, and generates SBOM with VEX statements. Integrates with Sigstore for artifact signing verification.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue)](https://python.org)
[![SLSA](https://img.shields.io/badge/SLSA-Level3-green)](https://slsa.dev)
[![Sigstore](https://img.shields.io/badge/Sigstore-verified-blue)](https://sigstore.dev)
[![CycloneDX](https://img.shields.io/badge/SBOM-CycloneDX-orange)](https://cyclonedx.org)

## The Problem

Supply chain attacks (SolarWinds, XZ Utils, event-stream, PyPI malware) are surging. Defenders need:
- **Real-time package reputation** scoring
- **Typosquatting detection** before install
- **Maintainer account takeover** detection
- **SBOM generation** with vulnerability correlation
- **Provenance verification** via Sigstore / in-toto

## Features

- 🎯 **Dependency confusion detection** — internal package names on public registries
- 🔤 **Typosquatting analysis** — edit-distance heuristics against popular packages
- 👤 **Maintainer risk scoring** — new maintainers, account age, 2FA status
- 📦 **Package behavior analysis** — install scripts, network calls, filesystem access
- 📜 **SBOM generation** — CycloneDX & SPDX 2.3 with license info
- ✅ **VEX statements** — Vulnerability Exploitability eXchange for known safe CVEs
- 🔏 **Sigstore verification** — verify artifact signatures & provenance
- 🕵️ **Historical comparison** — detect unexpected changes between versions

## Quickstart

```bash
pip install -r requirements.txt

# Audit current Python project
python supply_chain_auditor.py audit --ecosystem python --manifest requirements.txt

# Audit npm project
python supply_chain_auditor.py audit --ecosystem npm --manifest package-lock.json

# Check single package before installing
python supply_chain_auditor.py check --package requests --version 2.31.0 --ecosystem python

# Generate SBOM
python supply_chain_auditor.py sbom --manifest requirements.txt --format cyclonedx --out sbom.json

# Detect dependency confusion
python supply_chain_auditor.py confusion --internal-prefix mycompany- --manifest requirements.txt

# Verify Sigstore provenance
python supply_chain_auditor.py verify --artifact dist/myapp-1.0.tar.gz
```

## Risk Scoring

Each package receives a composite risk score (0-100):

| Factor | Weight | Description |
|--------|--------|-------------|
| Maintainer age | 15% | New maintainer or recent ownership change |
| 2FA enforcement | 10% | Maintainer account lacks 2FA |
| Package age | 10% | Package < 30 days old |
| Download velocity | 15% | Unusual spike in downloads |
| Install scripts | 20% | postinstall/preinstall hooks present |
| Source match | 15% | Published source matches repository |
| Known CVEs | 15% | Active unpatched vulnerabilities |

## Sample Output

```
🔍 Supply Chain Audit — requirements.txt
══════════════════════════════════════════════

[CRITICAL] Dependency Confusion: mycompany-utils (score: 95/100)
  → Package 'mycompany-utils' found on PyPI but appears to be an internal name
  → Public version (1.0.0) by unknown author 'h4ck3r99' uploaded 2 days ago
  → Action: Verify legitimacy or block via pip config

[HIGH] Typosquatting Risk: requets==2.28.0 (score: 78/100)
  → Edit distance 1 from 'requests' — possible typosquat
  → Author has no other packages, account created 5 days ago
  → Action: Verify package name spelling

[HIGH] Suspicious postinstall: node-fetch-polyfill@3.0.1 (score: 71/100)
  → postinstall script makes outbound HTTP call to unknown domain
  → Action: Review scripts/postinstall.js before installing

[MEDIUM] Maintainer takeover risk: flask==2.3.2 (score: 45/100)
  → Primary maintainer account has no 2FA
  → Action: Monitor for unexpected version bumps

Packages scanned: 142  |  Critical: 1  |  High: 3  |  Medium: 7
SBOM written to: sbom-cyclonedx.json (142 components, 23 CVEs)
```

## SBOM Integration

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {
      "type": "library",
      "name": "requests",
      "version": "2.31.0",
      "purl": "pkg:pypi/requests@2.31.0",
      "licenses": [{"license": {"id": "Apache-2.0"}}],
      "vulnerabilities": [
        {
          "id": "CVE-2023-32681",
          "ratings": [{"severity": "medium", "score": 6.1}],
          "analysis": {"state": "exploitable", "response": ["update"]}
        }
      ]
    }
  ]
}
```

## CI/CD Integration

```yaml
- name: Supply Chain Audit
  run: |
    python supply_chain_auditor.py audit \
      --ecosystem python \
      --manifest requirements.txt \
      --fail-on CRITICAL \
      --sbom sbom.json \
      --format sarif \
      --out supply-chain.sarif

- name: Attest SBOM
  uses: actions/attest-sbom@v1
  with:
    subject-path: dist/
    sbom-path: sbom.json
```
