"""
supply_chain_auditor.py — Software Supply Chain Security Scanner
Author: securekamal
"""

import re
import json
import hashlib
import logging
import argparse
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
#  DATA MODELS
# ─────────────────────────────────────────────

@dataclass
class PackageRisk:
    name: str
    version: str
    ecosystem: str
    risk_score: int  # 0–100
    severity: str
    findings: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    recommendation: str = "ALLOW"


@dataclass
class AuditResult:
    manifest: str
    ecosystem: str
    packages: list[PackageRisk] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def summary(self) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 0}
        for p in self.packages:
            counts[p.severity] = counts.get(p.severity, 0) + 1
        return counts

    def to_report(self) -> str:
        lines = [
            f"\n🔍 Supply Chain Audit — {self.manifest}",
            "=" * 50,
            f"Ecosystem: {self.ecosystem} | Packages: {len(self.packages)}",
            f"Summary: {self.summary()}",
            "",
        ]
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "SAFE": 4}
        sorted_pkgs = sorted(self.packages, key=lambda p: sev_order.get(p.severity, 9))
        for pkg in sorted_pkgs:
            if pkg.severity == "SAFE":
                continue
            lines += [
                f"[{pkg.severity}] {pkg.name}=={pkg.version}  (risk score: {pkg.risk_score}/100)",
                f"  Action: {pkg.recommendation}",
            ]
            for f in pkg.findings:
                lines.append(f"  → {f}")
            if pkg.cves:
                lines.append(f"  CVEs: {', '.join(pkg.cves)}")
            lines.append("")
        return "\n".join(lines)


# ─────────────────────────────────────────────
#  TYPOSQUATTING DETECTION
# ─────────────────────────────────────────────

POPULAR_PACKAGES = {
    "python": [
        "requests", "numpy", "pandas", "flask", "django", "boto3",
        "sqlalchemy", "fastapi", "pydantic", "pytest", "setuptools",
        "cryptography", "paramiko", "pillow", "scipy", "urllib3",
        "certifi", "charset-normalizer", "idna", "six",
    ],
    "npm": [
        "lodash", "express", "react", "axios", "webpack", "babel",
        "eslint", "typescript", "next", "vue", "angular", "jest",
        "chalk", "dotenv", "moment", "uuid", "cors", "body-parser",
    ],
}


def levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def check_typosquatting(package: str, ecosystem: str) -> Optional[str]:
    """Returns the suspected legitimate package if typosquatting is detected."""
    popular = POPULAR_PACKAGES.get(ecosystem, [])
    pkg_clean = package.lower().replace("-", "").replace("_", "")
    for legit in popular:
        legit_clean = legit.lower().replace("-", "").replace("_", "")
        if pkg_clean != legit_clean and levenshtein(pkg_clean, legit_clean) <= 2:
            return legit
    return None


# ─────────────────────────────────────────────
#  MANIFEST PARSERS
# ─────────────────────────────────────────────

def parse_requirements_txt(content: str) -> list[tuple[str, str]]:
    """Parse Python requirements.txt into (name, version) pairs."""
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "git+")):
            continue
        # Handle ==, >=, ~=
        match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*[=><~!]+\s*([^\s;]+)", line)
        if match:
            packages.append((match.group(1).lower(), match.group(2)))
        elif re.match(r"^[A-Za-z0-9_\-\.]+$", line):
            packages.append((line.lower(), "unknown"))
    return packages


def parse_package_json(content: str) -> list[tuple[str, str]]:
    """Parse npm package.json into (name, version) pairs."""
    data = json.loads(content)
    packages = []
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, version in data.get(section, {}).items():
            clean_ver = version.lstrip("^~>=<")
            packages.append((name, clean_ver))
    return packages


# ─────────────────────────────────────────────
#  RISK ANALYZER
# ─────────────────────────────────────────────

# Simulated known-bad packages (in production, query OSV/PyPI/npm APIs)
KNOWN_MALICIOUS = {
    "python": {"colourama", "python-dateutil2", "urllib", "request"},
    "npm": {"crossenv", "event-stream", "node-opencv2", "flatmap-stream"},
}

KNOWN_CVES = {
    "requests==2.27.0": ["CVE-2023-32681"],
    "pillow==9.0.0": ["CVE-2023-44271", "CVE-2023-50447"],
    "cryptography==38.0.0": ["CVE-2023-49083"],
    "flask==1.0.0": ["CVE-2023-30861"],
}

CONFUSION_PREFIXES = ["mycompany-", "internal-", "corp-", "private-", "acme-"]


class RiskAnalyzer:

    def analyze(self, name: str, version: str, ecosystem: str) -> PackageRisk:
        findings = []
        score = 0
        cves = []

        # 1. Known malicious
        if name in KNOWN_MALICIOUS.get(ecosystem, set()):
            findings.append(f"Known malicious package — immediate removal required")
            score += 50

        # 2. Typosquatting
        suspect = check_typosquatting(name, ecosystem)
        if suspect:
            findings.append(f"Possible typosquat of '{suspect}' (edit distance ≤ 2)")
            score += 35

        # 3. Dependency confusion
        for prefix in CONFUSION_PREFIXES:
            if name.startswith(prefix):
                findings.append(f"Dependency confusion risk: '{name}' matches internal naming pattern")
                score += 40
                break

        # 4. Known CVEs
        key = f"{name}=={version}"
        pkg_cves = KNOWN_CVES.get(key, [])
        if pkg_cves:
            findings.append(f"Known CVEs: {', '.join(pkg_cves)}")
            score += len(pkg_cves) * 15
            cves = pkg_cves

        # 5. Version 0.x (immature, higher risk)
        if version.startswith("0."):
            score += 5

        score = min(score, 100)

        if score >= 70:
            severity = "CRITICAL"
            rec = "BLOCK"
        elif score >= 45:
            severity = "HIGH"
            rec = "REVIEW"
        elif score >= 20:
            severity = "MEDIUM"
            rec = "MONITOR"
        elif score > 0:
            severity = "LOW"
            rec = "LOG"
        else:
            severity = "SAFE"
            rec = "ALLOW"

        return PackageRisk(
            name=name,
            version=version,
            ecosystem=ecosystem,
            risk_score=score,
            severity=severity,
            findings=findings,
            cves=cves,
            recommendation=rec,
        )


# ─────────────────────────────────────────────
#  SBOM GENERATOR
# ─────────────────────────────────────────────

def generate_cyclonedx_sbom(packages: list[tuple[str, str]], ecosystem: str) -> dict:
    type_map = {"python": "pypi", "npm": "npm"}
    registry = type_map.get(ecosystem, ecosystem)
    components = []
    for name, version in packages:
        components.append({
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:{registry}/{name}@{version}",
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{hashlib.md5(str(packages).encode()).hexdigest()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tools": [{"name": "supply-chain-auditor", "version": "1.0.0"}],
        },
        "components": components,
    }


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Supply Chain Auditor")
    sub = parser.add_subparsers(dest="command")

    audit_p = sub.add_parser("audit")
    audit_p.add_argument("--ecosystem", choices=["python", "npm"], required=True)
    audit_p.add_argument("--manifest", required=True)
    audit_p.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM"])
    audit_p.add_argument("--sbom", help="Path to write SBOM JSON")
    audit_p.add_argument("--format", choices=["text", "json"], default="text")

    check_p = sub.add_parser("check")
    check_p.add_argument("--package", required=True)
    check_p.add_argument("--version", default="unknown")
    check_p.add_argument("--ecosystem", choices=["python", "npm"], required=True)

    args = parser.parse_args()

    if args.command == "audit":
        content = Path(args.manifest).read_text()
        if args.ecosystem == "python":
            packages = parse_requirements_txt(content)
        else:
            packages = parse_package_json(content)

        analyzer = RiskAnalyzer()
        result = AuditResult(manifest=args.manifest, ecosystem=args.ecosystem)
        for name, version in packages:
            result.packages.append(analyzer.analyze(name, version, args.ecosystem))

        if args.format == "json":
            print(json.dumps({"summary": result.summary(),
                               "packages": [p.__dict__ for p in result.packages]}, indent=2))
        else:
            print(result.to_report())

        if args.sbom:
            sbom = generate_cyclonedx_sbom(packages, args.ecosystem)
            Path(args.sbom).write_text(json.dumps(sbom, indent=2))
            logger.info(f"SBOM written to {args.sbom}")

        if args.fail_on:
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
            threshold = sev_order[args.fail_on]
            if any(sev_order.get(p.severity, 9) <= threshold for p in result.packages):
                raise SystemExit(1)

    elif args.command == "check":
        pkg = RiskAnalyzer().analyze(args.package, args.version, args.ecosystem)
        print(json.dumps(pkg.__dict__, indent=2))
        if pkg.severity in ("CRITICAL", "HIGH"):
            raise SystemExit(1)


if __name__ == "__main__":
    main()
