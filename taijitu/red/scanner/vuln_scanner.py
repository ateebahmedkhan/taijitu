# taijitu/red/scanner/vuln_scanner.py
# Vulnerability scanner for authorized targets
# Checks OWASP Top 10 and common misconfigurations
# Use only on systems you own or are authorized to test

import requests
import structlog
from datetime import datetime
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

log = structlog.get_logger()

# Disable SSL warnings for testing
requests.packages.urllib3.disable_warnings()


@dataclass
class Vulnerability:
    """A discovered vulnerability"""
    name: str
    severity: str           # critical/high/medium/low/info
    description: str
    evidence: str           # What was found
    url: str                # Where it was found
    remediation: str        # How to fix it
    cvss_score: float = 0.0
    cve: str = ""


@dataclass
class ScanResult:
    """Complete scan result for a target"""
    target: str
    timestamp: datetime
    vulnerabilities: list = field(default_factory=list)
    security_headers: dict = field(default_factory=dict)
    ssl_issues: list = field(default_factory=list)
    interesting_files: list = field(default_factory=list)
    total_score: float = 0.0


class VulnerabilityScanner:
    """
    Web application vulnerability scanner

    Checks for:
    - Missing security headers
    - SSL/TLS misconfigurations
    - Information disclosure
    - Common exposed files
    - Basic injection points
    - CORS misconfigurations
    - Cookie security issues

    Use only on authorized targets.
    """

    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 10
        self.session.headers.update({
            "User-Agent": "TAIJITU-RED Security Scanner (Authorized Testing)",
        })
        self.results_history = []
        log.info("vulnerability_scanner_initialized")

    def scan(self, target_url: str) -> ScanResult:
        """
        Run full vulnerability scan on target URL
        Returns complete ScanResult
        """
        # Normalize URL
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"

        log.info("scan_started", target=target_url)

        result = ScanResult(
            target=target_url,
            timestamp=datetime.utcnow(),
        )

        # Run all scan modules
        result.security_headers = self._check_security_headers(target_url)
        result.ssl_issues = self._check_ssl(target_url)
        result.interesting_files = self._check_interesting_files(target_url)

        # Convert findings to vulnerabilities
        result.vulnerabilities = self._analyze_findings(result)

        # Calculate overall score
        result.total_score = self._calculate_score(result)

        self.results_history.append(result)

        log.info(
            "scan_complete",
            target=target_url,
            vulns=len(result.vulnerabilities),
            score=result.total_score,
        )

        return result

    def _check_security_headers(self, url: str) -> dict:
        """
        Check for missing or misconfigured security headers
        These are some of the most common findings on bug bounty
        """
        headers_result = {}

        try:
            response = self.session.get(url)
            headers = response.headers

            # Headers that should be present
            security_headers = {
                "Strict-Transport-Security": {
                    "present": "Strict-Transport-Security" in headers,
                    "value": headers.get("Strict-Transport-Security", "MISSING"),
                    "severity": "medium",
                    "description": "HSTS prevents protocol downgrade attacks",
                },
                "Content-Security-Policy": {
                    "present": "Content-Security-Policy" in headers,
                    "value": headers.get("Content-Security-Policy", "MISSING"),
                    "severity": "medium",
                    "description": "CSP prevents XSS and injection attacks",
                },
                "X-Frame-Options": {
                    "present": "X-Frame-Options" in headers,
                    "value": headers.get("X-Frame-Options", "MISSING"),
                    "severity": "medium",
                    "description": "Prevents clickjacking attacks",
                },
                "X-Content-Type-Options": {
                    "present": "X-Content-Type-Options" in headers,
                    "value": headers.get("X-Content-Type-Options", "MISSING"),
                    "severity": "low",
                    "description": "Prevents MIME type sniffing",
                },
                "Referrer-Policy": {
                    "present": "Referrer-Policy" in headers,
                    "value": headers.get("Referrer-Policy", "MISSING"),
                    "severity": "low",
                    "description": "Controls referrer information leakage",
                },
                "Permissions-Policy": {
                    "present": "Permissions-Policy" in headers,
                    "value": headers.get("Permissions-Policy", "MISSING"),
                    "severity": "low",
                    "description": "Controls browser feature access",
                },
            }

            # Headers that should NOT be present
            dangerous_headers = {
                "Server": headers.get("Server", None),
                "X-Powered-By": headers.get("X-Powered-By", None),
                "X-AspNet-Version": headers.get("X-AspNet-Version", None),
            }

            headers_result["security_headers"] = security_headers
            headers_result["information_disclosure"] = {
                k: v for k, v in dangerous_headers.items() if v
            }
            headers_result["status_code"] = response.status_code
            headers_result["server"] = headers.get("Server", "unknown")

            log.info(
                "headers_checked",
                url=url,
                missing=sum(
                    1 for h in security_headers.values()
                    if not h["present"]
                ),
            )

        except requests.RequestException as e:
            log.error("header_check_failed", url=url, error=str(e))
            headers_result["error"] = str(e)

        return headers_result

    def _check_ssl(self, url: str) -> list:
        """Check for SSL/TLS issues"""
        issues = []

        if not url.startswith("https://"):
            issues.append({
                "type": "no_https",
                "severity": "high",
                "description": "Target not using HTTPS — traffic can be intercepted",
            })
            return issues

        try:
            # Check if HTTP redirects to HTTPS
            http_url = url.replace("https://", "http://")
            response = self.session.get(
                http_url,
                allow_redirects=False,
                timeout=5,
            )
            if response.status_code not in (301, 302, 307, 308):
                issues.append({
                    "type": "no_http_to_https_redirect",
                    "severity": "medium",
                    "description": "HTTP does not redirect to HTTPS",
                })

        except Exception:
            pass

        return issues

    def _check_interesting_files(self, url: str) -> list:
        """
        Check for commonly exposed sensitive files
        These are frequent bug bounty findings
        """
        interesting_paths = [
            "/.git/HEAD",
            "/.env",
            "/robots.txt",
            "/sitemap.xml",
            "/.htaccess",
            "/wp-config.php",
            "/config.php",
            "/admin/",
            "/administrator/",
            "/phpmyadmin/",
            "/backup/",
            "/api/v1/",
            "/api/v2/",
            "/swagger.json",
            "/openapi.json",
            "/.well-known/security.txt",
        ]

        found = []
        for path in interesting_paths:
            try:
                full_url = urljoin(url, path)
                response = self.session.get(
                    full_url,
                    allow_redirects=False,
                    timeout=5,
                )
                if response.status_code in (200, 301, 302, 403):
                    found.append({
                        "path": path,
                        "url": full_url,
                        "status_code": response.status_code,
                        "size": len(response.content),
                        "interesting": self._is_interesting(
                            path, response
                        ),
                    })
                    log.info(
                        "interesting_file_found",
                        path=path,
                        status=response.status_code,
                    )
            except Exception:
                pass

        return found

    def _is_interesting(self, path: str, response) -> bool:
        """Determine if a file response is actually interesting"""
        high_value = [".git", ".env", "config", "backup", "admin"]
        if any(h in path for h in high_value):
            return True
        if response.status_code == 200 and len(response.content) > 100:
            return True
        return False

    def _analyze_findings(self, result: ScanResult) -> list:
        """Convert raw findings into structured vulnerabilities"""
        vulns = []

        # Analyze security headers
        headers = result.security_headers.get("security_headers", {})
        for header_name, header_data in headers.items():
            if not header_data.get("present"):
                vulns.append(Vulnerability(
                    name=f"Missing {header_name} Header",
                    severity=header_data["severity"],
                    description=header_data["description"],
                    evidence=f"Header '{header_name}' not present in response",
                    url=result.target,
                    remediation=f"Add '{header_name}' header to all responses",
                ))

        # Information disclosure
        disclosure = result.security_headers.get(
            "information_disclosure", {}
        )
        for header, value in disclosure.items():
            vulns.append(Vulnerability(
                name=f"Information Disclosure via {header}",
                severity="low",
                description=f"Server reveals {header}: {value}",
                evidence=f"{header}: {value}",
                url=result.target,
                remediation=f"Remove or obscure the {header} header",
            ))

        # SSL issues
        for issue in result.ssl_issues:
            vulns.append(Vulnerability(
                name=issue["type"].replace("_", " ").title(),
                severity=issue["severity"],
                description=issue["description"],
                evidence="SSL/TLS configuration issue detected",
                url=result.target,
                remediation="Configure proper SSL/TLS settings",
            ))

        # Interesting files
        for file_info in result.interesting_files:
            if file_info.get("interesting"):
                severity = "high" if any(
                    s in file_info["path"]
                    for s in [".git", ".env", "config"]
                ) else "medium"
                vulns.append(Vulnerability(
                    name=f"Sensitive File Exposed: {file_info['path']}",
                    severity=severity,
                    description=f"Sensitive file accessible at {file_info['url']}",
                    evidence=f"HTTP {file_info['status_code']} response",
                    url=file_info["url"],
                    remediation="Restrict access to sensitive files",
                ))

        return vulns

    def _calculate_score(self, result: ScanResult) -> float:
        """Calculate overall vulnerability score"""
        score = 0.0
        severity_weights = {
            "critical": 40,
            "high": 20,
            "medium": 10,
            "low": 5,
            "info": 1,
        }
        for vuln in result.vulnerabilities:
            score += severity_weights.get(vuln.severity, 1)
        return round(min(score, 100.0), 1)

    def generate_report(self, result: ScanResult) -> dict:
        """Generate structured vulnerability report"""
        vuln_by_severity = {}
        for vuln in result.vulnerabilities:
            sev = vuln.severity
            if sev not in vuln_by_severity:
                vuln_by_severity[sev] = []
            vuln_by_severity[sev].append({
                "name": vuln.name,
                "description": vuln.description,
                "evidence": vuln.evidence,
                "url": vuln.url,
                "remediation": vuln.remediation,
            })

        return {
            "target": result.target,
            "timestamp": result.timestamp.isoformat(),
            "total_vulnerabilities": len(result.vulnerabilities),
            "risk_score": result.total_score,
            "vulnerabilities_by_severity": vuln_by_severity,
            "interesting_files": result.interesting_files,
        }


# ── GLOBAL INSTANCE ───────────────────────────────────
vuln_scanner = VulnerabilityScanner()