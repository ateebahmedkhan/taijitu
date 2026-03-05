# taijitu/red/scanner/takeover.py
# Subdomain takeover detection
# One of the most common and automatable bug bounty findings
# Checks if subdomains point to unclaimed cloud services
# Use only on authorized targets

import socket
import requests
import structlog
from datetime import datetime
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

log = structlog.get_logger()

requests.packages.urllib3.disable_warnings()

# Fingerprints for vulnerable services
# If a subdomain points to one of these services
# and shows this response — it can be taken over
TAKEOVER_FINGERPRINTS = {
    "GitHub Pages": {
        "cname_contains": ["github.io", "github.com"],
        "response_contains": [
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index",
        ],
        "severity": "high",
        "how_to_takeover": "Claim the GitHub Pages site by creating a repo with the right name",
        "bounty_estimate": "$500 - $2,000",
    },
    "Heroku": {
        "cname_contains": ["herokuapp.com", "herokuapp.com"],
        "response_contains": [
            "No such app",
            "herokucdn.com/error-pages/no-such-app",
        ],
        "severity": "high",
        "how_to_takeover": "Create a Heroku app with the same name",
        "bounty_estimate": "$500 - $2,000",
    },
    "AWS S3": {
        "cname_contains": ["amazonaws.com", "s3.amazonaws.com"],
        "response_contains": [
            "NoSuchBucket",
            "The specified bucket does not exist",
        ],
        "severity": "high",
        "how_to_takeover": "Create an S3 bucket with the same name",
        "bounty_estimate": "$500 - $3,000",
    },
    "Netlify": {
        "cname_contains": ["netlify.app", "netlify.com"],
        "response_contains": [
            "Not Found - Request ID",
            "netlify",
        ],
        "severity": "high",
        "how_to_takeover": "Claim the Netlify site",
        "bounty_estimate": "$500 - $2,000",
    },
    "Shopify": {
        "cname_contains": ["myshopify.com"],
        "response_contains": [
            "Sorry, this shop is currently unavailable",
            "Only one step left",
        ],
        "severity": "medium",
        "how_to_takeover": "Create a Shopify store with the same name",
        "bounty_estimate": "$200 - $1,000",
    },
    "Fastly": {
        "cname_contains": ["fastly.net"],
        "response_contains": [
            "Fastly error: unknown domain",
        ],
        "severity": "high",
        "how_to_takeover": "Claim the Fastly service",
        "bounty_estimate": "$500 - $2,000",
    },
    "Zendesk": {
        "cname_contains": ["zendesk.com"],
        "response_contains": [
            "Help Center Closed",
            "Oops, this help center no longer exists",
        ],
        "severity": "medium",
        "how_to_takeover": "Create a Zendesk account with the same subdomain",
        "bounty_estimate": "$200 - $1,000",
    },
    "Tumblr": {
        "cname_contains": ["tumblr.com"],
        "response_contains": [
            "Whatever you were looking for doesn't currently exist",
            "There's nothing here",
        ],
        "severity": "low",
        "how_to_takeover": "Create a Tumblr blog with the same name",
        "bounty_estimate": "$100 - $500",
    },
    "WP Engine": {
        "cname_contains": ["wpengine.com"],
        "response_contains": [
            "The site you were looking for couldn't be found",
        ],
        "severity": "high",
        "how_to_takeover": "Claim the WP Engine site",
        "bounty_estimate": "$500 - $2,000",
    },
    "Azure": {
        "cname_contains": [
            "azurewebsites.net",
            "cloudapp.net",
            "blob.core.windows.net",
        ],
        "response_contains": [
            "404 Web Site not found",
            "The resource you are looking for has been removed",
        ],
        "severity": "high",
        "how_to_takeover": "Claim the Azure resource",
        "bounty_estimate": "$500 - $3,000",
    },
    "Vercel": {
        "cname_contains": ["vercel.app", "now.sh"],
        "response_contains": [
            "The deployment you requested does not exist",
        ],
        "severity": "high",
        "how_to_takeover": "Deploy to Vercel with the same domain",
        "bounty_estimate": "$500 - $2,000",
    },
    "Surge.sh": {
        "cname_contains": ["surge.sh"],
        "response_contains": [
            "project not found",
        ],
        "severity": "high",
        "how_to_takeover": "Claim the Surge.sh project",
        "bounty_estimate": "$200 - $1,000",
    },
    "Intercom": {
        "cname_contains": ["intercom.io", "custom.intercom.help"],
        "response_contains": [
            "This page is reserved for",
            "Uh oh. That page doesn",
        ],
        "severity": "medium",
        "how_to_takeover": "Claim the Intercom help center",
        "bounty_estimate": "$200 - $1,000",
    },
}

# Common subdomain wordlist for discovery
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging",
    "test", "vpn", "remote", "portal", "dashboard", "app",
    "beta", "cdn", "static", "assets", "blog", "shop", "secure",
    "help", "support", "docs", "status", "monitor", "analytics",
    "auth", "login", "sso", "oauth", "id", "accounts",
    "careers", "jobs", "media", "img", "images", "files",
    "download", "uploads", "backup", "old", "new", "v2", "v3",
    "internal", "intranet", "corp", "corporate", "office",
    "git", "gitlab", "jenkins", "jira", "confluence", "wiki",
    "grafana", "kibana", "elastic", "prometheus", "monitor",
    "smtp", "pop", "imap", "webmail", "exchange", "mx",
    "ns1", "ns2", "dns", "whois", "rdp", "ssh", "sftp",
    "stage", "uat", "qa", "preprod", "sandbox", "demo",
    "mobile", "m", "wap", "ios", "android", "app2",
    "forum", "community", "chat", "slack", "teams",
    "search", "elasticsearch", "solr", "redis", "mongo",
    "db", "database", "mysql", "postgres", "sql",
    "aws", "azure", "gcp", "cloud", "kubernetes", "k8s",
]


@dataclass
class TakeoverFinding:
    """A confirmed or potential subdomain takeover"""
    subdomain: str
    cname: str
    service: str
    severity: str
    description: str
    how_to_takeover: str
    bounty_estimate: str
    confirmed: bool = False


@dataclass
class TakeoverScanResult:
    """Complete takeover scan result"""
    target_domain: str
    timestamp: datetime
    subdomains_checked: int = 0
    subdomains_found: list = field(default_factory=list)
    vulnerable_subdomains: list = field(default_factory=list)
    dangling_cnames: list = field(default_factory=list)


class TakeoverScanner:
    """
    Subdomain takeover vulnerability scanner

    What it does:
    1. Enumerates subdomains of target domain
    2. Resolves CNAME records for each subdomain
    3. Checks if CNAME points to unclaimed service
    4. Confirms takeover by checking service response
    5. Reports vulnerable subdomains with takeover instructions

    Why this matters:
    Subdomain takeover allows an attacker to serve
    malicious content from a trusted company domain.
    Attackers can steal cookies, phish users, and
    bypass CSP policies using the trusted domain.

    Use only on authorized targets.
    """

    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 10
        log.info("takeover_scanner_initialized")

    def scan(
        self,
        domain: str,
        wordlist: list = None,
        threads: int = 20,
    ) -> TakeoverScanResult:
        """
        Run full subdomain takeover scan
        Returns TakeoverScanResult
        """
        # Clean domain
        domain = domain.replace("https://", "").replace("http://", "")
        domain = domain.split("/")[0]

        log.info("takeover_scan_starting", domain=domain)

        result = TakeoverScanResult(
            target_domain=domain,
            timestamp=datetime.utcnow(),
        )

        # Use provided wordlist or default
        subdomains_to_check = wordlist or COMMON_SUBDOMAINS

        # Generate full subdomain list
        full_subdomains = [
            f"{sub}.{domain}" for sub in subdomains_to_check
        ]

        result.subdomains_checked = len(full_subdomains)

        # Parallel subdomain resolution
        log.info(
            "checking_subdomains",
            count=len(full_subdomains),
            threads=threads,
        )

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(
                    self._check_subdomain, subdomain
                ): subdomain
                for subdomain in full_subdomains
            }

            for future in as_completed(futures):
                subdomain = futures[future]
                try:
                    check_result = future.result()
                    if check_result:
                        result.subdomains_found.append(
                            check_result["subdomain"]
                        )

                        if check_result.get("cname"):
                            # Check for takeover
                            finding = self._check_takeover(check_result)
                            if finding:
                                result.vulnerable_subdomains.append(finding)
                                log.info(
                                    "takeover_found",
                                    subdomain=check_result["subdomain"],
                                    service=finding.service,
                                )
                            elif check_result.get("dangling"):
                                result.dangling_cnames.append(check_result)

                except Exception as e:
                    log.warning(
                        "subdomain_check_error",
                        subdomain=subdomain,
                        error=str(e)[:50],
                    )

        log.info(
            "takeover_scan_complete",
            domain=domain,
            found=len(result.subdomains_found),
            vulnerable=len(result.vulnerable_subdomains),
            dangling=len(result.dangling_cnames),
        )

        return result

    def _check_subdomain(self, subdomain: str) -> dict:
        """
        Check a single subdomain
        Returns dict with resolution info or None
        """
        try:
            # Try to resolve
            ip = socket.gethostbyname(subdomain)

            result = {
                "subdomain": subdomain,
                "ip": ip,
                "cname": None,
                "dangling": False,
            }

            # Try to get CNAME
            try:
                import subprocess
                dig = subprocess.run(
                    ["dig", "+short", "CNAME", subdomain],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                cname = dig.stdout.strip()
                if cname:
                    result["cname"] = cname

            except Exception:
                pass

            return result

        except socket.gaierror:
            # NXDOMAIN — subdomain does not exist
            return None
        except Exception:
            return None

    def _check_takeover(self, subdomain_info: dict) -> TakeoverFinding:
        """
        Check if a subdomain is vulnerable to takeover
        Returns TakeoverFinding or None
        """
        subdomain = subdomain_info["subdomain"]
        cname = subdomain_info.get("cname", "") or ""

        for service_name, fingerprint in TAKEOVER_FINGERPRINTS.items():
            # Check if CNAME matches service
            cname_match = any(
                c in cname.lower()
                for c in fingerprint["cname_contains"]
            )

            if not cname_match:
                # Also check IP-based detection for some services
                continue

            # CNAME matches — check HTTP response
            confirmed = False
            try:
                for protocol in ["https", "http"]:
                    try:
                        response = self.session.get(
                            f"{protocol}://{subdomain}",
                            timeout=8,
                            allow_redirects=True,
                        )
                        response_text = response.text.lower()

                        for signature in fingerprint["response_contains"]:
                            if signature.lower() in response_text:
                                confirmed = True
                                break

                        if confirmed:
                            break

                    except Exception:
                        continue

            except Exception:
                pass

            if confirmed or cname_match:
                return TakeoverFinding(
                    subdomain=subdomain,
                    cname=cname,
                    service=service_name,
                    severity=fingerprint["severity"],
                    description=(
                        f"{subdomain} points to {service_name} via CNAME {cname} "
                        f"but the resource is unclaimed"
                    ),
                    how_to_takeover=fingerprint["how_to_takeover"],
                    bounty_estimate=fingerprint["bounty_estimate"],
                    confirmed=confirmed,
                )

        return None

    def generate_report(self, result: TakeoverScanResult) -> dict:
        """Generate takeover scan report"""
        vulnerable = [
            {
                "subdomain": f.subdomain,
                "cname": f.cname,
                "service": f.service,
                "severity": f.severity,
                "description": f.description,
                "how_to_takeover": f.how_to_takeover,
                "bounty_estimate": f.bounty_estimate,
                "confirmed": f.confirmed,
            }
            for f in result.vulnerable_subdomains
        ]

        return {
            "target_domain": result.target_domain,
            "timestamp": result.timestamp.isoformat(),
            "subdomains_checked": result.subdomains_checked,
            "subdomains_found": len(result.subdomains_found),
            "vulnerable_count": len(result.vulnerable_subdomains),
            "dangling_cnames": len(result.dangling_cnames),
            "vulnerable_subdomains": vulnerable,
            "all_subdomains": result.subdomains_found,
        }


# ── GLOBAL INSTANCE ───────────────────────────────────
takeover_scanner = TakeoverScanner()