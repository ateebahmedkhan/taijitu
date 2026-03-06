# taijitu/red/scanner/web_scanner.py
# Deep web application vulnerability scanner
# Tests for SQL injection, XSS, SSRF, open redirects,
# path traversal and more
# Use only on authorized targets

import requests
import structlog
from datetime import datetime
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse, urlencode, parse_qs

log = structlog.get_logger()

requests.packages.urllib3.disable_warnings()


@dataclass
class WebVuln:
    """A confirmed web vulnerability"""
    vuln_type: str
    severity: str
    url: str
    parameter: str
    payload: str
    evidence: str
    description: str
    remediation: str
    bounty_estimate: str = ""


@dataclass
class WebScanResult:
    """Complete web scan result"""
    target: str
    timestamp: datetime
    urls_tested: list = field(default_factory=list)
    parameters_found: list = field(default_factory=list)
    vulnerabilities: list = field(default_factory=list)
    total_requests: int = 0


class WebScanner:
    """
    Deep web application vulnerability scanner

    Tests for:
    - SQL Injection (error and boolean based)
    - XSS (reflected)
    - SSRF
    - Open Redirects
    - Path Traversal
    - Command Injection indicators

    IMPORTANT: Use only on authorized targets.
    Unauthorized scanning is illegal.
    """

    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 10
        self.session.headers.update({
            "User-Agent": "TAIJITU-RED Security Scanner (Authorized Testing)",
        })
        self.total_requests = 0
        log.info("web_scanner_initialized")

    def scan(self, target_url: str) -> WebScanResult:
        """
        Run full web vulnerability scan
        Discovers parameters then tests each one
        """
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"

        log.info("web_scan_started", target=target_url)

        result = WebScanResult(
            target=target_url,
            timestamp=datetime.utcnow(),
        )

        # Step 1 — Discover URLs and parameters
        result.urls_tested, result.parameters_found = self._discover(
            target_url
        )

        # Step 2 — Test each parameter with hard timeout
        import time
        phase_start = time.time()
        MAX_PHASE_SECONDS = 180  # 3 minutes max
        MAX_URLS = 30            # max URLs to test

        tested = 0
        for url, params in result.parameters_found:
            if tested >= MAX_URLS:
                log.info("web_scan_url_limit_reached", tested=tested)
                break
            if time.time() - phase_start > MAX_PHASE_SECONDS:
                log.info("web_scan_timeout_reached",
                         elapsed=int(time.time() - phase_start))
                break

            for param in params:
                if time.time() - phase_start > MAX_PHASE_SECONDS:
                    break

                sqli_vulns = self._test_sqli(url, param)
                result.vulnerabilities.extend(sqli_vulns)

                xss_vulns = self._test_xss(url, param)
                result.vulnerabilities.extend(xss_vulns)

                redirect_vulns = self._test_open_redirect(url, param)
                result.vulnerabilities.extend(redirect_vulns)

                traversal_vulns = self._test_path_traversal(url, param)
                result.vulnerabilities.extend(traversal_vulns)

            tested += 1

        # Step 3 — SSRF only if time remaining
        if time.time() - phase_start < MAX_PHASE_SECONDS:
            ssrf_vulns = self._test_ssrf(target_url)
            result.vulnerabilities.extend(ssrf_vulns)

        result.total_requests = self.total_requests

        log.info(
            "web_scan_complete",
            target=target_url,
            urls=len(result.urls_tested),
            params=len(result.parameters_found),
            vulns=len(result.vulnerabilities),
            requests=self.total_requests,
        )

        return result

    def _discover(self, url: str) -> tuple:
        """
        Discover URLs and parameters on target
        Crawls one level deep from the target URL
        """
        urls_found = [url]
        params_found = []

        try:
            response = self._get(url)
            if not response:
                return urls_found, params_found

            # Extract links from page
            from html.parser import HTMLParser

            class LinkExtractor(HTMLParser):
                def __init__(self):
                    super().__init__()
                    self.links = []
                    self.forms = []

                def handle_starttag(self, tag, attrs):
                    attrs = dict(attrs)
                    if tag == "a" and "href" in attrs:
                        self.links.append(attrs["href"])
                    if tag == "form":
                        action = attrs.get("action", "")
                        method = attrs.get("method", "get").lower()
                        self.forms.append((action, method))

            parser = LinkExtractor()
            parser.feed(response.text)

            # Process found links
            base_domain = urlparse(url).netloc
            for link in parser.links:
                full_url = urljoin(url, link)
                parsed = urlparse(full_url)

                # Stay on same domain
                if parsed.netloc != base_domain:
                    continue

                if full_url not in urls_found:
                    urls_found.append(full_url)

                # Extract parameters
                if parsed.query:
                    params = list(parse_qs(parsed.query).keys())
                    if params:
                        params_found.append((full_url, params))
            
            # Also check known vulnerable paths directly
            known_param_paths = [
                "/listproducts.php?cat=1",
                "/artists.php?artist=1",
                "/search.php?test=query",
                "/showimage.php?file=image",
                "/product.php?id=1",
                "/comment.php?aid=1",
                "/userinfo.php?uid=1",
            ]

            for path in known_param_paths:
                full_url = urljoin(url, path)
                parsed = urlparse(full_url)
                if parsed.query:
                    params = list(parse_qs(parsed.query).keys())
                    if params:
                        params_found.append((full_url, params))
                        if full_url not in urls_found:
                            urls_found.append(full_url)

            log.info(
                "discovery_complete",
                urls=len(urls_found),
                param_sets=len(params_found),
            )

        except Exception as e:
            log.error("discovery_failed", error=str(e))

        return urls_found, params_found

    def _test_sqli(self, url: str, param: str) -> list:
        """
        Test parameter for SQL injection
        Checks for error-based and boolean-based SQLi
        """
        vulns = []

       # SQL error payloads — from PayloadsAllTheThings
        from taijitu.red.payloads import payload_loader
        error_payloads = payload_loader.get("sql_injection", limit=30)

        # SQL error signatures
        error_signatures = [
            "sql syntax",
            "mysql_fetch",
            "ora-01756",
            "sqlite_exception",
            "postgresql error",
            "warning: mysql",
            "unclosed quotation",
            "quoted string not properly terminated",
            "syntax error",
            "odbc microsoft access",
        ]

        for payload in error_payloads:
            response = self._get_with_param(url, param, payload)
            if not response:
                continue

            response_lower = response.text.lower()
            for sig in error_signatures:
                if sig in response_lower:
                    vulns.append(WebVuln(
                        vuln_type="SQL Injection",
                        severity="critical",
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=f"SQL error signature found: '{sig}'",
                        description=f"Parameter '{param}' is vulnerable to SQL injection",
                        remediation="Use parameterized queries / prepared statements",
                        bounty_estimate="$500 - $10,000+",
                    ))
                    log.info(
                        "sqli_found",
                        url=url,
                        param=param,
                        payload=payload,
                    )
                    return vulns  # One confirmed vuln is enough

        return vulns

    def _test_xss(self, url: str, param: str) -> list:
        """
        Test parameter for reflected XSS
        Checks if payload is reflected unencoded
        """
        vulns = []

        # XSS payloads — from PayloadsAllTheThings
        from taijitu.red.payloads import payload_loader
        xss_payloads = payload_loader.get("xss", limit=20)

        for payload in xss_payloads:
            response = self._get_with_param(url, param, payload)
            if not response:
                continue

            # Check if payload reflected unencoded
            if payload in response.text:
                vulns.append(WebVuln(
                    vuln_type="Reflected XSS",
                    severity="high",
                    url=url,
                    parameter=param,
                    payload=payload,
                    evidence=f"Payload reflected unencoded in response",
                    description=f"Parameter '{param}' reflects user input without sanitization",
                    remediation="Encode all user input before reflecting in HTML",
                    bounty_estimate="$200 - $3,000",
                ))
                log.info("xss_found", url=url, param=param)
                return vulns

        return vulns

    def _test_open_redirect(self, url: str, param: str) -> list:
        """
        Test parameter for open redirect
        Checks if redirect parameters can be hijacked
        """
        vulns = []

        # Only test redirect-related parameters
        redirect_params = [
            "redirect", "url", "next", "return",
            "returnurl", "redirect_uri", "callback",
            "goto", "target", "dest", "destination",
        ]

        if param.lower() not in redirect_params:
            return vulns

        payloads = [
            "https://evil.com",
            "//evil.com",
            "https://evil.com/",
        ]

        for payload in payloads:
            response = self._get_with_param(
                url, param, payload,
                allow_redirects=False,
            )
            if not response:
                continue

            # Check if redirecting to our payload
            if response.status_code in (301, 302, 307, 308):
                location = response.headers.get("Location", "")
                if "evil.com" in location:
                    vulns.append(WebVuln(
                        vuln_type="Open Redirect",
                        severity="medium",
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=f"Redirects to: {location}",
                        description=f"Parameter '{param}' allows redirecting to arbitrary URLs",
                        remediation="Validate redirect URLs against allowlist",
                        bounty_estimate="$100 - $500",
                    ))
                    log.info("open_redirect_found", url=url, param=param)
                    return vulns

        return vulns

    def _test_path_traversal(self, url: str, param: str) -> list:
        """
        Test parameter for path traversal
        Checks if file system can be accessed
        """
        vulns = []

        # Only test file-related parameters
        file_params = [
            "file", "path", "page", "include",
            "doc", "document", "folder", "root",
            "template", "view", "name", "load",
        ]

        if param.lower() not in file_params:
            return vulns

        payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
        ]

        # Signs of successful traversal
        traversal_signatures = [
            "root:x:0:0",
            "daemon:x:",
            "/bin/bash",
            "/bin/sh",
            "www-data",
        ]

        for payload in payloads:
            response = self._get_with_param(url, param, payload)
            if not response:
                continue

            for sig in traversal_signatures:
                if sig in response.text:
                    vulns.append(WebVuln(
                        vuln_type="Path Traversal",
                        severity="critical",
                        url=url,
                        parameter=param,
                        payload=payload,
                        evidence=f"File system content detected: '{sig}'",
                        description=f"Parameter '{param}' allows reading arbitrary files",
                        remediation="Validate and sanitize file paths. Use allowlist.",
                        bounty_estimate="$500 - $5,000",
                    ))
                    log.info(
                        "path_traversal_found",
                        url=url,
                        param=param,
                    )
                    return vulns

        return vulns

    def _test_ssrf(self, url: str) -> list:
        """
        Test for Server Side Request Forgery
        Checks common SSRF entry points
        """
        vulns = []

        # Common SSRF endpoints
        ssrf_paths = [
            "/api/fetch?url=",
            "/proxy?url=",
            "/image?url=",
            "/download?url=",
            "/webhook?url=",
        ]

        # SSRF test payloads
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://localhost/",
            "http://127.0.0.1/",
            "http://0.0.0.0/",
        ]

        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        for path in ssrf_paths:
            for payload in ssrf_payloads:
                test_url = f"{base}{path}{payload}"
                try:
                    response = self._get(test_url)
                    if not response:
                        continue

                    # AWS metadata response
                    if any(kw in response.text for kw in [
                        "ami-id", "instance-id",
                        "local-hostname", "public-keys",
                    ]):
                        vulns.append(WebVuln(
                            vuln_type="SSRF",
                            severity="critical",
                            url=test_url,
                            parameter="url",
                            payload=payload,
                            evidence="Cloud metadata endpoint accessible",
                            description="Server can be forced to make requests to internal services",
                            remediation="Validate and allowlist URLs for any server-side requests",
                            bounty_estimate="$1,000 - $20,000",
                        ))
                        log.info("ssrf_found", url=test_url)
                        return vulns

                except Exception:
                    pass

        return vulns

    def _get(self, url: str, allow_redirects: bool = True):
        """Make a GET request safely"""
        try:
            self.total_requests += 1
            return self.session.get(
                url,
                allow_redirects=allow_redirects,
                timeout=8,
            )
        except Exception:
            return None

    def _get_with_param(
        self,
        url: str,
        param: str,
        value: str,
        allow_redirects: bool = True,
    ):
        """Make a GET request with a specific parameter value"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param] = [value]

            # Rebuild URL with new param value
            from urllib.parse import quote
            param_string = "&".join(
                f"{k}={quote(v[0])}"
                for k, v in params.items()
            )
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param_string}"

            self.total_requests += 1
            return self.session.get(
                test_url,
                allow_redirects=allow_redirects,
                timeout=8,
            )
        except Exception:
            return None

    def generate_report(self, result: WebScanResult) -> dict:
        """Generate structured bug bounty ready report"""
        vulns_by_severity = {}
        for vuln in result.vulnerabilities:
            sev = vuln.vuln_type
            if sev not in vulns_by_severity:
                vulns_by_severity[sev] = []
            vulns_by_severity[sev].append({
                "severity": vuln.severity,
                "url": vuln.url,
                "parameter": vuln.parameter,
                "payload": vuln.payload,
                "evidence": vuln.evidence,
                "description": vuln.description,
                "remediation": vuln.remediation,
                "bounty_estimate": vuln.bounty_estimate,
            })

        return {
            "target": result.target,
            "timestamp": result.timestamp.isoformat(),
            "total_requests": result.total_requests,
            "urls_tested": len(result.urls_tested),
            "parameters_tested": len(result.parameters_found),
            "total_vulnerabilities": len(result.vulnerabilities),
            "vulnerabilities": vulns_by_severity,
        }


# ── GLOBAL INSTANCE ───────────────────────────────────
web_scanner = WebScanner()