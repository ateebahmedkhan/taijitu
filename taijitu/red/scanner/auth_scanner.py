# taijitu/red/scanner/auth_scanner.py
# Authenticated vulnerability scanner
# Logs in to target and tests protected endpoints
# Finds IDOR, privilege escalation, auth bypass
# The vulnerabilities that pay the most on bug bounty

import asyncio
import re
import structlog
from datetime import datetime
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout

log = structlog.get_logger()


@dataclass
class AuthCredentials:
    """Credentials for authenticated scanning"""
    username: str
    password: str
    username_field: str = "username"
    password_field: str = "password"
    login_url: str = ""
    success_indicator: str = ""    # Text present after successful login
    failure_indicator: str = ""    # Text present after failed login


@dataclass
class AuthFinding:
    """A vulnerability found during authenticated scan"""
    vuln_type: str
    severity: str
    url: str
    description: str
    evidence: str
    parameter: str = ""
    payload: str = ""
    remediation: str = ""
    bounty_estimate: str = ""


@dataclass
class AuthScanResult:
    """Complete authenticated scan result"""
    target: str
    timestamp: datetime
    login_successful: bool = False
    authenticated_urls: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    user_id: str = ""
    session_cookies: dict = field(default_factory=dict)
    privileged_endpoints: list = field(default_factory=list)


class AuthScanner:
    """
    Authenticated vulnerability scanner

    What it does:
    - Logs in to target application
    - Tests authenticated endpoints
    - Detects IDOR vulnerabilities
    - Detects privilege escalation
    - Detects authentication bypass
    - Tests horizontal access control
    - Tests vertical access control
    - Finds session management issues

    Why this matters:
    Most bug bounty programs pay 2-5x more for
    authenticated vulnerabilities because they
    affect real user data and business logic.

    Use only on authorized targets with test accounts.
    Never use real user credentials.
    """

    def __init__(self):
        self.timeout = 30000
        log.info("auth_scanner_initialized")

    def scan(
        self,
        target_url: str,
        credentials: AuthCredentials,
    ) -> AuthScanResult:
        """Synchronous wrapper for async authenticated scan"""
        return asyncio.run(self._scan_async(target_url, credentials))

    async def _scan_async(
        self,
        target_url: str,
        credentials: AuthCredentials,
    ) -> AuthScanResult:
        """Main async authenticated scan"""
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"

        log.info("auth_scan_starting", target=target_url)

        result = AuthScanResult(
            target=target_url,
            timestamp=datetime.utcnow(),
        )

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )

            context = await browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1920, "height": 1080},
            )

            page = await context.new_page()

            # Step 1 — Login
            login_success = await self._login(
                page, target_url, credentials, result
            )

            if not login_success:
                log.warning("login_failed", target=target_url)
                await browser.close()
                return result

            result.login_successful = True
            log.info("login_successful", target=target_url)

            # Step 2 — Discover authenticated URLs
            await self._discover_authenticated_urls(
                page, target_url, result
            )

            # Step 3 — Test for IDOR
            await self._test_idor(page, result)

            # Step 4 — Test for auth bypass
            await self._test_auth_bypass(
                context, page, target_url, result
            )

            # Step 5 — Test session security
            await self._test_session_security(
                page, context, result
            )

            # Step 6 — Check for sensitive data exposure
            await self._check_sensitive_data(page, result)

            await browser.close()

        log.info(
            "auth_scan_complete",
            target=target_url,
            findings=len(result.findings),
            urls_tested=len(result.authenticated_urls),
        )

        return result

    async def _login(
        self,
        page,
        target_url: str,
        credentials: AuthCredentials,
        result: AuthScanResult,
    ) -> bool:
        """Attempt to log in to target"""
        login_url = credentials.login_url or urljoin(target_url, "/login")

        try:
            await page.goto(login_url, timeout=self.timeout)

            # Find and fill username field
            username_selectors = [
                f'input[name="{credentials.username_field}"]',
                f'input[id="{credentials.username_field}"]',
                'input[type="email"]',
                'input[name="email"]',
                'input[name="user"]',
                'input[name="uname"]',
                'input[name="login"]',
                'input[type="text"]:first-of-type',
            ]

            username_filled = False
            for selector in username_selectors:
                try:
                    element = await page.wait_for_selector(
                        selector, timeout=3000
                    )
                    if element:
                        await element.fill(credentials.username)
                        username_filled = True
                        log.info(
                            "username_filled",
                            selector=selector,
                        )
                        break
                except Exception:
                    continue

            if not username_filled:
                log.warning("username_field_not_found")
                return False

            # Find and fill password field
            password_selectors = [
                f'input[name="{credentials.password_field}"]',
                f'input[id="{credentials.password_field}"]',
                'input[type="password"]',
                'input[name="pass"]',
                'input[name="pwd"]',
            ]

            password_filled = False
            for selector in password_selectors:
                try:
                    element = await page.wait_for_selector(
                        selector, timeout=3000
                    )
                    if element:
                        await element.fill(credentials.password)
                        password_filled = True
                        log.info(
                            "password_filled",
                            selector=selector,
                        )
                        break
                except Exception:
                    continue

            if not password_filled:
                log.warning("password_field_not_found")
                return False

            # Submit form
            submit_selectors = [
                'input[type="submit"]',
                'button[type="submit"]',
                'button:has-text("Login")',
                'button:has-text("Sign in")',
                'button:has-text("Log in")',
                'input[value="login"]',
            ]

            submitted = False
            for selector in submit_selectors:
                try:
                    element = await page.wait_for_selector(
                        selector, timeout=3000
                    )
                    if element:
                        await element.click()
                        submitted = True
                        break
                except Exception:
                    continue

            if not submitted:
                await page.keyboard.press("Enter")

            # Wait for navigation
            await page.wait_for_load_state(
                "networkidle", timeout=10000
            )

            # Check login success
            current_url = page.url
            page_content = await page.content()

            # Success indicators
            success_signs = [
                "logout", "sign out", "dashboard",
                "profile", "account", "welcome",
                credentials.username.lower(),
            ]

            # Failure indicators
            failure_signs = [
                "invalid", "incorrect", "failed",
                "wrong password", "error", "denied",
            ]

            if credentials.success_indicator:
                if credentials.success_indicator.lower() in page_content.lower():
                    return True

            if credentials.failure_indicator:
                if credentials.failure_indicator.lower() in page_content.lower():
                    return False

            # Auto-detect
            content_lower = page_content.lower()
            if any(sign in content_lower for sign in failure_signs):
                return False

            if any(sign in content_lower for sign in success_signs):
                return True

            # If URL changed away from login — probably success
            if "login" not in current_url and "signin" not in current_url:
                return True

            return False

        except Exception as e:
            log.error("login_error", error=str(e)[:100])
            return False

    async def _discover_authenticated_urls(
        self,
        page,
        target_url: str,
        result: AuthScanResult,
    ):
        """Discover URLs accessible when authenticated"""
        base_domain = urlparse(target_url).netloc
        visited = {page.url}
        to_visit = [page.url, target_url]

        while to_visit and len(result.authenticated_urls) < 20:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)

            try:
                await page.goto(url, timeout=self.timeout,
                                wait_until="domcontentloaded")

                links = await page.evaluate("""
                    () => Array.from(
                        document.querySelectorAll('a[href]'),
                        a => a.href
                    )
                """)

                for link in links:
                    if not link:
                        continue
                    parsed = urlparse(link)
                    if parsed.netloc != base_domain:
                        continue
                    if link in visited:
                        continue
                    if any(ext in link for ext in [
                        '.jpg', '.png', '.gif', '.css', '.ico'
                    ]):
                        continue

                    result.authenticated_urls.append(link)
                    to_visit.append(link)

                    if any(p in link for p in [
                        "id=", "uid=", "user_id=",
                        "account=", "profile=", "user="
                    ]):
                        result.privileged_endpoints.append(link)

            except Exception:
                continue

        log.info(
            "authenticated_urls_discovered",
            count=len(result.authenticated_urls),
            privileged=len(result.privileged_endpoints),
        )

    async def _test_idor(self, page, result: AuthScanResult):
        """
        Test for Insecure Direct Object Reference
        Try accessing other users data by changing IDs
        IDOR is one of the highest-paid bug bounty findings
        """
        idor_candidates = result.privileged_endpoints.copy()

        # Also check authenticated URLs for ID parameters
        for url in result.authenticated_urls:
            if any(p in url for p in ["id=", "uid=", "user=", "account="]):
                idor_candidates.append(url)

        for url in idor_candidates[:10]:
            try:
                # Get original response
                await page.goto(url, timeout=self.timeout)
                original_content = await page.content()
                original_url = page.url

                # Try sequential IDs
                test_ids = ["1", "2", "3", "0", "-1", "999999"]
                parsed = urlparse(url)

                for test_id in test_ids:
                    # Replace numeric IDs in URL
                    import re
                    modified_url = re.sub(
                        r'(id|uid|user_id|account|profile)=\d+',
                        lambda m: f"{m.group(1)}={test_id}",
                        url,
                    )

                    if modified_url == url:
                        continue

                    await page.goto(modified_url, timeout=self.timeout)
                    modified_content = await page.content()

                    # If we get different content — potential IDOR
                    if (
                        modified_content != original_content
                        and len(modified_content) > 500
                        and "error" not in modified_content.lower()[:200]
                        and "not found" not in modified_content.lower()[:200]
                        and "denied" not in modified_content.lower()[:200]
                    ):
                        result.findings.append(AuthFinding(
                            vuln_type="IDOR",
                            severity="high",
                            url=modified_url,
                            description=(
                                f"Possible IDOR — accessing ID {test_id} "
                                f"returns different content"
                            ),
                            evidence=(
                                f"Original URL: {url}\n"
                                f"Modified URL: {modified_url}\n"
                                f"Response differs — manual verification needed"
                            ),
                            remediation=(
                                "Implement server-side authorization checks. "
                                "Verify user owns the resource before returning data."
                            ),
                            bounty_estimate="$500 - $5,000",
                        ))
                        log.info(
                            "potential_idor",
                            url=modified_url,
                            test_id=test_id,
                        )
                        break

            except Exception as e:
                log.warning("idor_test_error", error=str(e)[:100])

    async def _test_auth_bypass(
        self,
        context,
        authenticated_page,
        target_url: str,
        result: AuthScanResult,
    ):
        """
        Test if authenticated endpoints are accessible without auth
        Creates a new unauthenticated browser context
        """
        if not result.authenticated_urls:
            return

        try:
            # New context — no cookies — unauthenticated
            unauth_context = await context.browser.new_context(
                ignore_https_errors=True,
            )
            unauth_page = await unauth_context.new_page()

            for url in result.authenticated_urls[:10]:
                try:
                    response = await unauth_page.goto(
                        url, timeout=self.timeout
                    )
                    unauth_content = await unauth_page.content()
                    unauth_url = unauth_page.url

                    # If we stayed on the page and got real content
                    # without being redirected to login
                    if (
                        "login" not in unauth_url
                        and "signin" not in unauth_url
                        and len(unauth_content) > 500
                        and "please log in" not in unauth_content.lower()
                        and "please sign in" not in unauth_content.lower()
                    ):
                        result.findings.append(AuthFinding(
                            vuln_type="Authentication Bypass",
                            severity="critical",
                            url=url,
                            description=(
                                "Authenticated endpoint accessible without login"
                            ),
                            evidence=(
                                f"URL accessible without authentication: {url}\n"
                                f"No redirect to login page\n"
                                f"Response size: {len(unauth_content)} bytes"
                            ),
                            remediation=(
                                "Implement authentication middleware on all "
                                "protected routes. Verify session on every request."
                            ),
                            bounty_estimate="$1,000 - $10,000",
                        ))
                        log.info("auth_bypass_found", url=url)

                except Exception:
                    continue

            await unauth_context.close()

        except Exception as e:
            log.warning("auth_bypass_test_error", error=str(e)[:100])

    async def _test_session_security(
        self,
        page,
        context,
        result: AuthScanResult,
    ):
        """Test session management security"""
        try:
            cookies = await context.cookies()
            session_cookies = [
                c for c in cookies
                if any(
                    name in c["name"].lower()
                    for name in ["session", "auth", "token", "jwt", "sid"]
                )
            ]

            for cookie in session_cookies:
                result.session_cookies[cookie["name"]] = {
                    "value": cookie["value"][:20] + "...",
                    "httpOnly": cookie.get("httpOnly", False),
                    "secure": cookie.get("secure", False),
                    "sameSite": cookie.get("sameSite", "None"),
                }

                # Check cookie security flags
                if not cookie.get("httpOnly"):
                    result.findings.append(AuthFinding(
                        vuln_type="Insecure Cookie",
                        severity="medium",
                        url=result.target,
                        description=(
                            f"Session cookie '{cookie['name']}' missing "
                            f"HttpOnly flag — vulnerable to XSS cookie theft"
                        ),
                        evidence=f"Cookie: {cookie['name']} — HttpOnly: False",
                        remediation="Set HttpOnly flag on all session cookies.",
                        bounty_estimate="$100 - $500",
                    ))

                if not cookie.get("secure"):
                    result.findings.append(AuthFinding(
                        vuln_type="Insecure Cookie",
                        severity="medium",
                        url=result.target,
                        description=(
                            f"Session cookie '{cookie['name']}' missing "
                            f"Secure flag — transmitted over HTTP"
                        ),
                        evidence=f"Cookie: {cookie['name']} — Secure: False",
                        remediation="Set Secure flag on all session cookies.",
                        bounty_estimate="$100 - $500",
                    ))

        except Exception as e:
            log.warning("session_test_error", error=str(e)[:100])

    async def _check_sensitive_data(self, page, result: AuthScanResult):
        """Check authenticated pages for sensitive data exposure"""
        sensitive_patterns = [
            (r'\b\d{16}\b', "Credit Card Number", "critical"),
            (r'\b\d{3}-\d{2}-\d{4}\b', "SSN Pattern", "critical"),
            (r'password["\s:=]+["\']([^"\']{6,})["\']',
             "Plaintext Password", "critical"),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
             "Email Address", "low"),
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key", "critical"),
        ]

        for url in result.authenticated_urls[:5]:
            try:
                await page.goto(url, timeout=self.timeout)
                content = await page.content()

                for pattern, data_type, severity in sensitive_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches and data_type != "Email Address":
                        result.findings.append(AuthFinding(
                            vuln_type="Sensitive Data Exposure",
                            severity=severity,
                            url=url,
                            description=(
                                f"{data_type} found in authenticated response"
                            ),
                            evidence=f"Pattern matched: {data_type}",
                            remediation=(
                                "Mask or remove sensitive data from API responses. "
                                "Apply data minimization principles."
                            ),
                            bounty_estimate="$500 - $5,000",
                        ))

            except Exception:
                continue

    def generate_report(self, result: AuthScanResult) -> dict:
        """Generate authenticated scan report"""
        findings_by_severity = {}
        for finding in result.findings:
            sev = finding.severity
            if sev not in findings_by_severity:
                findings_by_severity[sev] = []
            findings_by_severity[sev].append({
                "type": finding.vuln_type,
                "url": finding.url,
                "description": finding.description,
                "evidence": finding.evidence,
                "remediation": finding.remediation,
                "bounty_estimate": finding.bounty_estimate,
            })

        return {
            "target": result.target,
            "timestamp": result.timestamp.isoformat(),
            "login_successful": result.login_successful,
            "authenticated_urls_found": len(result.authenticated_urls),
            "privileged_endpoints": result.privileged_endpoints,
            "total_findings": len(result.findings),
            "findings_by_severity": findings_by_severity,
            "session_cookies": result.session_cookies,
        }


# ── GLOBAL INSTANCE ───────────────────────────────────
auth_scanner = AuthScanner()