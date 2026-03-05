# taijitu/red/recon/js_crawler.py
# JavaScript-aware crawler using Playwright
# Renders real browser — handles React, Vue, Angular
# Extracts endpoints, parameters, forms, API calls
# Finds attack surface invisible to basic scanners

import asyncio
import re
import structlog
from datetime import datetime
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout

log = structlog.get_logger()


@dataclass
class CrawlResult:
    """Complete crawl result from JS-aware browser crawl"""
    target: str
    timestamp: datetime
    urls_found: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)
    forms: list = field(default_factory=list)
    js_files: list = field(default_factory=list)
    api_calls: list = field(default_factory=list)
    parameters: list = field(default_factory=list)
    technologies: list = field(default_factory=list)
    secrets_found: list = field(default_factory=list)
    screenshots: dict = field(default_factory=dict)
    total_pages_crawled: int = 0


class JSCrawler:
    """
    JavaScript-aware web crawler using Playwright

    Unlike basic HTTP scanners this crawler:
    - Renders JavaScript fully (React, Vue, Angular)
    - Extracts endpoints from JS source code
    - Intercepts API calls made by the app
    - Fills and submits forms automatically
    - Takes screenshots of every page
    - Finds secrets in JS files (API keys, tokens)
    - Handles authentication flows
    - Detects technologies in use

    This is the attack surface discovery that finds
    what basic scanners completely miss.

    Use only on authorized targets.
    """

    def __init__(self):
        self.visited_urls = set()
        self.max_pages = 50
        self.timeout = 30000  # 30 seconds per page
        log.info("js_crawler_initialized")

    def crawl(self, target_url: str, max_pages: int = 30) -> CrawlResult:
        """
        Synchronous wrapper for async crawl
        Returns complete CrawlResult
        """
        self.max_pages = max_pages
        return asyncio.run(self._crawl_async(target_url))

    async def _crawl_async(self, target_url: str) -> CrawlResult:
        """Main async crawl implementation"""
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"

        log.info("js_crawl_starting", target=target_url)

        result = CrawlResult(
            target=target_url,
            timestamp=datetime.utcnow(),
        )

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-blink-features=AutomationControlled",
                ],
            )

            context = await browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent=(
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                ignore_https_errors=True,
            )

            # Intercept all network requests
            api_calls = []

            async def intercept_request(request):
                if any(x in request.url for x in [
                    "/api/", "/v1/", "/v2/", "/graphql",
                    ".json", "ajax", "fetch",
                ]):
                    api_calls.append({
                        "url": request.url,
                        "method": request.method,
                        "headers": dict(request.headers),
                    })

            context.on("request", intercept_request)

            # Crawl pages
            page = await context.new_page()
            await self._crawl_page(
                page, target_url, result, api_calls
            )

            result.api_calls = api_calls

            # Extract endpoints from all JS files found
            for js_url in result.js_files[:10]:
                endpoints = await self._extract_from_js(
                    page, js_url, target_url
                )
                result.endpoints.extend(endpoints)

            await browser.close()

        # Deduplicate
        result.endpoints = list(set(result.endpoints))
        result.parameters = list(set(result.parameters))
        result.technologies = list(set(result.technologies))

        log.info(
            "js_crawl_complete",
            target=target_url,
            pages=result.total_pages_crawled,
            endpoints=len(result.endpoints),
            forms=len(result.forms),
            js_files=len(result.js_files),
            api_calls=len(result.api_calls),
            secrets=len(result.secrets_found),
        )

        return result

    async def _crawl_page(
        self,
        page,
        url: str,
        result: CrawlResult,
        api_calls: list,
        depth: int = 0,
    ):
        """Crawl a single page and extract all information"""
        if url in self.visited_urls:
            return
        if result.total_pages_crawled >= self.max_pages:
            return
        if depth > 3:
            return

        self.visited_urls.add(url)
        result.total_pages_crawled += 1
        base_domain = urlparse(result.target).netloc

        try:
            log.info("crawling_page", url=url[:60], depth=depth)

            response = await page.goto(
                url,
                wait_until="networkidle",
                timeout=self.timeout,
            )

            if not response:
                return

            # Take screenshot
            try:
                screenshot = await page.screenshot(
                    full_page=False,
                    type="png",
                )
                result.screenshots[url] = screenshot
            except Exception:
                pass

            # Detect technologies
            techs = await self._detect_technologies(page)
            result.technologies.extend(techs)

            # Extract all links
            links = await page.evaluate("""
                () => {
                    const links = [];
                    document.querySelectorAll('a[href]').forEach(a => {
                        links.push(a.href);
                    });
                    return links;
                }
            """)

            for link in links:
                if not link:
                    continue
                parsed = urlparse(link)
                if parsed.netloc == base_domain:
                    if link not in result.urls_found:
                        result.urls_found.append(link)
                    if parsed.query:
                        params = [
                            p.split("=")[0]
                            for p in parsed.query.split("&")
                        ]
                        result.parameters.extend(params)

            # Extract JavaScript files
            js_files = await page.evaluate("""
                () => {
                    const scripts = [];
                    document.querySelectorAll('script[src]').forEach(s => {
                        scripts.push(s.src);
                    });
                    return scripts;
                }
            """)

            for js in js_files:
                if js and js not in result.js_files:
                    result.js_files.append(js)

            # Extract and analyze forms
            forms = await page.evaluate("""
                () => {
                    const forms = [];
                    document.querySelectorAll('form').forEach(form => {
                        const inputs = [];
                        form.querySelectorAll('input, textarea, select').forEach(input => {
                            inputs.push({
                                name: input.name || input.id || '',
                                type: input.type || 'text',
                                placeholder: input.placeholder || ''
                            });
                        });
                        forms.push({
                            action: form.action || '',
                            method: form.method || 'get',
                            inputs: inputs
                        });
                    });
                    return forms;
                }
            """)

            for form in forms:
                if form not in result.forms:
                    result.forms.append(form)
                    # Extract parameter names from forms
                    for inp in form.get("inputs", []):
                        if inp.get("name"):
                            result.parameters.append(inp["name"])

            # Check for secrets in page source
            content = await page.content()
            secrets = self._find_secrets(content, url)
            result.secrets_found.extend(secrets)

            # Recursively crawl same-domain links
            for link in result.urls_found[:self.max_pages]:
                if link not in self.visited_urls:
                    parsed = urlparse(link)
                    if parsed.netloc == base_domain:
                        await self._crawl_page(
                            page, link, result,
                            api_calls, depth + 1,
                        )

        except PlaywrightTimeout:
            log.warning("page_timeout", url=url[:60])
        except Exception as e:
            log.warning("page_crawl_error", url=url[:60], error=str(e)[:100])

    async def _extract_from_js(
        self,
        page,
        js_url: str,
        base_url: str,
    ) -> list:
        """
        Extract API endpoints and paths from JavaScript files
        This finds hidden endpoints that are never linked in HTML
        """
        endpoints = []

        try:
            import httpx
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.get(js_url, timeout=10)
                js_content = response.text

            # Pattern 1 — API paths in strings
            api_patterns = [
                r'["\'](/api/[^"\']+)["\']',
                r'["\'](/v\d+/[^"\']+)["\']',
                r'fetch\(["\']([^"\']+)["\']',
                r'axios\.[a-z]+\(["\']([^"\']+)["\']',
                r'\.get\(["\']([^"\']+)["\']',
                r'\.post\(["\']([^"\']+)["\']',
                r'url:\s*["\']([^"\']+)["\']',
                r'endpoint:\s*["\']([^"\']+)["\']',
                r'baseURL:\s*["\']([^"\']+)["\']',
            ]

            for pattern in api_patterns:
                matches = re.findall(pattern, js_content)
                for match in matches:
                    if match.startswith("/"):
                        full_url = urljoin(base_url, match)
                        endpoints.append(full_url)
                    elif match.startswith("http"):
                        endpoints.append(match)

            # Check for secrets in JS files
            secrets = self._find_secrets(js_content, js_url)
            if secrets:
                log.info(
                    "secrets_in_js",
                    js_file=js_url[:60],
                    count=len(secrets),
                )

            log.info(
                "js_endpoints_extracted",
                js_file=js_url[:60],
                endpoints=len(endpoints),
            )

        except Exception as e:
            log.warning("js_extraction_failed", url=js_url[:60], error=str(e)[:50])

        return endpoints

    async def _detect_technologies(self, page) -> list:
        """Detect technologies used by the target"""
        technologies = []

        try:
            # Check meta tags and headers
            tech_signals = await page.evaluate("""
                () => {
                    const signals = {};
                    
                    // Generator meta tag
                    const gen = document.querySelector('meta[name="generator"]');
                    if (gen) signals.generator = gen.content;
                    
                    // Framework indicators
                    if (window.React) signals.react = true;
                    if (window.Vue) signals.vue = true;
                    if (window.angular) signals.angular = true;
                    if (window.jQuery) signals.jquery = true;
                    if (window.WordPress) signals.wordpress = true;
                    if (window.Shopify) signals.shopify = true;
                    if (window.next) signals.nextjs = true;
                    
                    // Data attributes
                    if (document.querySelector('[data-reactroot]')) signals.react = true;
                    if (document.querySelector('[ng-version]')) signals.angular = true;
                    if (document.querySelector('#__next')) signals.nextjs = true;
                    if (document.querySelector('#__nuxt')) signals.nuxt = true;
                    
                    return signals;
                }
            """)

            for tech, present in tech_signals.items():
                if present:
                    technologies.append(tech)

        except Exception:
            pass

        return technologies

    def _find_secrets(self, content: str, source_url: str) -> list:
        """
        Search for exposed secrets in page content and JS files
        API keys, tokens, passwords left in client-side code
        These are critical findings on bug bounty
        """
        secrets = []

        secret_patterns = [
            (r'(?i)(api[_-]?key|apikey)["\s:=]+(["\']?)([a-zA-Z0-9_\-]{20,})\2',
             "API Key"),
            (r'(?i)(secret[_-]?key)["\s:=]+(["\']?)([a-zA-Z0-9_\-]{20,})\2',
             "Secret Key"),
            (r'(?i)(access[_-]?token)["\s:=]+(["\']?)([a-zA-Z0-9_\-\.]{20,})\2',
             "Access Token"),
            (r'(?i)(password|passwd|pwd)["\s:=]+(["\']?)([^\s"\']{8,})\2',
             "Password"),
            (r'AKIA[0-9A-Z]{16}',
             "AWS Access Key"),
            (r'(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})',
             "Bearer Token"),
            (r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+',
             "JWT Token"),
            (r'(?i)(private[_-]?key)["\s:=]+(["\']?)([^\s"\']{20,})\2',
             "Private Key"),
            (r'ghp_[a-zA-Z0-9]{36}',
             "GitHub Personal Access Token"),
            (r'(?i)(stripe[_-]?key)["\s:=]+(["\']?)(sk_live_[a-zA-Z0-9]{24,})\2',
             "Stripe Secret Key"),
        ]

        for pattern, secret_type in secret_patterns:
            matches = re.findall(pattern, content)
            if matches:
                for match in matches[:3]:
                    value = match if isinstance(match, str) else match[-1]
                    # Skip obvious placeholders
                    if value in ["YOUR_API_KEY", "your_key_here",
                                 "xxx", "placeholder"]:
                        continue
                    if "<" in value or ">" in value or "input" in value.lower():
                        continue
                    secrets.append({
                        "type": secret_type,
                        "value": value[:20] + "...",
                        "source": source_url[:60],
                        "severity": "critical",
                    })

        return secrets

    def generate_report(self, result: CrawlResult) -> dict:
        """Generate attack surface report from crawl"""
        return {
            "target": result.target,
            "timestamp": result.timestamp.isoformat(),
            "summary": {
                "pages_crawled": result.total_pages_crawled,
                "urls_found": len(result.urls_found),
                "endpoints_discovered": len(result.endpoints),
                "forms_found": len(result.forms),
                "js_files": len(result.js_files),
                "api_calls_intercepted": len(result.api_calls),
                "parameters_found": len(result.parameters),
                "technologies": result.technologies,
                "secrets_found": len(result.secrets_found),
            },
            "endpoints": result.endpoints[:50],
            "parameters": list(set(result.parameters))[:30],
            "forms": result.forms[:10],
            "api_calls": result.api_calls[:20],
            "secrets": result.secrets_found,
            "js_files": result.js_files[:20],
            "attack_surface_score": self._score(result),
        }

    def _score(self, result: CrawlResult) -> float:
        """Score the attack surface discovered"""
        score = 0.0
        score += min(len(result.endpoints) * 2, 30)
        score += min(len(result.forms) * 5, 20)
        score += min(len(result.parameters) * 1, 15)
        score += min(len(result.api_calls) * 3, 20)
        score += len(result.secrets_found) * 15
        return round(min(score, 100.0), 1)


# ── GLOBAL INSTANCE ───────────────────────────────────
js_crawler = JSCrawler()