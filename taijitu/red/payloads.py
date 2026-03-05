# taijitu/red/payloads.py
# PayloadsAllTheThings integration
# Loads thousands of real-world payloads
# Powers all RED scanner modules

import os
import structlog
from pathlib import Path

log = structlog.get_logger()

# Path to PayloadsAllTheThings
PAYLOADS_DIR = Path(__file__).parent.parent.parent / "data" / "payloads"

# Mapping of vuln type to PayloadsAllTheThings folder
PAYLOAD_MAP = {
    "sql_injection":        "SQL Injection",
    "xss":                  "XSS Injection",
    "ssrf":                 "Server Side Request Forgery",
    "path_traversal":       "Directory Traversal",
    "command_injection":    "Command Injection",
    "xxe":                  "XXE Injection",
    "ssti":                 "Server Side Template Injection",
    "csrf":                 "Cross-Site Request Forgery",
    "cors":                 "CORS Misconfiguration",
    "jwt":                  "JSON Web Token",
    "ldap":                 "LDAP Injection",
    "nosql":                "NoSQL Injection",
    "xpath":                "XPATH Injection",
    "crlf":                 "CRLF Injection",
    "request_smuggling":    "Request Smuggling",
    "account_takeover":     "Account Takeover",
    "idor":                 "Insecure Direct Object References",
    "file_inclusion":       "File Inclusion",
    "upload":               "Upload Insecure Files",
}


class PayloadLoader:
    """
    Loads payloads from PayloadsAllTheThings
    Gives every RED scanner module access to
    thousands of real-world attack payloads

    Instead of 5 hardcoded payloads per vuln type
    TAIJITU RED now has hundreds per type
    """

    def __init__(self):
        self._cache = {}
        self.available = self._check_available()
        if self.available:
            log.info(
                "payload_loader_initialized",
                categories=len(PAYLOAD_MAP),
                path=str(PAYLOADS_DIR),
            )
        else:
            log.warning(
                "payloads_not_found",
                path=str(PAYLOADS_DIR),
                hint="Run: git clone https://github.com/swisskyrepo/PayloadsAllTheThings data/payloads",
            )

    def get(
        self,
        vuln_type: str,
        limit: int = 50,
    ) -> list:
        """
        Get payloads for a vulnerability type
        Returns list of payload strings

        vuln_type: sql_injection, xss, ssrf, etc
        limit: max payloads to return (default 50)
        """
        if not self.available:
            return self._get_fallback(vuln_type)

        # Check cache
        cache_key = f"{vuln_type}_{limit}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        payloads = self._load_payloads(vuln_type, limit)

        # Cache for performance
        self._cache[cache_key] = payloads

        log.info(
            "payloads_loaded",
            vuln_type=vuln_type,
            count=len(payloads),
        )

        return payloads

    def get_all_categories(self) -> list:
        """Get list of all available payload categories"""
        return list(PAYLOAD_MAP.keys())

    def count(self, vuln_type: str) -> int:
        """Count total payloads available for a vuln type"""
        return len(self.get(vuln_type, limit=9999))

    def _load_payloads(
        self,
        vuln_type: str,
        limit: int,
    ) -> list:
        """Load payloads from PayloadsAllTheThings files"""
         # SSRF payloads are better served from curated list
        if vuln_type == "ssrf":
            return self._get_fallback("ssrf")[:limit]
        folder_name = PAYLOAD_MAP.get(vuln_type)
        if not folder_name:
            log.warning("unknown_vuln_type", vuln_type=vuln_type)
            return self._get_fallback(vuln_type)

        folder_path = PAYLOADS_DIR / folder_name
        if not folder_path.exists():
            log.warning("payload_folder_not_found", path=str(folder_path))
            return self._get_fallback(vuln_type)

        payloads = []

        # Read all .md and .txt files in the folder
        for file_path in sorted(folder_path.rglob("*.txt")):
            payloads.extend(self._extract_from_file(file_path))
            if len(payloads) >= limit:
                break

        # If not enough from txt, try extracting from markdown
        if len(payloads) < limit:
            for file_path in sorted(folder_path.rglob("*.md")):
                if "README" in file_path.name:
                    continue
                payloads.extend(self._extract_from_markdown(file_path))
                if len(payloads) >= limit:
                    break

        # Deduplicate and clean
        seen = set()
        clean = []
        for p in payloads:
            p = p.strip()
            if p and p not in seen and len(p) < 500:
                seen.add(p)
                clean.append(p)

        return clean[:limit]

    def _extract_from_file(self, file_path: Path) -> list:
        """Extract payloads from a text file — one per line"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            clean = []
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("#"):
                    continue
                if line.startswith("//"):
                    continue
                if line.startswith("url ="):
                    continue
                if line.startswith("response"):
                    continue
                if line.startswith("return"):
                    continue
                if line.startswith("import"):
                    continue
                if "{" in line or "}" in line:
                    continue
                if len(line) > 200:
                    continue
                # Skip single character or very short fuzzing strings
                if len(line) < 4:
                    continue
                # Skip single words that are not payloads
                if " " not in line and not any(
                    c in line for c in ["'", "\"", "<", ">", "/", "\\", ";", "=", "%", "http"]
                ):
                    continue
                clean.append(line)

            return clean

        except Exception:
            return []

    def _extract_from_markdown(self, file_path: Path) -> list:
        """
        Extract payloads from markdown files
        Looks for code blocks and inline code
        """
        payloads = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Extract code blocks
            in_code_block = False
            for line in content.split("\n"):
                if line.startswith("```"):
                    in_code_block = not in_code_block
                    continue
                if in_code_block:
                    line = line.strip()
                    if line:
                        payloads.append(line)

        except Exception:
            pass

        return payloads

    def _check_available(self) -> bool:
        """Check if PayloadsAllTheThings is downloaded"""
        return PAYLOADS_DIR.exists() and any(PAYLOADS_DIR.iterdir())

    def _get_fallback(self, vuln_type: str) -> list:
        """Fallback payloads when PATT not available"""
        fallbacks = {
            "sql_injection": [
                "'", "\"", "' OR '1'='1",
                "' OR 1=1--", "1 UNION SELECT NULL--",
            ],
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "\"><script>alert(1)</script>",
            ],
            "ssrf": [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://169.254.169.254/latest/user-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/metadata/v1/maintenance",
                "http://localhost/",
                "http://127.0.0.1/",
                "http://0.0.0.0/",
                "http://[::1]/",
                "http://localhost:22/",
                "http://localhost:3306/",
                "http://localhost:6379/",
                "http://localhost:27017/",
                "http://192.168.0.1/",
                "http://10.0.0.1/",
                "dict://localhost:11211/stat",
                "gopher://localhost:6379/_INFO",
                "file:///etc/passwd",
                "file:///etc/hosts",
                "file:///proc/self/environ",
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "....//....//etc/passwd",
                "%2e%2e%2fetc%2fpasswd",
            ],
            "command_injection": [
                "; ls -la",
                "| whoami",
                "`id`",
                "$(id)",
            ],
        }
        return fallbacks.get(vuln_type, [])


# ── GLOBAL INSTANCE ───────────────────────────────────
payload_loader = PayloadLoader()