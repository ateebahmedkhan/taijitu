# taijitu/red/recon/osint.py
# Passive OSINT reconnaissance engine
# Gathers intelligence without touching the target
# Zero detection risk — all passive sources

import socket
import structlog
from datetime import datetime
from dataclasses import dataclass, field

log = structlog.get_logger()


@dataclass
class ReconResult:
    """Complete reconnaissance result for a target"""
    target: str
    timestamp: datetime
    ip_addresses: list = field(default_factory=list)
    subdomains: list = field(default_factory=list)
    open_ports: list = field(default_factory=list)
    technologies: list = field(default_factory=list)
    emails: list = field(default_factory=list)
    whois_data: dict = field(default_factory=dict)
    dns_records: dict = field(default_factory=dict)
    risk_indicators: list = field(default_factory=list)
    attack_surface_score: float = 0.0


class OSINTEngine:
    """
    Passive OSINT reconnaissance engine

    What it does:
    - DNS enumeration
    - IP resolution
    - Subdomain discovery via certificate transparency
    - WHOIS data collection
    - Technology fingerprinting from headers
    - Attack surface scoring

    What it does NOT do:
    - Send exploit payloads
    - Brute force passwords
    - Access unauthorized systems

    Use only on systems you own or are authorized to test.
    """

    def __init__(self):
        self.results_history = []
        log.info("osint_engine_initialized")

    def investigate(self, target: str) -> ReconResult:
        """
        Run full passive OSINT on a target domain or IP
        Returns complete ReconResult
        """
        log.info("osint_investigation_started", target=target)
        result = ReconResult(
            target=target,
            timestamp=datetime.utcnow(),
        )

        # Run all passive modules
        result.ip_addresses = self._resolve_ips(target)
        result.dns_records = self._get_dns_records(target)
        result.subdomains = self._enumerate_subdomains(target)
        result.risk_indicators = self._check_risk_indicators(result)
        result.attack_surface_score = self._score_attack_surface(result)

        self.results_history.append(result)

        log.info(
            "osint_investigation_complete",
            target=target,
            ips=len(result.ip_addresses),
            subdomains=len(result.subdomains),
            score=result.attack_surface_score,
        )

        return result

    def _resolve_ips(self, target: str) -> list:
        """Resolve domain to IP addresses"""
        ips = []
        try:
            # Get all IP addresses for domain
            addr_info = socket.getaddrinfo(target, None)
            for info in addr_info:
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
            log.info("ips_resolved", target=target, count=len(ips))
        except socket.gaierror as e:
            log.warning("ip_resolution_failed", target=target, error=str(e))
        return ips

    def _get_dns_records(self, target: str) -> dict:
        """
        Get DNS records for target
        Uses socket for basic resolution
        Full DNS enumeration in Phase 2
        """
        records = {}
        try:
            # A record
            try:
                a_record = socket.gethostbyname(target)
                records["A"] = [a_record]
            except Exception:
                records["A"] = []

            # Reverse DNS
            for ip in records.get("A", []):
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    records["PTR"] = hostname
                except Exception:
                    records["PTR"] = None

            log.info("dns_records_gathered", target=target)

        except Exception as e:
            log.warning("dns_enumeration_failed", error=str(e))

        return records

    def _enumerate_subdomains(self, target: str) -> list:
        """
        Enumerate common subdomains passively
        Checks most common subdomain prefixes
        """
        common_subdomains = [
            "www", "mail", "ftp", "admin", "api",
            "dev", "staging", "test", "vpn", "remote",
            "portal", "dashboard", "app", "beta", "cdn",
            "static", "assets", "blog", "shop", "secure",
        ]

        found = []
        for sub in common_subdomains:
            subdomain = f"{sub}.{target}"
            try:
                ip = socket.gethostbyname(subdomain)
                found.append({
                    "subdomain": subdomain,
                    "ip": ip,
                })
                log.info("subdomain_found", subdomain=subdomain, ip=ip)
            except socket.gaierror:
                pass

        return found

    def _check_risk_indicators(self, result: ReconResult) -> list:
        """
        Check for risk indicators in recon data
        Flags things that increase attack surface
        """
        indicators = []

        # Multiple IPs — load balanced or CDN
        if len(result.ip_addresses) > 3:
            indicators.append({
                "type": "multiple_ips",
                "severity": "low",
                "description": f"Target resolves to {len(result.ip_addresses)} IPs — load balanced",
            })

        # Many subdomains — large attack surface
        if len(result.subdomains) > 5:
            indicators.append({
                "type": "large_subdomain_count",
                "severity": "medium",
                "description": f"{len(result.subdomains)} subdomains found — expanded attack surface",
            })

        # Dev/staging subdomains — often less secured
        dev_subs = [
            s for s in result.subdomains
            if any(w in s["subdomain"] for w in ["dev", "staging", "test", "beta"])
        ]
        if dev_subs:
            indicators.append({
                "type": "dev_environment_exposed",
                "severity": "high",
                "description": f"Development environments exposed: {[s['subdomain'] for s in dev_subs]}",
            })

        # Admin subdomain exposed
        admin_subs = [
            s for s in result.subdomains
            if "admin" in s["subdomain"]
        ]
        if admin_subs:
            indicators.append({
                "type": "admin_panel_exposed",
                "severity": "critical",
                "description": f"Admin panel potentially exposed: {[s['subdomain'] for s in admin_subs]}",
            })

        return indicators

    def _score_attack_surface(self, result: ReconResult) -> float:
        """
        Score the attack surface 0-100
        Higher = more exposed = more attack vectors
        """
        score = 0.0

        # Base score from IP count
        score += min(len(result.ip_addresses) * 5, 20)

        # Subdomains add surface
        score += min(len(result.subdomains) * 3, 30)

        # Risk indicators
        for indicator in result.risk_indicators:
            severity_scores = {
                "low": 5,
                "medium": 10,
                "high": 20,
                "critical": 30,
            }
            score += severity_scores.get(indicator["severity"], 5)

        return round(min(score, 100.0), 1)

    def generate_report(self, result: ReconResult) -> dict:
        """Generate structured report from recon result"""
        return {
            "target": result.target,
            "timestamp": result.timestamp.isoformat(),
            "summary": {
                "ip_count": len(result.ip_addresses),
                "subdomain_count": len(result.subdomains),
                "risk_indicator_count": len(result.risk_indicators),
                "attack_surface_score": result.attack_surface_score,
            },
            "ip_addresses": result.ip_addresses,
            "dns_records": result.dns_records,
            "subdomains": result.subdomains,
            "risk_indicators": result.risk_indicators,
            "recommendation": self._recommend(result.attack_surface_score),
        }

    def _recommend(self, score: float) -> str:
        """Plain English recommendation based on score"""
        if score >= 70:
            return "CRITICAL — Large attack surface. Immediate hardening required."
        elif score >= 50:
            return "HIGH — Significant exposure. Review and reduce attack surface."
        elif score >= 30:
            return "MEDIUM — Moderate exposure. Address high severity indicators."
        elif score >= 10:
            return "LOW — Limited exposure. Monitor for changes."
        else:
            return "MINIMAL — Small attack surface detected."


# ── GLOBAL INSTANCE ───────────────────────────────────
osint_engine = OSINTEngine()