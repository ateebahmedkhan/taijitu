# taijitu/red/scope_manager.py
# Scope Manager — safety layer for authorized testing
# NEVER tests targets outside defined scope
# One out-of-scope test = permanent ban on bug bounty platforms

import structlog
from datetime import datetime
from dataclasses import dataclass, field
from urllib.parse import urlparse

log = structlog.get_logger()


@dataclass
class BugBountyProgram:
    """A bug bounty program with defined scope"""
    name: str
    platform: str                    # hackerone, bugcrowd, intigriti
    in_scope: list                   # domains/IPs allowed to test
    out_of_scope: list               # explicitly forbidden targets
    vulnerability_types: list        # what types are in scope
    max_severity: str                # max severity they accept
    notes: str = ""
    added_at: datetime = None

    def __post_init__(self):
        if not self.added_at:
            self.added_at = datetime.utcnow()


@dataclass
class ScopeCheck:
    """Result of a scope check"""
    target: str
    is_in_scope: bool
    reason: str
    program: str = ""
    safe_to_test: bool = False


class ScopeManager:
    """
    Scope management and safety system

    Before ANY scan or test:
    1. Check if target is in scope
    2. Check if target is explicitly out of scope
    3. Check if vulnerability type is in scope
    4. Only proceed if all checks pass

    This is not optional — it is hardcoded into
    every RED module to run automatically.

    IMPORTANT: Always read the program's scope page
    before adding it here. Scope changes frequently.
    """

    def __init__(self):
        self.programs: dict = {}
        self.test_log: list = []
        self._add_practice_targets()
        log.info("scope_manager_initialized")

    def add_program(self, program: BugBountyProgram) -> None:
        """Add a bug bounty program to scope manager"""
        self.programs[program.name] = program
        log.info(
            "program_added",
            name=program.name,
            platform=program.platform,
            in_scope_count=len(program.in_scope),
        )

    def check(self, target_url: str) -> ScopeCheck:
        """
        Check if a target is in scope for any program
        MUST be called before any scan or test
        Returns ScopeCheck with is_in_scope and reason
        """
        parsed = urlparse(target_url)
        domain = parsed.netloc or target_url

        # Remove port from domain
        domain = domain.split(":")[0]

        log.info("scope_check", target=domain)

        # Check against all programs
        for program_name, program in self.programs.items():

            # Check explicit out-of-scope first
            for oos in program.out_of_scope:
                if self._matches(domain, oos):
                    result = ScopeCheck(
                        target=target_url,
                        is_in_scope=False,
                        reason=f"Explicitly OUT OF SCOPE in {program_name}: {oos}",
                        program=program_name,
                        safe_to_test=False,
                    )
                    log.warning(
                        "out_of_scope_blocked",
                        target=domain,
                        program=program_name,
                    )
                    self._log_check(result)
                    return result

            # Check in-scope
            for ins in program.in_scope:
                if self._matches(domain, ins):
                    result = ScopeCheck(
                        target=target_url,
                        is_in_scope=True,
                        reason=f"In scope for {program_name}: matches {ins}",
                        program=program_name,
                        safe_to_test=True,
                    )
                    log.info(
                        "target_in_scope",
                        target=domain,
                        program=program_name,
                    )
                    self._log_check(result)
                    return result

        # Not found in any program
        result = ScopeCheck(
            target=target_url,
            is_in_scope=False,
            reason="Target not found in any authorized program scope",
            program="none",
            safe_to_test=False,
        )
        log.warning("target_not_in_scope", target=domain)
        self._log_check(result)
        return result

    def check_vuln_type(
        self,
        program_name: str,
        vuln_type: str,
    ) -> bool:
        """Check if a vulnerability type is in scope for a program"""
        program = self.programs.get(program_name)
        if not program:
            return False

        # If no restrictions specified — all types allowed
        if not program.vulnerability_types:
            return True

        return any(
            vuln_type.lower() in vt.lower()
            for vt in program.vulnerability_types
        )

    def get_in_scope_targets(self, program_name: str) -> list:
        """Get all in-scope targets for a program"""
        program = self.programs.get(program_name)
        if not program:
            return []
        return program.in_scope

    def list_programs(self) -> list:
        """List all registered programs"""
        return [
            {
                "name": p.name,
                "platform": p.platform,
                "in_scope_count": len(p.in_scope),
                "out_of_scope_count": len(p.out_of_scope),
                "added_at": p.added_at.isoformat(),
            }
            for p in self.programs.values()
        ]

    def get_test_log(self) -> list:
        """Get log of all scope checks performed"""
        return [
            {
                "target": c.target,
                "in_scope": c.is_in_scope,
                "reason": c.reason,
                "program": c.program,
            }
            for c in self.test_log
        ]

    def safe_scan(
        self,
        target_url: str,
        scan_function,
        *args,
        **kwargs,
    ):
        """
        Wrapper that checks scope before running any scan
        Use this to wrap all RED module scans

        Example:
            result = scope_manager.safe_scan(
                'https://target.com',
                web_scanner.scan,
                'https://target.com',
            )
        """
        scope_check = self.check(target_url)

        if not scope_check.safe_to_test:
            log.error(
                "scan_blocked_out_of_scope",
                target=target_url,
                reason=scope_check.reason,
            )
            return {
                "error": "OUT OF SCOPE",
                "target": target_url,
                "reason": scope_check.reason,
                "safe_to_test": False,
            }

        log.info(
            "scope_check_passed_proceeding",
            target=target_url,
            program=scope_check.program,
        )
        return scan_function(*args, **kwargs)

    def _matches(self, domain: str, pattern: str) -> bool:
        """
        Check if domain matches a scope pattern
        Supports wildcards: *.example.com
        """
        pattern = pattern.lower().strip()
        domain = domain.lower().strip()

        # Exact match
        if domain == pattern:
            return True

        # Wildcard match — *.example.com
        if pattern.startswith("*."):
            base = pattern[2:]
            if domain == base or domain.endswith(f".{base}"):
                return True

        # Subdomain match — example.com matches sub.example.com
        if domain.endswith(f".{pattern}"):
            return True

        return False

    def _log_check(self, check: ScopeCheck) -> None:
        """Log scope check for audit trail"""
        self.test_log.append(check)

    def _add_practice_targets(self) -> None:
        """
        Add known safe practice targets
        These are deliberately vulnerable apps for testing
        Always safe to test
        """
        practice = BugBountyProgram(
            name="Practice Targets",
            platform="self-hosted",
            in_scope=[
                "testphp.vulnweb.com",
                "testhtml5.vulnweb.com",
                "testasp.vulnweb.com",
                "testaspnet.vulnweb.com",
                "localhost",
                "127.0.0.1",
            ],
            out_of_scope=[],
            vulnerability_types=[],
            max_severity="critical",
            notes="Deliberately vulnerable apps — always safe to test",
        )
        self.add_program(practice)


# ── GLOBAL INSTANCE ───────────────────────────────────
scope_manager = ScopeManager()