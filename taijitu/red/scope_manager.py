# taijitu/red/scope_manager.py
# Scope Manager — safety layer for authorized testing
# Programs persist to disk — survive restarts
# NEVER tests targets outside defined scope

import json
import os
import structlog
from datetime import datetime
from dataclasses import dataclass, field
from urllib.parse import urlparse

log = structlog.get_logger()

# Persist programs here — survives restarts
SCOPE_FILE = os.path.expanduser("~/.taijitu/scope.json")


@dataclass
class BugBountyProgram:
    name:                str
    platform:            str
    in_scope:            list = field(default_factory=list)
    out_of_scope:        list = field(default_factory=list)
    vulnerability_types: list = field(default_factory=list)
    max_severity:        str  = "critical"
    notes:               str  = ""
    added_at:            str  = ""

    def __post_init__(self):
        if not self.added_at:
            self.added_at = datetime.utcnow().isoformat()

    def to_dict(self):
        return {
            "name":                self.name,
            "platform":            self.platform,
            "in_scope":            self.in_scope,
            "out_of_scope":        self.out_of_scope,
            "vulnerability_types": self.vulnerability_types,
            "max_severity":        self.max_severity,
            "notes":               self.notes,
            "added_at":            self.added_at,
        }

    @classmethod
    def from_dict(cls, d):
        return cls(
            name=d.get("name", ""),
            platform=d.get("platform", ""),
            in_scope=d.get("in_scope", []),
            out_of_scope=d.get("out_of_scope", []),
            vulnerability_types=d.get("vulnerability_types", []),
            max_severity=d.get("max_severity", "critical"),
            notes=d.get("notes", ""),
            added_at=d.get("added_at", ""),
        )


@dataclass
class ScopeCheck:
    target:       str
    is_in_scope:  bool
    reason:       str
    program:      str  = ""
    safe_to_test: bool = False


class ScopeManager:
    """
    Scope management and safety system.
    Programs persist to ~/.taijitu/scope.json
    Survives restarts — no re-entry needed.
    """

    def __init__(self):
        self.programs:       dict = {}
        self.current_program = None
        self.test_log:  list = []
        self._ensure_dir()
        self._add_practice_targets()
        self._load()
        log.info("scope_manager_initialized",
                 programs=len(self.programs))

    def _ensure_dir(self):
        os.makedirs(os.path.dirname(SCOPE_FILE), exist_ok=True)

    def _load(self):
        """Load programs from disk"""
        if not os.path.exists(SCOPE_FILE):
            return
        try:
            with open(SCOPE_FILE) as f:
                data = json.load(f)
            for d in data.get("programs", []):
                p = BugBountyProgram.from_dict(d)
                if p.name not in self.programs:
                    self.programs[p.name] = p
            log.info("scope_loaded",
                     programs=len(self.programs))
        except Exception as e:
            log.error("scope_load_error", error=str(e))

    def _save(self):
        """Persist programs to disk"""
        try:
            # Don't save practice targets
            to_save = [
                p.to_dict()
                for p in self.programs.values()
                if p.platform != "self-hosted"
            ]
            with open(SCOPE_FILE, "w") as f:
                json.dump({"programs": to_save}, f, indent=2)
            log.info("scope_saved", programs=len(to_save))
        except Exception as e:
            log.error("scope_save_error", error=str(e))

    def add_program(self, program: BugBountyProgram):
        self.programs[program.name] = program
        self._save()
        log.info("program_added",
                 name=program.name,
                 platform=program.platform,
                 in_scope_count=len(program.in_scope))

    def check(self, target_url: str) -> ScopeCheck:
        parsed = urlparse(target_url)
        domain = parsed.netloc or target_url
        domain = domain.split(":")[0].lower().strip()

        log.info("scope_check", target=domain)

        for program_name, program in self.programs.items():

            # Out of scope check first
            for oos in program.out_of_scope:
                if self._matches(domain, oos):
                    result = ScopeCheck(
                        target=target_url,
                        is_in_scope=False,
                        reason=f"OUT OF SCOPE in {program_name}: {oos}",
                        program=program_name,
                        safe_to_test=False,
                    )
                    log.warning("out_of_scope_blocked",
                                target=domain,
                                program=program_name)
                    self._log_check(result)
                    return result

            # In scope check
            for ins in program.in_scope:
                # Handle dict entries from HackerOne API
                if isinstance(ins, dict):
                    asset = ins.get("asset", "")
                else:
                    asset = ins

                if self._matches(domain, asset):
                    result = ScopeCheck(
                        target=target_url,
                        is_in_scope=True,
                        reason=f"In scope: {program_name} — {asset}",
                        program=program_name,
                        safe_to_test=True,
                    )
                    log.info("target_in_scope",
                             target=domain,
                             program=program_name)
                    self._log_check(result)
                    return result

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

    def check_vuln_type(self, program_name, vuln_type):
        program = self.programs.get(program_name)
        if not program:
            return False
        if not program.vulnerability_types:
            return True
        return any(
            vuln_type.lower() in vt.lower()
            for vt in program.vulnerability_types
        )

    def get_in_scope_targets(self, program_name):
        program = self.programs.get(program_name)
        if not program:
            return []
        return program.in_scope

    def list_programs(self):
        return [
            {
                "name":            p.name,
                "platform":        p.platform,
                "in_scope_count":  len(p.in_scope),
                "out_of_scope_count": len(p.out_of_scope),
                "added_at":        p.added_at,
            }
            for p in self.programs.values()
        ]

    def safe_scan(self, target_url, scan_function, *args, **kwargs):
        scope_check = self.check(target_url)
        if not scope_check.safe_to_test:
            log.error("scan_blocked_out_of_scope",
                      target=target_url,
                      reason=scope_check.reason)
            return {
                "error":        "OUT OF SCOPE",
                "target":       target_url,
                "reason":       scope_check.reason,
                "safe_to_test": False,
            }
        return scan_function(*args, **kwargs)

    def _matches(self, domain: str, pattern: str) -> bool:
        """
        Match domain against scope pattern.
        Supports:
          *.example.com  — any subdomain
          example.com    — exact + subdomains
          https://...    — strips protocol first
        """
        # Strip protocol if present
        if "://" in pattern:
            pattern = pattern.split("://")[1]

        # Strip paths
        pattern = pattern.split("/")[0]
        pattern = pattern.lower().strip()
        domain  = domain.lower().strip()

        if not pattern:
            return False

        # Exact match
        if domain == pattern:
            return True

        # Wildcard *.example.com
        if pattern.startswith("*."):
            base = pattern[2:]
            if domain == base or domain.endswith(f".{base}"):
                return True

        # Pattern is bare domain — match subdomains too
        if domain.endswith(f".{pattern}"):
            return True

        return False

    def _log_check(self, check: ScopeCheck):
        self.test_log.append(check)

    def get_test_log(self):
        return [
            {
                "target":    c.target,
                "in_scope":  c.is_in_scope,
                "reason":    c.reason,
                "program":   c.program,
            }
            for c in self.test_log
        ]

    def _add_practice_targets(self):
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
            notes="Deliberately vulnerable apps — safe to test",
        )
        self.programs[practice.name] = practice


# ── GLOBAL INSTANCE ───────────────────────────────────
scope_manager = ScopeManager()