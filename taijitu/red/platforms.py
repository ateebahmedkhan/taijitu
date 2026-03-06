# taijitu/red/platforms.py
# Bug Bounty Platform Integrations
# HackerOne, Bugcrowd, Intigriti API clients
# Reads program scope, assets, restrictions automatically
# Use only on programs you are authorized to test

import os
import re
import requests
import structlog
from dataclasses import dataclass, field
from typing import Optional

log = structlog.get_logger()
requests.packages.urllib3.disable_warnings()


@dataclass
class PlatformProgram:
    """Complete bug bounty program details from platform API"""
    name:               str
    handle:             str
    platform:           str
    url:                str
    in_scope:           list = field(default_factory=list)
    out_of_scope:       list = field(default_factory=list)
    asset_types:        list = field(default_factory=list)
    vulnerability_types: list = field(default_factory=list)
    offers_bounties:    bool = False
    min_bounty:         int  = 0
    max_bounty:         int  = 0
    requires_account:   bool = False
    testing_notes:      str  = ""
    response_time:      str  = ""
    managed:            bool = False


class HackerOneClient:
    """
    HackerOne API client
    Reads program scope, assets, restrictions
    Free — requires HackerOne account + API token

    Credentials loaded from environment:
      HACKERONE_USERNAME
      HACKERONE_API_TOKEN
    """

    BASE = "https://api.hackerone.com/v1"

    def __init__(self):
        self.username  = os.environ.get("HACKERONE_USERNAME", "")
        self.api_token = os.environ.get("HACKERONE_API_TOKEN", "")
        self.session   = requests.Session()

        if self.username and self.api_token:
            self.session.auth = (self.username, self.api_token)
            self.authenticated = True
            log.info("hackerone_client_initialized",
                     username=self.username)
        else:
            self.authenticated = False
            log.warning("hackerone_no_credentials")

    def get_program(self, handle: str) -> Optional[PlatformProgram]:
        """
        Fetch full program details by handle
        handle = the program name in the URL
        e.g. hackerone.com/google → handle = 'google'
        """
        if not self.authenticated:
            log.error("hackerone_not_authenticated")
            return None

        try:
            log.info("fetching_program", handle=handle)

            # Get program details
            resp = self.session.get(
                f"{self.BASE}/hackers/programs/{handle}",
                timeout=15,
            )

            if resp.status_code == 401:
                log.error("hackerone_unauthorized")
                return None

            if resp.status_code == 404:
                log.error("hackerone_program_not_found",
                          handle=handle)
                return None

            if resp.status_code != 200:
                log.error("hackerone_api_error",
                          status=resp.status_code)
                return None

            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})

            program = PlatformProgram(
                name=attrs.get("name", handle),
                handle=handle,
                platform="hackerone",
                url=f"https://hackerone.com/{handle}",
                offers_bounties=attrs.get("offers_bounties", False),
                managed=attrs.get("managed_program", False),
                response_time=str(
                    attrs.get("mean_time_to_first_response_in_days", "")
                ),
            )

            # Get structured scope
            scope_resp = self.session.get(
                f"{self.BASE}/hackers/programs/{handle}"
                f"/structured_scopes",
                timeout=15,
            )

            if scope_resp.status_code == 200:
                scope_data = scope_resp.json()
                for item in scope_data.get("data", []):
                    a = item.get("attributes", {})
                    asset = a.get("asset_identifier", "")
                    asset_type = a.get("asset_type", "")
                    eligible = a.get("eligible_for_bounty", False)
                    eligible_submission = a.get(
                        "eligible_for_submission", True
                    )
                    instruction = a.get("instruction", "")

                    if not asset:
                        continue

                    scope_entry = {
                        "asset":        asset,
                        "type":         asset_type,
                        "bounty":       eligible,
                        "submittable":  eligible_submission,
                        "notes":        instruction[:200] if instruction else "",
                    }

                    if eligible_submission:
                        program.in_scope.append(scope_entry)
                    else:
                        program.out_of_scope.append(scope_entry)

                    if asset_type not in program.asset_types:
                        program.asset_types.append(asset_type)

            # Detect if program needs account creation
            web_assets = [
                s for s in program.in_scope
                if s["type"] in ("URL", "WILDCARD", "DOMAIN")
            ]
            if web_assets:
                program.requires_account = True
                program.testing_notes = (
                    "Web application targets detected. "
                    "Create a dedicated test account before "
                    "testing authenticated endpoints. "
                    "Never use real user accounts."
                )

            # Bounty range from scope
            bounty_assets = [
                s for s in program.in_scope if s["bounty"]
            ]
            program.min_bounty = 0
            program.max_bounty = 0

            log.info(
                "program_fetched",
                handle=handle,
                in_scope=len(program.in_scope),
                out_of_scope=len(program.out_of_scope),
                bounty=program.offers_bounties,
            )

            return program

        except Exception as e:
            log.error("hackerone_fetch_error", error=str(e)[:100])
            return None

    def search_programs(
        self,
        query: str = "",
        limit: int = 10,
    ) -> list:
        """
        Search for bug bounty programs by name
        Returns list of matching programs
        """
        if not self.authenticated:
            return []

        try:
            params = {
                "page[size]": limit,
            }
            if query:
                params["filter[name__contains]"] = query

            resp = self.session.get(
                f"{self.BASE}/hackers/programs",
                params=params,
                timeout=15,
            )

            if resp.status_code != 200:
                return []

            data = resp.json()
            programs = []

            for item in data.get("data", []):
                a    = item.get("attributes", {})
                handle = a.get("handle", "")
                programs.append({
                    "name":    a.get("name", handle),
                    "handle":  handle,
                    "bounty":  a.get("offers_bounties", False),
                    "managed": a.get("managed_program", False),
                    "url":     f"https://hackerone.com/{handle}",
                })

            log.info("programs_searched",
                     query=query, found=len(programs))
            return programs

        except Exception as e:
            log.error("search_error", error=str(e)[:100])
            return []

    def get_my_programs(self) -> list:
        """Get programs the researcher has joined"""
        return self.search_programs(limit=25)


def parse_url_to_handle(url: str) -> tuple:
    """
    Extract platform and handle from bug bounty URL

    Examples:
    hackerone.com/google          → ('hackerone', 'google')
    bugcrowd.com/tesla            → ('bugcrowd', 'tesla')
    intigriti.com/programs/adobe  → ('intigriti', 'adobe')
    """
    url = url.strip().rstrip("/")

    if "hackerone.com" in url:
        parts = url.split("hackerone.com/")
        if len(parts) > 1:
            handle = parts[1].split("/")[0].split("?")[0]
            return ("hackerone", handle)

    if "bugcrowd.com" in url:
        parts = url.split("bugcrowd.com/")
        if len(parts) > 1:
            handle = parts[1].split("/")[0].split("?")[0]
            return ("bugcrowd", handle)

    if "intigriti.com" in url:
        parts = url.split("programs/")
        if len(parts) > 1:
            handle = parts[1].split("/")[0].split("?")[0]
            return ("intigriti", handle)

    if "yeswehack.com" in url:
        parts = url.split("programs/")
        if len(parts) > 1:
            handle = parts[1].split("/")[0].split("?")[0]
            return ("yeswehack", handle)

    return (None, None)


def load_program_from_url(url: str) -> Optional[PlatformProgram]:
    """
    Main entry point — load program from any platform URL
    Detects platform, fetches scope, returns PlatformProgram
    """
    platform, handle = parse_url_to_handle(url)

    if not platform or not handle:
        log.error("cannot_parse_url", url=url)
        return None

    log.info("loading_program", platform=platform, handle=handle)

    if platform == "hackerone":
        client = HackerOneClient()
        return client.get_program(handle)

    # Future: Bugcrowd, Intigriti clients
    log.warning("platform_not_yet_supported", platform=platform)
    return None


# ── GLOBAL INSTANCES ─────────────────────────────────
hackerone = HackerOneClient()