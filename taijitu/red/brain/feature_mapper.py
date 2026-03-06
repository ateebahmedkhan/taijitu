# taijitu/red/brain/feature_mapper.py
import os, re, json, requests, structlog
from dataclasses import dataclass, field
from typing import List

log = structlog.get_logger()
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_URL     = "https://api.groq.com/openai/v1/chat/completions"
MODEL        = "moonshotai/kimi-k2-instruct"

def _ask(system, user, max_tokens=2048):
    if not GROQ_API_KEY:
        return ""
    try:
        resp = requests.post(GROQ_URL,
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={"model": MODEL, "max_tokens": max_tokens, "temperature": 0.2,
                  "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]},
            timeout=30)
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"].strip()
        return ""
    except Exception as e:
        log.error("fm_groq_failed", error=str(e)[:100])
        return ""

FEATURE_ATTACKS = {
    "login":          ["auth_bypass", "sql_injection", "default_credentials"],
    "signup":         ["mass_assignment", "username_enumeration"],
    "password_reset": ["token_predictability", "host_header_injection", "token_reuse"],
    "file_upload":    ["unrestricted_upload", "path_traversal", "rce_via_upload", "stored_xss_via_svg"],
    "search":         ["sql_injection", "xss_reflected", "ssti", "nosql_injection"],
    "user_profile":   ["idor", "stored_xss", "mass_assignment"],
    "api_endpoint":   ["bola", "mass_assignment", "jwt_attacks", "broken_function_level_auth"],
    "payment":        ["price_manipulation", "race_condition", "coupon_bypass"],
    "admin_panel":    ["privilege_escalation", "auth_bypass", "idor"],
    "comment_system": ["stored_xss", "html_injection"],
    "redirect":       ["open_redirect", "ssrf", "header_injection"],
    "import_export":  ["xxe", "csv_injection", "path_traversal"],
    "oauth":          ["csrf", "state_bypass", "redirect_uri_manipulation"],
    "websocket":      ["xss_via_websocket", "auth_bypass"],
}

PRIORITIES = {
    "file_upload": 1, "api_endpoint": 1, "admin_panel": 1, "payment": 1,
    "oauth": 2, "password_reset": 2, "login": 2,
    "user_profile": 3, "websocket": 3, "import_export": 3,
    "search": 4, "comment_system": 4,
    "signup": 5, "redirect": 5,
}

@dataclass
class Feature:
    name:       str
    confidence: float
    urls:       List[str] = field(default_factory=list)
    forms:      List[dict] = field(default_factory=list)
    attacks:    List[str] = field(default_factory=list)
    priority:   int = 5
    notes:      str = ""

@dataclass
class AttackPlan:
    target:         str
    features:       List[Feature] = field(default_factory=list)
    ordered_tests:  List[dict]    = field(default_factory=list)
    tech_stack:     List[str]     = field(default_factory=list)
    summary:        str = ""
    estimated_time: int = 0

class FeatureMapper:
    def map(self, target, crawl_result, tech_stack=None):
        log.info("feature_mapping_started", target=target)
        plan = AttackPlan(target=target, tech_stack=tech_stack or [])
        features = self._detect_fast(crawl_result)
        features = self._enrich_cortex(target, crawl_result, features, tech_stack)
        plan.features      = features
        plan.ordered_tests = self._build_plan(features, tech_stack)
        plan.summary       = self._summarize(target, features, tech_stack)
        plan.estimated_time = len(plan.ordered_tests) * 3
        log.info("feature_mapping_complete", features=len(features), tests=len(plan.ordered_tests))
        return plan

    def _detect_fast(self, cr):
        features = {}
        urls    = getattr(cr, "urls_found",    []) or []
        forms   = getattr(cr, "forms",         []) or []
        secrets = getattr(cr, "secrets_found", []) or []

        url_map = {
            "login":          ["/login", "/signin", "/auth"],
            "signup":         ["/signup", "/register", "/join"],
            "password_reset": ["/forgot", "/reset-password", "/recover"],
            "file_upload":    ["/upload", "/import", "/attach"],
            "search":         ["/search", "?q=", "?query=", "?s="],
            "user_profile":   ["/profile", "/user/", "/account", "/me"],
            "api_endpoint":   ["/api/", "/v1/", "/v2/", "/graphql"],
            "payment":        ["/payment", "/checkout", "/billing"],
            "admin_panel":    ["/admin", "/dashboard", "/manage"],
            "comment_system": ["/comment", "/review", "/guestbook"],
            "redirect":       ["redirect=", "url=", "return=", "next="],
            "import_export":  ["/export", "/download", ".csv", ".xml"],
            "oauth":          ["/oauth", "/callback", "code="],
        }
        for url in urls:
            ul = url.lower()
            for fname, patterns in url_map.items():
                if any(p in ul for p in patterns):
                    f = features.setdefault(fname, Feature(
                        name=fname, confidence=0.7,
                        attacks=FEATURE_ATTACKS.get(fname, []),
                        priority=PRIORITIES.get(fname, 5)))
                    if url not in f.urls:
                        f.urls.append(url)
                    f.confidence = min(f.confidence + 0.05, 1.0)

        form_map = {
            "login":          ["password", "passwd", "pwd"],
            "signup":         ["username", "confirm_password"],
            "search":         ["search", "query", "q"],
            "file_upload":    ["file", "upload", "attachment"],
            "comment_system": ["comment", "message", "review"],
            "payment":        ["card", "cvv", "billing"],
        }
        for form in forms:
            names = [i.get("name","").lower() for i in form.get("inputs",[])]
            types = [i.get("type","").lower() for i in form.get("inputs",[])]
            for fname, kws in form_map.items():
                if any(kw in n for kw in kws for n in names) or any(kw in types for kw in kws):
                    f = features.setdefault(fname, Feature(
                        name=fname, confidence=0.8,
                        attacks=FEATURE_ATTACKS.get(fname, []),
                        priority=PRIORITIES.get(fname, 5)))
                    if form not in f.forms:
                        f.forms.append(form)
                    f.confidence = min(f.confidence + 0.15, 1.0)

        if secrets and "api_endpoint" not in features:
            features["api_endpoint"] = Feature(
                name="api_endpoint", confidence=0.6,
                attacks=FEATURE_ATTACKS["api_endpoint"], priority=1,
                notes="API keys found in JS — likely has API endpoints")

        log.info("fast_detection_done", found=list(features.keys()))
        return list(features.values())

    def _enrich_cortex(self, target, cr, features, tech_stack=None):
        urls  = (getattr(cr, "urls_found", []) or [])[:20]
        forms = (getattr(cr, "forms",      []) or [])[:5]
        detected = [f.name for f in features]

        system = "You are a senior bug bounty researcher. Respond in valid JSON only. No markdown."
        user = f"""Target: {target}
Tech: {", ".join(tech_stack or ["Unknown"])}
URLs: {chr(10).join(urls)}
Forms: {json.dumps(forms, indent=2)}
Already detected: {detected}

Find additional attack surfaces NOT in the detected list.
Return JSON array:
[{{"name":"feature_name","confidence":0.0-1.0,"urls":[],"attacks":[],"priority":1-10,"notes":""}}]
Return [] if nothing new."""

        raw = _ask(system, user, max_tokens=1024)
        if not raw:
            return features
        try:
            clean = re.sub(r"```json|```", "", raw).strip()
            for item in json.loads(clean):
                name = item.get("name","")
                if name and name not in detected:
                    features.append(Feature(
                        name=name,
                        confidence=float(item.get("confidence", 0.5)),
                        urls=item.get("urls",[]),
                        attacks=item.get("attacks",[]) or FEATURE_ATTACKS.get(name,[]),
                        priority=int(item.get("priority", 5)),
                        notes=item.get("notes","")))
                    log.info("cortex_added_feature", name=name)
        except Exception as e:
            log.error("cortex_parse_error", error=str(e)[:80])
        return features

    def _build_plan(self, features, tech_stack=None):
        tests = []
        skip  = {"brute_force_protection", "rate_limit_bypass", "email_header_injection"}
        stack = [t.lower() for t in (tech_stack or [])]
        for f in sorted(features, key=lambda x: x.priority):
            for attack in f.attacks:
                if attack in skip:
                    continue
                p = f.priority
                if "php"  in stack and attack == "sql_injection":   p = 1
                if "node" in stack and attack == "nosql_injection":  p = 1
                if "java" in stack and attack == "xxe":              p = 1
                tests.append({"feature": f.name, "attack": attack,
                               "urls": f.urls[:3], "forms": f.forms[:2],
                               "priority": p, "confidence": f.confidence,
                               "notes": f.notes})
        tests.sort(key=lambda t: (t["priority"], -t["confidence"]))
        return tests

    def _summarize(self, target, features, tech_stack=None):
        if not features:
            return f"No significant attack surface on {target}."
        high = [f for f in features if f.priority <= 3]
        names = [f.name for f in features]
        s = f"{target} exposes {len(features)} attack surfaces: {', '.join(names)}. "
        if high:
            s += f"High priority: {', '.join(f.name for f in high)}. "
        if tech_stack:
            s += f"Stack: {', '.join(tech_stack)}."
        return s

feature_mapper = FeatureMapper()
