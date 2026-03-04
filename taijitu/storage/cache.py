# taijitu/storage/cache.py
# Redis cache layer
# Hot data lives here — attacker profiles, recent events
# Redis responds in microseconds vs database milliseconds

import json
import redis
import structlog

from taijitu.config import settings

# ── LOGGING ───────────────────────────────────────────
log = structlog.get_logger()

# ── REDIS CONNECTION ──────────────────────────────────
redis_client = redis.from_url(
    settings.redis_url,
    decode_responses=True,    # Return strings not bytes
    socket_connect_timeout=5, # Fail fast if Redis is down
)

# ── CACHE EXPIRY TIMES ────────────────────────────────
ATTACKER_PROFILE_TTL = 3600      # 1 hour — refresh often
RECENT_EVENTS_TTL = 300          # 5 minutes
SYSTEM_STATS_TTL = 60            # 1 minute


def check_connection() -> bool:
    """
    Test if Redis is reachable
    Returns True if connected, False if not
    """
    try:
        redis_client.ping()
        log.info("redis_connection_ok")
        return True
    except redis.ConnectionError as e:
        log.error("redis_unreachable", error=str(e))
        return False


# ── ATTACKER PROFILE CACHE ────────────────────────────

def get_attacker_profile(ip: str) -> dict | None:
    """
    Get attacker profile from cache
    Returns the profile dict or None if not cached
    """
    key = f"attacker:{ip}"
    data = redis_client.get(key)
    if data:
        log.info("cache_hit", key=key)
        return json.loads(data)
    log.info("cache_miss", key=key)
    return None


def set_attacker_profile(ip: str, profile: dict) -> None:
    """
    Save attacker profile to cache
    Expires after 1 hour — keeps data fresh
    """
    key = f"attacker:{ip}"
    redis_client.setex(
        key,
        ATTACKER_PROFILE_TTL,
        json.dumps(profile, default=str)
    )
    log.info("cache_set", key=key)


def delete_attacker_profile(ip: str) -> None:
    """
    Remove attacker profile from cache
    Called when profile is updated in database
    """
    key = f"attacker:{ip}"
    redis_client.delete(key)
    log.info("cache_deleted", key=key)


# ── RECENT EVENTS CACHE ───────────────────────────────

def get_recent_events() -> list | None:
    """
    Get recent threat events from cache
    Used by dashboard to avoid hammering database
    """
    data = redis_client.get("recent_events")
    if data:
        return json.loads(data)
    return None


def set_recent_events(events: list) -> None:
    """
    Cache recent threat events for 5 minutes
    """
    redis_client.setex(
        "recent_events",
        RECENT_EVENTS_TTL,
        json.dumps(events, default=str)
    )


# ── SYSTEM STATS CACHE ────────────────────────────────

def get_system_stats() -> dict | None:
    """
    Get cached system statistics
    """
    data = redis_client.get("system_stats")
    if data:
        return json.loads(data)
    return None


def set_system_stats(stats: dict) -> None:
    """
    Cache system statistics for 1 minute
    """
    redis_client.setex(
        "system_stats",
        SYSTEM_STATS_TTL,
        json.dumps(stats, default=str)
    )


# ── BLOCKED IPS ───────────────────────────────────────

def add_blocked_ip(ip: str) -> None:
    """
    Add IP to the blocked set
    Checked before processing any event
    """
    redis_client.sadd("blocked_ips", ip)
    log.info("ip_blocked_in_cache", ip=ip)


def is_ip_blocked(ip: str) -> bool:
    """
    Check if an IP is currently blocked
    This is checked for every single incoming event
    Returns True if blocked
    """
    return redis_client.sismember("blocked_ips", ip)


def get_all_blocked_ips() -> set:
    """
    Get all currently blocked IPs
    """
    return redis_client.smembers("blocked_ips")