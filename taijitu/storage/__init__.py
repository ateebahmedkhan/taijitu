# taijitu/storage/__init__.py
# Makes storage a Python package
# Exposes the most used items for easy importing

from taijitu.storage.database import (
    get_db,
    create_tables,
    check_connection as check_db_connection,
)

from taijitu.storage.cache import (
    check_connection as check_cache_connection,
    get_attacker_profile,
    set_attacker_profile,
    delete_attacker_profile,
    is_ip_blocked,
    add_blocked_ip,
)

__all__ = [
    "get_db",
    "create_tables",
    "check_db_connection",
    "check_cache_connection",
    "get_attacker_profile",
    "set_attacker_profile",
    "delete_attacker_profile",
    "is_ip_blocked",
    "add_blocked_ip",
]