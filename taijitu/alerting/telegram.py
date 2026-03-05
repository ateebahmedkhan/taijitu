# taijitu/alerting/telegram.py
# Telegram War Room — TAIJITU's communication channel
# Alert bot sends threat notifications
# Command bot receives commands from operator

import asyncio
import structlog
from datetime import datetime
from telegram import Bot
from telegram.error import TelegramError

from taijitu.config import settings

log = structlog.get_logger()

# ── SEVERITY COLORS ───────────────────────────────────
SEVERITY_EMOJI = {
    "low":      "🟡",
    "medium":   "🟠",
    "high":     "🔴",
    "critical": "🚨",
}

VERDICT_EMOJI = {
    "threat":         "⚠️",
    "false_positive": "✅",
    "unknown":        "❓",
}


class TelegramAlerter:
    """
    Sends threat alerts to operator via Telegram
    Uses dedicated alert bot — send only
    Never receives commands
    """

    def __init__(self):
        self.token = settings.telegram_alert_token
        self.chat_id = settings.telegram_chat_id
        self.bot = None
        if self.token and self.token != "your_real_token_here":
            self.bot = Bot(token=self.token)
            log.info("telegram_alerter_initialized")
        else:
            log.warning("telegram_alerter_not_configured")

    def send_threat_alert(self, verdict, event_data: dict) -> bool:
        """
        Send threat alert to operator phone
        Called immediately after debate verdict
        """
        if not self.bot:
            log.warning("telegram_not_configured_skipping_alert")
            return False

        message = self._build_threat_message(verdict, event_data)
        return self._send(message)

    def send_night_probe_report(self, report: dict) -> bool:
        """
        Send night probe results to operator
        Called after 3am self-test completes
        """
        if not self.bot:
            return False

        message = self._build_probe_message(report)
        return self._send(message)

    def send_system_startup(self) -> bool:
        """Send notification when TAIJITU starts"""
        if not self.bot:
            return False

        message = (
            "☯ *TAIJITU ONLINE*\n\n"
            "Two Minds. One System. Zero Blind Spots.\n\n"
            f"🕐 Started: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
            "🛡 Guardian Mind: Ready\n"
            "⚔️ Adversary Mind: Ready\n"
            "🔍 Detection Engine: Active\n"
            "🧠 Memory Engine: Active\n\n"
            "Watching for threats..."
        )
        return self._send(message)

    def send_ip_blocked(self, ip: str, reason: str) -> bool:
        """Send notification when IP is auto-blocked"""
        if not self.bot:
            return False

        message = (
            f"🚫 *IP BLOCKED AUTOMATICALLY*\n\n"
            f"IP: `{ip}`\n"
            f"Reason: {reason}\n"
            f"Time: {datetime.utcnow().strftime('%H:%M:%S')} UTC\n\n"
            f"TAIJITU acted autonomously."
        )
        return self._send(message)

    def _build_threat_message(self, verdict, event_data: dict) -> str:
        """Build formatted threat alert message"""
        severity = verdict.final_severity
        sev_emoji = SEVERITY_EMOJI.get(severity, "⚠️")
        ver_emoji = VERDICT_EMOJI.get(verdict.verdict, "❓")

        ip = event_data.get("source_ip", "unknown")
        event_type = event_data.get("event_type", "unknown")
        raw_log = event_data.get("raw_log", "")[:80]

        return (
            f"{sev_emoji} *TAIJITU THREAT ALERT*\n\n"
            f"{ver_emoji} Verdict: *{verdict.verdict.upper()}*\n"
            f"🎯 Severity: *{severity.upper()}*\n"
            f"📊 Confidence: *{int(verdict.final_confidence * 100)}%*\n"
            f"⚡ Action: *{verdict.recommended_action}*\n\n"
            f"🌐 IP: `{ip}`\n"
            f"🔍 Type: {event_type}\n"
            f"📝 Log: `{raw_log}`\n\n"
            f"🛡 Guardian: {verdict.guardian_summary[:100]}\n\n"
            f"⚔️ Adversary: {verdict.adversary_summary[:100]}\n\n"
            f"🕐 {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"
        )

    def _build_probe_message(self, report: dict) -> str:
        """Build night probe report message"""
        detection_rate = report.get("detection_rate", 0)
        score_before = report.get("security_score_before", 0)
        score_after = report.get("security_score_after", 0)
        weaknesses = report.get("weaknesses_found", 0)
        recommendations = report.get("recommendations", [])

        score_emoji = "📈" if score_after > score_before else "📉"

        recs_text = "\n".join(
            f"  • {r}" for r in recommendations[:3]
        )

        return (
            f"🌙 *TAIJITU NIGHT PROBE REPORT*\n\n"
            f"🎯 Detection Rate: *{int(detection_rate * 100)}%*\n"
            f"⚠️ Weaknesses Found: *{weaknesses}*\n"
            f"{score_emoji} Security Score: *{score_before}* → *{score_after}*\n\n"
            f"📋 Recommendations:\n{recs_text}\n\n"
            f"🕐 {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"
        )

    def _send(self, message: str) -> bool:
        """Send a message via Telegram"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(
                self.bot.send_message(
                    chat_id=self.chat_id,
                    text=message,
                    parse_mode="Markdown",
                )
            )
            loop.close()
            log.info("telegram_message_sent")
            return True

        except TelegramError as e:
            log.error("telegram_send_failed", error=str(e))
            return False
        except Exception as e:
            log.error("telegram_unexpected_error", error=str(e))
            return False


class TelegramCommander:
    """
    Receives commands from operator via Telegram
    Uses dedicated command bot — receive only
    Processes operator instructions
    """

    def __init__(self):
        self.token = settings.telegram_command_token
        self.allowed_user_id = settings.telegram_allowed_user_id
        self.bot = None
        if self.token and self.token != "your_real_token_here":
            self.bot = Bot(token=self.token)
            log.info("telegram_commander_initialized")
        else:
            log.warning("telegram_commander_not_configured")

    def check_commands(self) -> list:
        """
        Check for new commands from operator
        Returns list of commands to process
        """
        if not self.bot:
            return []

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            updates = loop.run_until_complete(
                self.bot.get_updates(timeout=1)
            )
            loop.close()

            commands = []
            for update in updates:
                if not update.message:
                    continue

                # Security check — only allow configured user
                user_id = str(update.message.from_user.id)
                if user_id != str(self.allowed_user_id):
                    log.warning(
                        "unauthorized_command_attempt",
                        user_id=user_id,
                    )
                    continue

                text = update.message.text or ""
                if text.startswith("/"):
                    commands.append({
                        "command": text.split()[0],
                        "args": text.split()[1:],
                        "user_id": user_id,
                        "timestamp": datetime.utcnow(),
                    })

            return commands

        except Exception as e:
            log.error("command_check_failed", error=str(e))
            return []

    def process_command(self, command: dict) -> str:
        """
        Process a command from operator
        Returns response message
        """
        cmd = command.get("command", "").lower()
        args = command.get("args", [])

        if cmd == "/status":
            return self._cmd_status()
        elif cmd == "/block" and args:
            return self._cmd_block(args[0])
        elif cmd == "/unblock" and args:
            return self._cmd_unblock(args[0])
        elif cmd == "/blocked":
            return self._cmd_list_blocked()
        elif cmd == "/score":
            return self._cmd_security_score()
        elif cmd == "/help":
            return self._cmd_help()
        else:
            return f"Unknown command: {cmd}\nSend /help for available commands"

    def _cmd_status(self) -> str:
        return (
            "☯ TAIJITU Status: ONLINE\n"
            "🛡 Guardian: Active\n"
            "⚔️ Adversary: Active\n"
            "🔍 Detection: Running\n"
            "🧠 Memory: Active"
        )

    def _cmd_block(self, ip: str) -> str:
        from taijitu.storage.cache import add_blocked_ip
        add_blocked_ip(ip)
        return f"🚫 IP {ip} blocked manually"

    def _cmd_unblock(self, ip: str) -> str:
        from taijitu.autonomy.hardening import hardening_engine
        hardening_engine.unblock_ip(ip)
        return f"✅ IP {ip} unblocked"

    def _cmd_list_blocked(self) -> str:
        from taijitu.autonomy.hardening import hardening_engine
        blocked = hardening_engine.get_blocked_ips()
        if not blocked:
            return "No IPs currently blocked"
        return "🚫 Blocked IPs:\n" + "\n".join(f"  • {ip}" for ip in blocked)

    def _cmd_security_score(self) -> str:
        from taijitu.autonomy.night_probe import night_probe
        report = night_probe.get_last_report()
        if report.get("status") == "no_probe_run_yet":
            return "No night probe run yet"
        score = report.get("security_score_after", 0)
        return f"🎯 Security Score: {score}/100"

    def _cmd_help(self) -> str:
        return (
            "☯ TAIJITU Commands:\n\n"
            "/status — System status\n"
            "/block <ip> — Block an IP\n"
            "/unblock <ip> — Unblock an IP\n"
            "/blocked — List blocked IPs\n"
            "/score — Security posture score\n"
            "/help — This message"
        )


# ── GLOBAL INSTANCES ──────────────────────────────────
alerter = TelegramAlerter()
commander = TelegramCommander()