# taijitu/ingestion/packet_sensor.py
# Real network packet capture
# TAIJITU watches actual traffic on your machine
# Converts raw packets into TaijituEvents

import structlog
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
from taijitu.ingestion.log_sources import TaijituEvent

log = structlog.get_logger()

# ── SUSPICIOUS PORT DEFINITIONS ───────────────────────
ATTACK_PORTS = {
    22:    "SSH",
    23:    "Telnet",
    21:    "FTP",
    3389:  "RDP",
    445:   "SMB",
    139:   "NetBIOS",
    3306:  "MySQL",
    5432:  "PostgreSQL",
    6379:  "Redis",
    27017: "MongoDB",
    4444:  "Metasploit",
    1337:  "Backdoor",
    8080:  "HTTP-Alt",
    9200:  "Elasticsearch",
}

# Ports that indicate web traffic — less suspicious
NORMAL_PORTS = {80, 443, 53, 123, 25, 587}


class PacketSensor:
    """
    Real-time network packet capture
    Uses Scapy to watch actual network traffic

    What it captures:
    - TCP SYN packets (connection attempts)
    - UDP packets to suspicious ports
    - ICMP packets (ping sweeps)
    - Connections to known attack ports

    What it ignores:
    - Normal web traffic (80, 443)
    - DNS (53)
    - Already established connections
    """

    def __init__(self):
        self.captured_events = []
        self.packet_count = 0
        self.suspicious_count = 0
        self.is_running = False
        log.info("packet_sensor_initialized")

    def packet_to_event(self, packet) -> TaijituEvent | None:
        """
        Convert a raw Scapy packet to TaijituEvent
        Returns None if packet is not suspicious
        """
        self.packet_count += 1

        # Only process IP packets
        if not packet.haslayer(IP):
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Skip loopback and private ranges for now
        if src_ip.startswith("127.") or src_ip.startswith("::1"):
            return None

        # ── TCP PACKET ────────────────────────────────
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags

            # SYN packets = connection attempts
            is_syn = flags == 0x02

            # Check if targeting attack port
            is_attack_port = dst_port in ATTACK_PORTS

            # Skip normal web traffic
            if dst_port in NORMAL_PORTS and not is_syn:
                return None

            # Determine event type
            if is_attack_port and is_syn:
                service = ATTACK_PORTS.get(dst_port, "unknown")
                event_type = f"connection_attempt_{service.lower()}"
                raw_log = (
                    f"TCP SYN from {src_ip}:{src_port} "
                    f"to {dst_ip}:{dst_port} ({service})"
                )
            elif is_syn and dst_port > 1024:
                event_type = "port_probe"
                raw_log = (
                    f"TCP SYN probe from {src_ip}:{src_port} "
                    f"to {dst_ip}:{dst_port}"
                )
            else:
                return None

            self.suspicious_count += 1
            log.info(
                "suspicious_packet_captured",
                src=src_ip,
                dst_port=dst_port,
                event_type=event_type,
            )

            return TaijituEvent(
                timestamp=datetime.utcnow(),
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=src_port,
                destination_port=dst_port,
                event_type=event_type,
                raw_log=raw_log,
                log_source="network",
            )

        # ── ICMP PACKET ───────────────────────────────
        if packet.haslayer(ICMP):
            icmp_type = packet[ICMP].type

            # Type 8 = echo request (ping)
            if icmp_type == 8:
                self.suspicious_count += 1
                raw_log = f"ICMP echo request from {src_ip} to {dst_ip}"
                log.info("ping_detected", src=src_ip)

                return TaijituEvent(
                    timestamp=datetime.utcnow(),
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=0,
                    destination_port=0,
                    event_type="ping_sweep",
                    raw_log=raw_log,
                    log_source="network",
                )

        # ── UDP PACKET ────────────────────────────────
        if packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            # Skip DNS
            if dst_port == 53 or src_port == 53:
                return None

            if dst_port in ATTACK_PORTS:
                service = ATTACK_PORTS[dst_port]
                self.suspicious_count += 1
                raw_log = (
                    f"UDP packet from {src_ip}:{src_port} "
                    f"to {dst_ip}:{dst_port} ({service})"
                )

                return TaijituEvent(
                    timestamp=datetime.utcnow(),
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=src_port,
                    destination_port=dst_port,
                    event_type=f"udp_probe_{service.lower()}",
                    raw_log=raw_log,
                    log_source="network",
                )

        return None

    def capture(self, duration_seconds: int = 30, interface: str = None) -> list:
        """
        Capture packets for a set duration
        Returns list of TaijituEvents

        Note: Requires sudo/root on most systems
        Run with: sudo python -m taijitu.ingestion.packet_sensor
        """
        self.is_running = True
        captured = []

        log.info(
            "packet_capture_starting",
            duration=duration_seconds,
            interface=interface or "default",
        )

        def process_packet(packet):
            event = self.packet_to_event(packet)
            if event:
                captured.append(event)
                self.captured_events.append(event)

        try:
            sniff(
                iface=interface,
                prn=process_packet,
                timeout=duration_seconds,
                store=False,
            )
        except PermissionError:
            log.error(
                "packet_capture_permission_denied",
                hint="Run with sudo for packet capture",
            )
        except Exception as e:
            log.error("packet_capture_error", error=str(e))
        finally:
            self.is_running = False

        log.info(
            "packet_capture_complete",
            total_packets=self.packet_count,
            suspicious=self.suspicious_count,
            events_captured=len(captured),
        )

        return captured

    def get_stats(self) -> dict:
        """Get packet capture statistics"""
        return {
            "total_packets_seen": self.packet_count,
            "suspicious_packets": self.suspicious_count,
            "events_generated": len(self.captured_events),
            "is_running": self.is_running,
            "suspicion_rate": round(
                self.suspicious_count / self.packet_count, 3
            ) if self.packet_count > 0 else 0,
        }


# ── GLOBAL INSTANCE ───────────────────────────────────
packet_sensor = PacketSensor()