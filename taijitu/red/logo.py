# taijitu/red/logo.py
# TAIJITU RED — Terminal Branding
# Big gradient wordmark — blue → purple → red
# Like Gemini CLI but TAIJITU

import time
import pyfiglet
from rich.console import Console
from rich.live import Live
from rich.text import Text

# ── BRAND COLORS ─────────────────────────────────────
BLUE   = (0,   194, 255)
PURPLE = (123, 47,  190)
RED    = (227, 62,  62)
DIM    = (58,  58,  74)
WHITE  = (255, 255, 255)

# Gradient stops — blue → purple → red
GRADIENT = [
    (0,   194, 255),  # Guardian Blue
    (61,  130, 230),  # blue-purple
    (123, 47,  190),  # Adversary Purple
    (175, 54,  125),  # purple-red
    (227, 62,  62),   # RED
]

RST  = "\033[0m"
BOLD = "\033[1m"

def _c(r, g, b): return f"\033[38;2;{r};{g};{b}m"
def _dim():      return _c(*DIM)
def _white():    return _c(*WHITE)


def _interpolate(colors, t):
    """Interpolate through color stops at position t (0.0-1.0)"""
    seg   = t * (len(colors) - 1)
    si    = int(seg)
    st    = seg - si
    if si >= len(colors) - 1:
        return colors[-1]
    r1,g1,b1 = colors[si]
    r2,g2,b2 = colors[si+1]
    return (
        int(r1 + (r2-r1) * st),
        int(g1 + (g2-g1) * st),
        int(b1 + (b2-b1) * st),
    )


def _gradient_lines(text: str, colors: list) -> list:
    """Apply horizontal gradient across figlet text lines"""
    lines  = pyfiglet.figlet_format(text, font="slant").split("\n")
    # Find actual content width
    max_w  = max((len(l) for l in lines), default=1)
    result = []
    for line in lines:
        if not line.strip():
            result.append("")
            continue
        colored = "  "  # left indent
        for i, ch in enumerate(line):
            if ch == " ":
                colored += " "
                continue
            t = i / max(max_w - 1, 1)
            r, g, b = _interpolate(colors, t)
            colored += f"{BOLD}\033[38;2;{r};{g};{b}m{ch}{RST}"
        result.append(colored)
    return result


def _render_wordmark() -> list:
    """Return gradient wordmark lines"""
    return _gradient_lines("TAIJITU RED", GRADIENT)


def print_logo(console: Console):
    """Print static gradient wordmark + tagline"""
    console.print()
    lines = _render_wordmark()
    for line in lines:
        console.print(Text.from_ansi(line))
    console.print()
    console.print("  [dim]AUTONOMOUS SECURITY RESEARCH PLATFORM[/dim]")
    console.print("  [dim]Two Minds · One System · Zero Blind Spots[/dim]")
    console.print()
    console.print("  [dim]" + "─" * 56 + "[/dim]")
    console.print()


def animate_startup(console: Console):
    """
    Startup animation — wordmark fades in line by line
    then progress bar fills blue → white center → purple
    Represents Guardian and Adversary converging
    """
    lines = _render_wordmark()

    # Fade in — reveal one line at a time
    console.print()
    revealed = []
    for line in lines:
        revealed.append(line)
        console.clear()
        console.print()
        for l in revealed:
            console.print(Text.from_ansi(l))
        time.sleep(0.04)

    # Tagline appears
    console.print("  [dim]AUTONOMOUS SECURITY RESEARCH PLATFORM[/dim]")
    console.print("  [dim]Two Minds · One System · Zero Blind Spots[/dim]")
    console.print()
    console.print("  [dim]" + "─" * 56 + "[/dim]")
    console.print()

    # Progress bar — blue fills left half, purple fills right
    # center dot pulses white when they meet
    BAR = 48

    with Live(console=console, refresh_per_second=30) as live:

        # Phase 1 — Guardian blue fills left to center
        for i in range(BAR // 2 + 1):
            filled = i
            empty  = BAR - filled
            bar = (
                f"  {_c(*BLUE)}{'━' * filled}"
                f"{_c(*DIM)}{'─' * empty}{RST}"
                f"  {_dim()}Guardian{RST}"
            )
            live.update(Text.from_ansi(bar))
            time.sleep(0.018)

        # Phase 2 — Adversary purple fills right half
        half = BAR // 2
        for i in range(half + 1):
            filled_p = i
            bar = (
                f"  {_c(*BLUE)}{'━' * half}"
                f"{_c(*PURPLE)}{'━' * filled_p}"
                f"{_c(*DIM)}{'─' * (half - filled_p)}{RST}"
                f"  {_dim()}Adversary{RST}"
            )
            live.update(Text.from_ansi(bar))
            time.sleep(0.018)

        # Phase 3 — center white dot pulse
        for _ in range(3):
            # pulse on
            bar = (
                f"  {_c(*BLUE)}{'━' * (half-1)}"
                f"{BOLD}{_c(*WHITE)}●{RST}"
                f"{_c(*PURPLE)}{'━' * (half-1)}{RST}"
                f"  {_c(*BLUE)}Systems online{RST}"
            )
            live.update(Text.from_ansi(bar))
            time.sleep(0.15)
            # pulse off
            bar = (
                f"  {_c(*BLUE)}{'━' * half}"
                f"{_c(*PURPLE)}{'━' * half}{RST}"
                f"  {_c(*BLUE)}Systems online{RST}"
            )
            live.update(Text.from_ansi(bar))
            time.sleep(0.1)

        # Final state
        bar = (
            f"  {_c(*BLUE)}{'━' * (half-1)}"
            f"{BOLD}{_c(*WHITE)}●{RST}"
            f"{_c(*PURPLE)}{'━' * (half-1)}{RST}"
            f"  {_c(*BLUE)}Systems online{RST}"
        )
        live.update(Text.from_ansi(bar))
        time.sleep(0.5)

    console.print()