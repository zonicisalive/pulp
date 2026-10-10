#!/usr/bin/env python3
"""Turn ANSI-colored terminal output (stdin) into a small animated SVG (stdout).

usage: scripts/demo.sh | scripts/ansi2svg.py "pulp scan --format short" > docs/demo.svg
Lines appear one after another; no JavaScript, so GitHub renders it inside README.md.
"""
import html
import re
import sys

COLORS = {"31": "#ff7b72", "33": "#e3b341", "36": "#79c0ff", "2": "#8b949e"}
FG, BG, BAR = "#c9d1d9", "#0d1117", "#161b22"
MAXCOLS = 118
CW, LH, PAD = 7.8, 19, 18  # char width, line height, padding

cmd = sys.argv[1] if len(sys.argv) > 1 else "pulp scan"
raw = sys.stdin.read().rstrip("\n").split("\n")


def spans(line):
    """Split a line into (text, color, bold) runs; truncate to MAXCOLS visible chars."""
    out, color, bold, shown = [], FG, False, 0
    for part in re.split(r"(\x1b\[[0-9;]*m)", line):
        m = re.fullmatch(r"\x1b\[([0-9;]*)m", part)
        if m:
            for code in (m.group(1) or "0").split(";"):
                if code in ("0", ""):
                    color, bold = FG, False
                elif code == "1":
                    bold = True
                elif code in COLORS:
                    color = COLORS[code]
        elif part and shown < MAXCOLS:
            text = part[: MAXCOLS - shown]
            if len(part) > len(text):
                text = text[:-1] + "…"
            shown += len(text)
            out.append((text, color, bold))
    return out


rows = [spans(l) for l in raw]
cols = max([len("$ " + cmd)] + [sum(len(t) for t, _, _ in r) for r in rows])
W = int(cols * CW + PAD * 2)
H = int(44 + PAD + (len(rows) + 2) * LH + PAD)
out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" aria-label="pulp scan demo">',
       "<style>text{font:13px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre}"
       ".l{opacity:0;animation:s .01s linear forwards}@keyframes s{to{opacity:1}}"
       "@media (prefers-reduced-motion:reduce){.l{animation:none;opacity:1}}</style>",
       f'<rect width="{W}" height="{H}" rx="8" fill="{BG}"/><rect width="{W}" height="30" rx="8" fill="{BAR}"/>',
       '<circle cx="18" cy="15" r="5" fill="#ff5f56"/><circle cx="36" cy="15" r="5" fill="#ffbd2e"/><circle cx="54" cy="15" r="5" fill="#27c93f"/>']
y = 30 + PAD + LH
out.append(f'<text class="l" x="{PAD}" y="{y}" fill="{FG}" style="animation-delay:.2s"><tspan fill="#7ee787">$</tspan> {html.escape(cmd)}</text>')
delay = 1.0
for i, r in enumerate(rows):
    y += LH + (LH // 2 if raw[i] == "" else 0)
    tspans = "".join(
        f'<tspan fill="{c}"{" font-weight=\"bold\"" if b else ""}>{html.escape(t)}</tspan>' for t, c, b in r)
    out.append(f'<text class="l" x="{PAD}" y="{y}" fill="{FG}" style="animation-delay:{delay:.2f}s">{tspans}</text>')
    delay += 0.12 if raw[i] else 0.5
out.append("</svg>")
print("\n".join(out))
