#!/usr/bin/env python3
"""Generate publication-ready SVG figures from the UDS 0x29 benchmark CSV."""

from __future__ import annotations

import argparse
import csv
import html
import math
from pathlib import Path

SCHEMES = ["CL-ECS-SM2", "RSA-2048-PSS+X509", "ECDSA-P256+X509", "SM2-SM3+X509"]
SHORT = {"CL-ECS-SM2": "CL-ECS-SM2", "RSA-2048-PSS+X509": "RSA-2048", "ECDSA-P256+X509": "ECDSA-P256", "SM2-SM3+X509": "SM2-SM3"}
COLORS = {"CL-ECS-SM2": "#0072B2", "RSA-2048-PSS+X509": "#D55E00", "ECDSA-P256+X509": "#009E73", "SM2-SM3+X509": "#CC79A7"}
HATCH = {"CL-ECS-SM2": "diag", "RSA-2048-PSS+X509": "cross", "ECDSA-P256+X509": "dots", "SM2-SM3+X509": "horiz"}
PHASES = ["2901_credential", "6901_challenge", "2903_sign", "6903_verify"]
PHASE_LABELS = ["0x2901\nCredential", "0x6901\nChallenge", "0x2903\nSigning", "0x6903\nVerification"]
MSG_COLORS = ["#4C78A8", "#F58518", "#54A24B", "#B279A2"]
MSG_LABELS = ["0x2901", "0x6901", "0x2903", "0x6903"]


def load(csv_path):
    rows = {}
    with csv_path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows[(row["scheme"], row["phase"])] = row
    return rows


def esc(s):
    return html.escape(str(s))


class SVG:
    def __init__(self, width, height, title, desc):
        self.width, self.height = width, height
        self.a = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img">',
            f"<title>{esc(title)}</title><desc>{esc(desc)}</desc>",
            "<defs>",
            '<pattern id="diag" width="8" height="8" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><line x1="0" y1="0" x2="0" y2="8" stroke="#111" stroke-width="1.4" opacity=".42"/></pattern>',
            '<pattern id="cross" width="9" height="9" patternUnits="userSpaceOnUse"><path d="M0 0L9 9M9 0L0 9" stroke="#111" stroke-width="1" opacity=".32"/></pattern>',
            '<pattern id="dots" width="8" height="8" patternUnits="userSpaceOnUse"><circle cx="2" cy="2" r="1.25" fill="#111" opacity=".42"/></pattern>',
            '<marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#555"/></marker>',
            "<pattern id=\"horiz\" width=\"8\" height=\"8\" patternUnits=\"userSpaceOnUse\"><line x1=\"0\" y1=\"2\" x2=\"8\" y2=\"2\" stroke=\"#111\" stroke-width=\"1.2\" opacity=\".42\"/></pattern>",
            "</defs>",
            '<rect width="100%" height="100%" fill="white"/>',
            '<g font-family="Nimbus Roman, Noto Sans, serif" fill="#171717">',
        ]

    def line(self, x1, y1, x2, y2, **kw):
        attrs = {"stroke": "#222", "stroke_width": 1.5, **kw}
        self.a.append(f'<line x1="{x1:.2f}" y1="{y1:.2f}" x2="{x2:.2f}" y2="{y2:.2f}" {fmt(attrs)}/>')

    def rect(self, x, y, w, h, **kw):
        attrs = {"fill": "none", **kw}
        self.a.append(f'<rect x="{x:.2f}" y="{y:.2f}" width="{w:.2f}" height="{h:.2f}" {fmt(attrs)}/>')

    def circle(self, x, y, r, **kw):
        self.a.append(f'<circle cx="{x:.2f}" cy="{y:.2f}" r="{r:.2f}" {fmt(kw)}/>')

    def text(self, x, y, text, size=25, anchor="middle", weight="normal", **kw):
        attrs = {"font-size": size, "text-anchor": anchor, "font-weight": weight, **kw}
        lines = str(text).split("\n")
        if len(lines) == 1:
            self.a.append(f'<text x="{x:.2f}" y="{y:.2f}" {fmt(attrs)}>{esc(text)}</text>')
        else:
            spans = "".join(f'<tspan x="{x:.2f}" dy="{0 if i == 0 else 1.08}em">{esc(t)}</tspan>' for i, t in enumerate(lines))
            self.a.append(f'<text x="{x:.2f}" y="{y:.2f}" {fmt(attrs)}>{spans}</text>')

    def finish(self):
        return "".join(self.a) + "</g></svg>\n"


def fmt(attrs):
    return " ".join(f'{k.replace("_", "-")}="{esc(v)}"' for k, v in attrs.items())


def patterned_bar(s, scheme, x, y, w, h):
    s.rect(x, y, w, h, fill=COLORS[scheme], stroke="#222", stroke_width=1.3, rx=2)
    s.rect(x, y, w, h, fill=f"url(#{HATCH[scheme]})", stroke="none", rx=2)


def make_overview(rows, output_path):
    W, H = 1800, 720
    s = SVG(W, H, "UDS 0x29 authentication performance overview", "Median and P95 latency, message bytes, and latency-bandwidth trade-off")
    s.text(900, 42, "UDS 0x29 Authentication: Computation and Communication Performance", 31, weight="bold")

    # Shared scheme legend.
    lx = 350
    for i, scheme in enumerate(SCHEMES):
        x = lx + i * 270
        patterned_bar(s, scheme, x, 62, 35, 20)
        s.text(x + 46, 79, SHORT[scheme], 21, anchor="start")

    # Panel A: phase medians on a linear scale; small cap marks P95.
    x0, y0, pw, ph = 82, 128, 720, 480
    s.text(x0, 112, "(a) Online latency by protocol phase", 26, anchor="start", weight="bold")
    max_latency = max(float(rows[(scheme, phase)]["p95_us"]) for scheme in SCHEMES for phase in PHASES)
    rough_step = max_latency / 5
    magnitude = 10 ** math.floor(math.log10(rough_step))
    tick_step = next(step * magnitude for step in (1, 2, 5, 10) if step * magnitude >= rough_step)
    ymax = math.ceil(max_latency / tick_step) * tick_step
    def ya(v): return y0 + ph - v / ymax * ph
    for i in range(round(ymax / tick_step) + 1):
        tick = i * tick_step
        y = ya(tick); s.line(x0, y, x0 + pw, y, stroke="#D2D2D2", stroke_width=1)
        s.text(x0 - 13, y + 7, f"{tick:g}", 20, anchor="end")
    s.line(x0, y0, x0, y0 + ph); s.line(x0, y0 + ph, x0 + pw, y0 + ph)
    group_w, bar_w = pw / 4, 30
    for j, (phase, label) in enumerate(zip(PHASES, PHASE_LABELS)):
        center = x0 + (j + .5) * group_w
        for i, scheme in enumerate(SCHEMES):
            row = rows[(scheme, phase)]; med = float(row["median_us"]); p95 = float(row["p95_us"])
            x = center + (i - 1.5) * 38 - bar_w / 2; y = ya(med)
            patterned_bar(s, scheme, x, y, bar_w, y0 + ph - y)
            capy = ya(p95); s.line(x + 4, capy, x + bar_w - 4, capy, stroke="#111", stroke_width=3)
        s.text(center, y0 + ph + 28, label, 19)
    s.text(25, y0 + ph / 2, "Latency (μs)", 22, transform=f"rotate(-90 25 {y0 + ph / 2})")
    s.text(x0 + pw - 2, y0 + 18, "bar: median; cap: P95", 18, anchor="end", fill="#555")

    # Panel B: stacked wire bytes.
    bx, by, bw, bh = 885, 128, 400, 480
    s.text(bx, 112, "(b) UDS payload size", 26, anchor="start", weight="bold")
    maxb = 1400
    def yb(v): return by + bh - v / maxb * bh
    for tick in range(0, 1401, 200):
        y = yb(tick); s.line(bx, y, bx + bw, y, stroke="#D2D2D2", stroke_width=1); s.text(bx - 10, y + 7, tick, 19, anchor="end")
    s.line(bx, by, bx, by + bh); s.line(bx, by + bh, bx + bw, by + bh)
    keys = ["wire_2901", "wire_6901", "wire_2903", "wire_6903"]
    for i, scheme in enumerate(SCHEMES):
        row = rows[(scheme, "total")]; vals = [int(row[k]) for k in keys]; x = bx + 18 + i * 94; acc = 0
        for val, col, lab in zip(vals, MSG_COLORS, MSG_LABELS):
            y_top, y_bot = yb(acc + val), yb(acc)
            s.rect(x, y_top, 58, y_bot - y_top, fill=col, stroke="white", stroke_width=1)
            if y_bot - y_top > 27: s.text(x + 29, (y_top + y_bot) / 2 + 7, val, 17, fill="white", weight="bold")
            acc += val
        s.text(x + 29, yb(acc) - 9, acc, 20, weight="bold")
        s.text(x + 29, by + bh + 27, SHORT[scheme].replace("-2048", "\n2048").replace("-P256", "\nP256").replace("-SM3", "\nSM3"), 16)
    s.text(bx - 54, by + bh / 2, "Bytes", 22, transform=f"rotate(-90 {bx - 54} {by + bh / 2})")
    for i, (lab, col) in enumerate(zip(MSG_LABELS, MSG_COLORS)):
        x = bx + (i % 2) * 110 + 170; y = by + 24 + (i // 2) * 28
        s.rect(x, y - 14, 23, 16, fill=col); s.text(x + 30, y, lab, 17, anchor="start")

    # Panel C: lower-left is desirable.
    cx, cy, cw, ch = 1380, 128, 350, 480
    s.text(cx, 112, "(c) Latency–payload trade-off", 26, anchor="start", weight="bold")
    def xc(v): return cx + v / 1200 * cw
    def yc(v): return cy + ch - v / 600 * ch
    for tick in range(0, 1201, 300):
        x=xc(tick);s.line(x,cy,x,cy+ch,stroke="#E1E1E1",stroke_width=1);s.text(x,cy+ch+25,tick,18)
    for tick in range(0, 601, 100):
        y=yc(tick);s.line(cx,y,cx+cw,y,stroke="#E1E1E1",stroke_width=1);s.text(cx-9,y+6,tick,18,anchor="end")
    s.line(cx,cy,cx,cy+ch);s.line(cx,cy+ch,cx+cw,cy+ch)
    offsets={SCHEMES[0]:(10,-18),SCHEMES[1]:(-10,-18),SCHEMES[2]:(10,-14),SCHEMES[3]:(10,-16)}
    anchors={SCHEMES[0]:"start",SCHEMES[1]:"end",SCHEMES[2]:"start",SCHEMES[3]:"start"}
    for scheme in SCHEMES:
        row=rows[(scheme,"total")]; total=sum(int(row[k]) for k in keys); med=float(row["median_us"]); x,y=xc(total),yc(med)
        s.circle(x,y,12,fill=COLORS[scheme],stroke="#111",stroke_width=1.5)
        dx,dy=offsets[scheme];s.text(x+dx,y+dy,SHORT[scheme],18,anchor=anchors[scheme],weight="bold")
    s.line(cx+250,cy+80,cx+55,cy+390,stroke="#555",stroke_width=2,stroke_dasharray="7 6",marker_end="url(#arrow)")
    s.text(cx+235,cy+68,"Lower is better",18,anchor="end",fill="#555",font_style="italic")
    s.text(cx+cw/2,cy+ch+55,"Total UDS payload (bytes)",21)
    s.text(cx-61,cy+ch/2,"Median online latency (μs)",21,transform=f"rotate(-90 {cx-61} {cy+ch/2})")
    s.text(W-25,H-18,"Median/P95 from input CSV; 32-byte challenge",17,anchor="end",fill="#555")
    output_path.write_text(s.finish(), encoding="utf-8")


def make_frames(rows, output_path):
    W,H=1100,700;s=SVG(W,H,"Estimated ISO-TP frame counts","Estimated frame counts for Classical CAN and CAN FD")
    s.text(W/2,45,"Estimated ISO-TP Frames per UDS 0x29 Authentication",30,weight="bold")
    # Simplified normal-addressing models described in REPORT.md.
    def frames_classic(n): return 1 if n<=7 else 1+math.ceil((n-6)/7)
    def frames_fd(n): return 1 if n<=62 else 1+math.ceil((n-62)/63)
    keys=["wire_2901","wire_6901","wire_2903","wire_6903"]
    vals={sname:(sum(frames_classic(int(rows[(sname,"total")][k])) for k in keys),sum(frames_fd(int(rows[(sname,"total")][k])) for k in keys)) for sname in SCHEMES}
    x0,y0,pw,ph=105,105,900,470; ymax=160
    for tick in range(0,161,20):
        y=y0+ph-tick/ymax*ph;s.line(x0,y,x0+pw,y,stroke="#D5D5D5",stroke_width=1);s.text(x0-12,y+7,tick,21,anchor="end")
    s.line(x0,y0,x0,y0+ph);s.line(x0,y0+ph,x0+pw,y0+ph)
    for i,scheme in enumerate(SCHEMES):
        center=x0+112.5+i*225
        for j,(value,lab,opacity) in enumerate(zip(vals[scheme],["Classical CAN","CAN FD"],[1,.52])):
            x=center+(j-.5)*82-30;y=y0+ph-value/ymax*ph
            s.rect(x,y,60,y0+ph-y,fill=COLORS[scheme],fill_opacity=opacity,stroke="#222",stroke_width=1.2)
            s.text(x+30,y-10,value,23,weight="bold")
        s.text(center,y0+ph+34,SHORT[scheme],22)
    s.text(28,y0+ph/2,"Estimated ISO-TP frames",23,transform=f"rotate(-90 28 {y0+ph/2})")
    s.rect(385,625,28,20,fill="#555");s.text(424,642,"Classical CAN",20,anchor="start")
    s.rect(610,625,28,20,fill="#555",fill_opacity=.52);s.text(649,642,"CAN FD",20,anchor="start")
    s.text(W/2,682,"Normal addressing; simplified payload capacities; excludes flow-control frames",17,fill="#555")
    output_path.write_text(s.finish(), encoding="utf-8")



def main():
    parser = argparse.ArgumentParser(
        description="Generate a publication-ready SVG figure from a benchmark CSV."
    )
    parser.add_argument("input_csv", type=Path, help="input benchmark CSV file")
    parser.add_argument("output_svg", type=Path, help="SVG file to create")
    parser.add_argument(
        "--figure",
        choices=("overview", "isotp"),
        default="overview",
        help="figure type to generate (default: overview)",
    )
    args = parser.parse_args()

    rows = load(args.input_csv)
    args.output_svg.parent.mkdir(parents=True, exist_ok=True)
    if args.figure == "overview":
        make_overview(rows, args.output_svg)
    else:
        make_frames(rows, args.output_svg)
    print(f"Generated {args.output_svg}")


if __name__ == "__main__":
    main()
