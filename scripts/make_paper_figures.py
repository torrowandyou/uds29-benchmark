#!/usr/bin/env python3
"""Generate publication-ready SVG figures from the UDS 0x29 benchmark CSV."""

from __future__ import annotations

import argparse
import csv
import html
import math
from pathlib import Path

SCHEMES = ["CL-ECS-SM2", "RSA-3072-PSS+X509", "ECDSA-P256+X509", "SM2-SM3+X509"]
SHORT = {"CL-ECS-SM2": "CL-ECS-SM2", "RSA-3072-PSS+X509": "RSA-3072", "ECDSA-P256+X509": "ECDSA-P256", "SM2-SM3+X509": "SM2-SM3"}
COLORS = {"CL-ECS-SM2": "#0072B2", "RSA-3072-PSS+X509": "#D55E00", "ECDSA-P256+X509": "#009E73", "SM2-SM3+X509": "#CC79A7"}
HATCH = {"CL-ECS-SM2": "diag", "RSA-3072-PSS+X509": "cross", "ECDSA-P256+X509": "dots", "SM2-SM3+X509": "horiz"}
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


def nice_axis(max_value, target_ticks=5):
    if max_value <= 0:
        return 1.0, 1.0
    rough_step = max_value / target_ticks
    magnitude = 10 ** math.floor(math.log10(rough_step))
    tick_step = next(
        step * magnitude for step in (1, 2, 5, 10)
        if step * magnitude >= rough_step
    )
    limit = math.ceil(max_value / tick_step) * tick_step
    return limit, tick_step


def draw_scheme_legend(s, y, start_x, spacing):
    for i, scheme in enumerate(SCHEMES):
        x = start_x + i * spacing
        patterned_bar(s, scheme, x, y - 17, 32, 19)
        s.text(x + 42, y, SHORT[scheme], 19, anchor="start")


def make_latency(rows, output_path):
    W, H = 1050, 700
    s = SVG(
        W,
        H,
        "Online latency by UDS 0x29 protocol phase",
        "Median latency bars and P95 caps on a linear microsecond scale",
    )
    s.text(W / 2, 42, "(a) Online Latency by Protocol Phase", 30, weight="bold")
    draw_scheme_legend(s, 78, 90, 235)

    x0, y0, pw, ph = 92, 112, 900, 470
    max_latency = max(
        float(rows[(scheme, phase)]["p95_us"])
        for scheme in SCHEMES
        for phase in PHASES
    )
    ymax, tick_step = nice_axis(max_latency)

    def yscale(value):
        return y0 + ph - value / ymax * ph

    for i in range(round(ymax / tick_step) + 1):
        tick = i * tick_step
        y = yscale(tick)
        s.line(x0, y, x0 + pw, y, stroke="#D2D2D2", stroke_width=1)
        s.text(x0 - 12, y + 7, f"{tick:g}", 20, anchor="end")
    s.line(x0, y0, x0, y0 + ph)
    s.line(x0, y0 + ph, x0 + pw, y0 + ph)

    group_w, bar_w = pw / len(PHASES), 34
    for phase_index, (phase, label) in enumerate(zip(PHASES, PHASE_LABELS)):
        center = x0 + (phase_index + 0.5) * group_w
        for scheme_index, scheme in enumerate(SCHEMES):
            row = rows[(scheme, phase)]
            median = float(row["median_us"])
            p95 = float(row["p95_us"])
            x = center + (scheme_index - 1.5) * 43 - bar_w / 2
            y = yscale(median)
            patterned_bar(s, scheme, x, y, bar_w, y0 + ph - y)
            cap_y = yscale(p95)
            s.line(x + 4, cap_y, x + bar_w - 4, cap_y, stroke="#111", stroke_width=3)
        s.text(center, y0 + ph + 29, label, 19)

    s.text(26, y0 + ph / 2, "Latency (μs)", 22, transform=f"rotate(-90 26 {y0 + ph / 2})")
    s.text(x0 + pw, y0 + 18, "bar: median; cap: P95", 17, anchor="end", fill="#555")
    s.text(W - 20, H - 16, "Linear scale; values read directly from input CSV", 16, anchor="end", fill="#555")
    output_path.write_text(s.finish(), encoding="utf-8")


def make_payload(rows, output_path):
    W, H = 850, 700
    s = SVG(
        W,
        H,
        "UDS 0x29 application payload size",
        "Stacked application payload bytes for the four authentication messages",
    )
    s.text(W / 2, 42, "(b) UDS Payload Size", 30, weight="bold")

    keys = ["wire_2901", "wire_6901", "wire_2903", "wire_6903"]
    totals = {
        scheme: sum(int(rows[(scheme, "total")][key]) for key in keys)
        for scheme in SCHEMES
    }
    ymax, tick_step = nice_axis(max(totals.values()), target_ticks=6)
    x0, y0, pw, ph = 100, 92, 690, 490

    def yscale(value):
        return y0 + ph - value / ymax * ph

    for i in range(round(ymax / tick_step) + 1):
        tick = i * tick_step
        y = yscale(tick)
        s.line(x0, y, x0 + pw, y, stroke="#D2D2D2", stroke_width=1)
        s.text(x0 - 11, y + 7, f"{tick:g}", 20, anchor="end")
    s.line(x0, y0, x0, y0 + ph)
    s.line(x0, y0 + ph, x0 + pw, y0 + ph)

    bar_w = 82
    for i, scheme in enumerate(SCHEMES):
        row = rows[(scheme, "total")]
        values = [int(row[key]) for key in keys]
        center = x0 + (i + 0.5) * pw / len(SCHEMES)
        x = center - bar_w / 2
        accumulated = 0
        for value, color in zip(values, MSG_COLORS):
            y_top, y_bottom = yscale(accumulated + value), yscale(accumulated)
            s.rect(x, y_top, bar_w, y_bottom - y_top, fill=color, stroke="white", stroke_width=1)
            if y_bottom - y_top > 27:
                s.text(center, (y_top + y_bottom) / 2 + 7, value, 17, fill="white", weight="bold")
            accumulated += value
        s.text(center, yscale(accumulated) - 9, accumulated, 20, weight="bold")
        label = SHORT[scheme].replace("-3072", "\n3072").replace("-P256", "\nP256").replace("-SM3", "\nSM3")
        s.text(center, y0 + ph + 30, label, 18)

    s.text(28, y0 + ph / 2, "Application payload (bytes)", 22, transform=f"rotate(-90 28 {y0 + ph / 2})")
    legend_start = 155
    for i, (label, color) in enumerate(zip(MSG_LABELS, MSG_COLORS)):
        x = legend_start + i * 145
        s.rect(x, 650, 25, 17, fill=color)
        s.text(x + 34, 665, label, 18, anchor="start")
    output_path.write_text(s.finish(), encoding="utf-8")


def make_tradeoff(rows, output_path):
    W, H = 850, 700
    s = SVG(
        W,
        H,
        "Latency and payload trade-off",
        "Median online latency versus total UDS application payload",
    )
    s.text(W / 2, 42, "(c) Latency–Payload Trade-off", 30, weight="bold")

    keys = ["wire_2901", "wire_6901", "wire_2903", "wire_6903"]
    totals = {
        scheme: sum(int(rows[(scheme, "total")][key]) for key in keys)
        for scheme in SCHEMES
    }
    medians = {
        scheme: float(rows[(scheme, "total")]["median_us"])
        for scheme in SCHEMES
    }
    xmax, xstep = nice_axis(max(totals.values()), target_ticks=6)
    ymax, ystep = nice_axis(max(medians.values()), target_ticks=6)
    x0, y0, pw, ph = 105, 86, 680, 500

    def xscale(value):
        return x0 + value / xmax * pw

    def yscale(value):
        return y0 + ph - value / ymax * ph

    for i in range(round(xmax / xstep) + 1):
        tick = i * xstep
        x = xscale(tick)
        s.line(x, y0, x, y0 + ph, stroke="#E1E1E1", stroke_width=1)
        s.text(x, y0 + ph + 25, f"{tick:g}", 18)
    for i in range(round(ymax / ystep) + 1):
        tick = i * ystep
        y = yscale(tick)
        s.line(x0, y, x0 + pw, y, stroke="#E1E1E1", stroke_width=1)
        s.text(x0 - 10, y + 6, f"{tick:g}", 18, anchor="end")
    s.line(x0, y0, x0, y0 + ph)
    s.line(x0, y0 + ph, x0 + pw, y0 + ph)

    offsets = {
        SCHEMES[0]: (12, -18),
        SCHEMES[1]: (-12, -18),
        SCHEMES[2]: (12, -15),
        SCHEMES[3]: (12, -17),
    }
    anchors = {
        SCHEMES[0]: "start",
        SCHEMES[1]: "end",
        SCHEMES[2]: "start",
        SCHEMES[3]: "start",
    }
    for scheme in SCHEMES:
        x, y = xscale(totals[scheme]), yscale(medians[scheme])
        s.circle(x, y, 12, fill=COLORS[scheme], stroke="#111", stroke_width=1.5)
        dx, dy = offsets[scheme]
        s.text(x + dx, y + dy, SHORT[scheme], 19, anchor=anchors[scheme], weight="bold")

    s.line(x0 + pw * 0.80, y0 + ph * 0.20, x0 + pw * 0.18, y0 + ph * 0.82,
           stroke="#555", stroke_width=2, stroke_dasharray="7 6", marker_end="url(#arrow)")
    s.text(x0 + pw * 0.79, y0 + ph * 0.17, "Lower is better", 18, anchor="end",
           fill="#555", font_style="italic")
    s.text(x0 + pw / 2, 655, "Total UDS payload (bytes)", 22)
    s.text(27, y0 + ph / 2, "Median online latency (μs)", 22,
           transform=f"rotate(-90 27 {y0 + ph / 2})")
    output_path.write_text(s.finish(), encoding="utf-8")


def make_frames(rows, output_path):
    W,H=1100,700;s=SVG(W,H,"Estimated ISO-TP frame counts","Estimated frame counts for Classical CAN and CAN FD")
    s.text(W/2,45,"Estimated ISO-TP Frames per UDS 0x29 Authentication",30,weight="bold")
    # Simplified normal-addressing models described in REPORT.md.
    def frames_classic(n): return 1 if n<=7 else 1+math.ceil((n-6)/7)
    def frames_fd(n): return 1 if n<=62 else 1+math.ceil((n-62)/63)
    keys=["wire_2901","wire_6901","wire_2903","wire_6903"]
    vals={sname:(sum(frames_classic(int(rows[(sname,"total")][k])) for k in keys),sum(frames_fd(int(rows[(sname,"total")][k])) for k in keys)) for sname in SCHEMES}
    x0,y0,pw,ph=105,105,900,470
    ymax,tick_step=nice_axis(max(max(pair) for pair in vals.values()),6)
    tick=0.0
    while tick<=ymax:
        y=y0+ph-tick/ymax*ph;s.line(x0,y,x0+pw,y,stroke="#D5D5D5",stroke_width=1);s.text(x0-12,y+7,int(tick),21,anchor="end")
        tick+=tick_step
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
        choices=("latency", "payload", "tradeoff", "isotp"),
        default="latency",
        help="figure type to generate (default: latency)",
    )
    args = parser.parse_args()

    rows = load(args.input_csv)
    args.output_svg.parent.mkdir(parents=True, exist_ok=True)
    generators = {
        "latency": make_latency,
        "payload": make_payload,
        "tradeoff": make_tradeoff,
        "isotp": make_frames,
    }
    generators[args.figure](rows, args.output_svg)
    print(f"Generated {args.output_svg}")


if __name__ == "__main__":
    main()
