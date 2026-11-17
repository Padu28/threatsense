"""ThreatSense design system — "SOC Terminal".

Cyberpunk security-operations console: matrix-rain + glitch hero with a typing
shell session (canvas, iframe), CRT scanlines and flicker, terminal-window
panels with traffic-light chrome, neon glow, and a live alert ticker.
"""
from __future__ import annotations

import html
import json
from collections.abc import Iterable

import plotly.graph_objects as go
import plotly.io as pio
import streamlit as st
import streamlit.components.v1 as components

BRAND = "ThreatSense"
TAGLINE = "SOC console · explainable anomaly detection"
PRIMARY = "#ff2e63"     # alert red
SECONDARY = "#00ff9c"   # terminal green
ACCENT = "#ffb800"      # warning amber
SUCCESS, WARNING, DANGER, MUTED = "#00ff9c", "#ffb800", "#ff2e63", "#6b8a7a"
BG, SURFACE, BORDER, TEXT = "#030806", "rgba(0,255,156,0.035)", "rgba(0,255,156,0.22)", "#d5ffe9"
COLORWAY = [SECONDARY, PRIMARY, ACCENT, "#00d4ff", "#b967ff", "#ff6ec7", "#a3ff12", "#f0f0f0"]
MODEL_COLORS = {"majority_class": "#3d5a4c", "zscore_threshold": "#6b8a7a", "logistic_regression": "#00d4ff",
                "random_forest": PRIMARY, "hist_gradient_boosting": ACCENT, "isolation_forest": "#b967ff", "hybrid": SECONDARY}
PRIORITY_COLORS = {"critical": "#ff2e63", "high": "#ff7a00", "medium": "#ffb800", "low": "#00d4ff"}
CATEGORY_COLORS = {"benign": "#1f3b2e", "dos": "#ff2e63", "portscan": "#ffb800", "bruteforce": "#b967ff",
                   "botnet": "#00d4ff", "exfiltration": "#ff6ec7"}
SEVERITY_COLORS = {"critical": DANGER, "high": "#ff7a00", "medium": WARNING, "low": "#00d4ff", "info": SECONDARY}

MONO = "'JetBrains Mono', 'Fira Code', ui-monospace, monospace"
pio.templates["threatsense"] = go.layout.Template(layout=dict(
    font=dict(family=MONO, color=TEXT, size=12),
    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,255,156,0.02)", colorway=COLORWAY,
    xaxis=dict(gridcolor="rgba(0,255,156,0.09)", zeroline=False, linecolor=BORDER, tickfont=dict(color=MUTED)),
    yaxis=dict(gridcolor="rgba(0,255,156,0.09)", zeroline=False, linecolor=BORDER, tickfont=dict(color=MUTED)),
    legend=dict(bgcolor="rgba(0,0,0,0)", orientation="h", y=1.1, x=0, font=dict(color=MUTED)),
    margin=dict(l=10, r=10, t=40, b=10),
    hoverlabel=dict(bgcolor="#03140c", bordercolor=SECONDARY, font=dict(family=MONO, color=SECONDARY)),
    transition=dict(duration=400, easing="cubic-in-out"),
))
pio.templates.default = "plotly_dark+threatsense"

_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700;800&family=Chakra+Petch:wght@500;600;700&display=swap');
html, body, [class*="css"], .stMarkdown, p, li, label { font-family: __MONO__; }
.stApp { background:
    radial-gradient(1000px 500px at 50% -10%, #00ff9c14, transparent 60%),
    repeating-linear-gradient(0deg, transparent 0 3px, #00ff9c05 3px 4px), __BG__; }
/* CRT scanlines + flicker */
.stApp::before { content: ""; position: fixed; inset: 0; pointer-events: none; z-index: 998;
  background: repeating-linear-gradient(180deg, #0000 0 2px, #00000038 2px 3px); animation: flicker 6s infinite; }
@keyframes flicker { 0%,100% { opacity: .55; } 48% { opacity: .55; } 50% { opacity: .9; } 52% { opacity: .5; } }
.stApp::after { content: ""; position: fixed; inset: 0; pointer-events: none; z-index: 997;
  background: radial-gradient(ellipse at center, transparent 60%, #000a 100%); }
[data-testid="stHeader"] { background: #030806e6; border-bottom: 1px solid __BORDER__; backdrop-filter: blur(6px); }
[data-testid="stHeader"] a, [data-testid="stHeader"] button, [data-testid="stHeader"] span { font-family: __MONO__ !important; letter-spacing: .04em; }
.block-container { padding-top: 4.2rem; max-width: 1500px; }

@keyframes boot { 0% { opacity: 0; clip-path: inset(0 100% 0 0); } 100% { opacity: 1; clip-path: inset(0 0 0 0); } }
@keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
@keyframes blink { 50% { opacity: 0; } }
@keyframes glow { 0%,100% { box-shadow: 0 0 0 1px var(--c), 0 0 12px -2px var(--c); } 50% { box-shadow: 0 0 0 1px var(--c), 0 0 26px 0 var(--c); } }
@keyframes marquee { from { transform: translateX(0); } to { transform: translateX(-50%); } }
@keyframes ringFill { from { --ring: 0; } }
@property --ring { syntax: '<number>'; inherits: false; initial-value: 0; }
.element-container, .stPlotlyChart { animation: fadeIn .45s ease both; }

/* plain card (used inline by views) */
.card { border: 1px solid __BORDER__; background: #04110bcc; border-radius: 6px; padding: 14px 16px; margin-bottom: 12px; animation: fadeIn .4s ease both; }
.card p { margin: 0; color: #9fc9b2; font-size: .84rem; line-height: 1.6; }
/* terminal window panel */
.term { border: 1px solid __BORDER__; background: #04110bcc; border-radius: 8px; overflow: hidden; margin-bottom: 12px; animation: boot .6s steps(14) both; }
.term .bar { display: flex; align-items: center; gap: 6px; padding: 7px 12px; background: #062015; border-bottom: 1px solid __BORDER__;
  font-size: .7rem; color: __MUTED__; letter-spacing: .06em; }
.term .bar i { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }
.term .bar .t { margin-left: 8px; }
.term .body { padding: 14px 16px; }
.term h4 { margin: 0 0 6px; color: __SECONDARY__; font-size: .92rem; font-weight: 700; }
.term h4::before { content: "> "; color: __MUTED__; }
.term p { margin: 0; color: #9fc9b2; font-size: .84rem; line-height: 1.6; }

.kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 12px; margin: 8px 0 20px; }
.kpi { position: relative; padding: 14px 16px; background: #04140dcc; border-radius: 6px; --c: __BORDER__;
  border: 1px solid var(--c); animation: fadeIn .5s ease both; overflow: hidden; }
.kpi::after { content: ""; position: absolute; left: -40%; top: 0; width: 40%; height: 100%;
  background: linear-gradient(90deg, transparent, #00ff9c14, transparent); animation: sheen 4s ease-in-out infinite; }
@keyframes sheen { 0%,60% { left: -40%; } 100% { left: 120%; } }
.kpi.hot { animation: fadeIn .5s ease both, glow 2.2s ease-in-out infinite; }
.kpi .label { color: __MUTED__; font-size: .66rem; letter-spacing: .16em; text-transform: uppercase; }
.kpi .value { font-family: 'Chakra Petch', __MONO__; font-size: 1.9rem; font-weight: 700; margin-top: 4px; color: var(--vc); text-shadow: 0 0 14px var(--vc); }
.kpi .delta { font-size: .72rem; margin-top: 2px; }
.kpi .icon { position: absolute; right: 12px; top: 10px; font-size: 1.1rem; opacity: .55; }

.section { margin: 26px 0 10px; font-size: .95rem; color: __SECONDARY__; animation: fadeIn .4s ease both; display: flex; gap: 10px; align-items: baseline; }
.section .pr { color: __MUTED__; }
.section h3 { margin: 0; font-size: 1rem; font-weight: 700; color: __SECONDARY__; display: inline; }
.section h3::after { content: "_"; animation: blink 1s steps(1) infinite; margin-left: 2px; }
.section .sub { color: __MUTED__; font-size: .76rem; }

.tl-item { padding: 8px 12px; margin-bottom: 6px; border-left: 3px solid var(--sev); background: linear-gradient(90deg, color-mix(in srgb, var(--sev) 10%, transparent), transparent 70%);
  animation: fadeIn .35s ease both; font-size: .82rem; }
.tl-item .meta { font-size: .7rem; color: __MUTED__; }
.tl-item .msg { color: __TEXT__; margin-top: 2px; }
.chip { display: inline-block; padding: 0 7px; font-size: .66rem; font-weight: 800; text-transform: uppercase; letter-spacing: .1em;
  color: #031008; background: var(--c); border-radius: 2px; }

.ring { width: 136px; height: 136px; border-radius: 50%; margin: auto; display: grid; place-items: center; --ring: var(--val);
  background: repeating-conic-gradient(from 0deg, #0000 0 4deg, #031008 4deg 6deg), conic-gradient(var(--rc) calc(var(--ring) * 1%), #00ff9c14 0);
  animation: ringFill 1.6s steps(24) both; filter: drop-shadow(0 0 10px color-mix(in srgb, var(--rc) 50%, transparent)); }
.ring > div { width: 104px; height: 104px; border-radius: 50%; background: __BG__; display: grid; place-items: center;
  font: 700 1.6rem 'Chakra Petch', __MONO__; color: var(--rc); }

.flow { display: flex; align-items: center; flex-wrap: wrap; gap: 0; margin: 6px 0 12px; font-size: .8rem; }
.flow .node { padding: 8px 12px; border: 1px solid __BORDER__; background: #04140d; color: __SECONDARY__; animation: boot .5s steps(10) both; }
.flow .node small { display: block; color: __MUTED__; font-size: .66rem; }
.flow .arr { color: __PRIMARY__; padding: 0 6px; animation: blink 1.2s steps(1) infinite; }

/* ticker */
.ticker { position: relative; overflow: hidden; border: 1px solid #ff2e6355; background: #1a0509cc; border-radius: 4px; margin-bottom: 12px; height: 34px; }
.ticker .tag { position: absolute; left: 0; top: 0; bottom: 0; z-index: 2; display: flex; align-items: center; gap: 6px; padding: 0 12px;
  background: __PRIMARY__; color: #fff; font-weight: 800; font-size: .72rem; letter-spacing: .12em; }
.ticker .tag i { width: 7px; height: 7px; border-radius: 50%; background: #fff; animation: blink .8s steps(1) infinite; }
.ticker .track { display: inline-flex; white-space: nowrap; gap: 48px; padding-left: 140px; line-height: 34px; font-size: .78rem; color: #ffd0da;
  animation: marquee 38s linear infinite; }
.ticker:hover .track { animation-play-state: paused; }
.ticker .track b { color: __PRIMARY__; }

.stButton > button, .stDownloadButton > button { border-radius: 2px; border: 1px solid __SECONDARY__; background: transparent; color: __SECONDARY__;
  font-family: __MONO__; text-transform: uppercase; letter-spacing: .1em; font-size: .78rem; }
.stButton > button:hover { background: __SECONDARY__; color: #031008; box-shadow: 0 0 22px #00ff9c99; }
[data-testid="stDataFrame"] { border: 1px solid __BORDER__; border-radius: 4px; }
.disclaimer { font-size: .74rem; color: __MUTED__; border: 1px dashed #ffb80066; padding: 9px 12px; margin-top: 18px; }
.disclaimer::before { content: "[!] "; color: __ACCENT__; font-weight: 700; }
.footer { text-align: center; color: __MUTED__; font-size: .7rem; margin-top: 36px; letter-spacing: .14em; }
.footer b { color: __SECONDARY__; }
@media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation: none !important; } }
</style>
"""

_TOK = {"__BG__": BG, "__BORDER__": BORDER, "__TEXT__": TEXT, "__MUTED__": MUTED, "__PRIMARY__": PRIMARY,
        "__SECONDARY__": SECONDARY, "__ACCENT__": ACCENT, "__MONO__": MONO}


def _fill(s: str) -> str:
    for k, v in _TOK.items():
        s = s.replace(k, v)
    return s


def _e(s: object) -> str:
    return html.escape(str(s))


def apply_theme() -> None:
    st.markdown(_fill(_CSS), unsafe_allow_html=True)


_HERO = """<!DOCTYPE html><html><head><style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Chakra+Petch:wght@700&display=swap');
html,body{margin:0;background:transparent;overflow:hidden;font-family:'JetBrains Mono',ui-monospace,monospace}
.w{position:relative;height:__H__px;border:1px solid #00ff9c40;border-radius:10px;overflow:hidden;background:#020604}
canvas{position:absolute;inset:0;width:100%;height:100%;opacity:.55}
.fade{position:absolute;inset:0;background:linear-gradient(90deg,#020604 0%,#020604ee 45%,#02060466 75%,transparent)}
.l{position:absolute;left:28px;top:22px;right:330px}
.badge{font-size:11px;color:#020604;background:#00ff9c;padding:3px 9px;font-weight:700;letter-spacing:.14em;text-transform:uppercase}
.badge i{display:inline-block;width:7px;height:7px;background:#ff2e63;border-radius:50%;margin-right:6px;animation:bl .7s steps(1) infinite}
@keyframes bl{50%{opacity:0}}
h1{font-family:'Chakra Petch',sans-serif;font-size:44px;margin:12px 0 6px;color:#eafff4;position:relative;letter-spacing:.02em;text-shadow:0 0 18px #00ff9c88}
h1::before,h1::after{content:attr(data-t);position:absolute;left:0;top:0;width:100%;overflow:hidden}
h1::before{color:#ff2e63;transform:translate(2px,0);clip-path:inset(0 0 60% 0);animation:g1 2.8s infinite steps(2)}
h1::after{color:#00d4ff;transform:translate(-2px,0);clip-path:inset(55% 0 0 0);animation:g2 3.3s infinite steps(2)}
@keyframes g1{0%,88%,100%{transform:none;opacity:0}90%{transform:translate(4px,-2px);opacity:1}94%{transform:translate(-3px,1px);opacity:1}}
@keyframes g2{0%,84%,100%{transform:none;opacity:0}86%{transform:translate(-4px,2px);opacity:1}92%{transform:translate(3px,0);opacity:1}}
p{color:#8fb9a2;font-size:13px;line-height:1.6;margin:0;max-width:720px}
.sh{margin-top:12px;font-size:12px;color:#00ff9c;min-height:40px;white-space:pre}
.sh::after{content:'█';animation:bl 1s steps(1) infinite}
.g{position:absolute;right:30px;top:50%;transform:translateY(-50%);width:200px;height:200px}
.g svg{width:100%;height:100%}
.g .lv{position:absolute;inset:0;display:grid;place-items:center;text-align:center;color:#ff2e63;font:700 13px 'Chakra Petch',system-ui,sans-serif;letter-spacing:.14em}
.g .lv b{display:block;font-size:30px;color:#fff;text-shadow:0 0 16px #ff2e63}
@media(max-width:820px){.l{right:20px}.g{display:none}h1{font-size:32px}}
</style></head><body><div class="w"><canvas id="c"></canvas><div class="fade"></div>
<div class="l"><span class="badge"><i></i>__BADGE__</span><h1 data-t="__TITLE__">__TITLE__</h1><p>__SUBH__</p><div class="sh" id="sh"></div></div>
<div class="g"><svg viewBox="0 0 200 200"><circle cx="100" cy="100" r="86" fill="none" stroke="#ff2e6322" stroke-width="10"/>
<circle id="arc" cx="100" cy="100" r="86" fill="none" stroke="#ff2e63" stroke-width="10" stroke-linecap="round" stroke-dasharray="540" stroke-dashoffset="540" transform="rotate(-90 100 100)" style="transition:stroke-dashoffset 1.8s cubic-bezier(.16,1,.3,1);filter:drop-shadow(0 0 8px #ff2e63)"/>
<circle cx="100" cy="100" r="70" fill="none" stroke="#00ff9c33" stroke-dasharray="2 6"><animateTransform attributeName="transform" type="rotate" from="0 100 100" to="360 100 100" dur="14s" repeatCount="indefinite"/></circle>
</svg><div class="lv"><div>THREAT LEVEL<b id="lvn">--</b>ELEVATED</div></div></div></div>
<script>
const c=document.getElementById('c'),x=c.getContext('2d');let W,H,cols,drops;const ch='01ABCDEF<>/{}#$%&*アイウエオカキクケコ';
function rs(){W=c.width=c.offsetWidth;H=c.height=c.offsetHeight;cols=Math.floor(W/14);drops=Array(cols).fill(0).map(()=>Math.random()*H/14)}
rs();addEventListener('resize',rs);
setInterval(()=>{x.fillStyle='rgba(2,6,4,.14)';x.fillRect(0,0,W,H);x.font='13px JetBrains Mono, monospace';
 for(let i=0;i<cols;i++){const t=ch[Math.floor(Math.random()*ch.length)];x.fillStyle=Math.random()<.03?'#ff2e63':'#00ff9c';
  x.fillText(t,i*14,drops[i]*14);if(drops[i]*14>H&&Math.random()>.975)drops[i]=0;drops[i]++}},55);
const lines=__LINES__;const sh=document.getElementById('sh');let li=0,ci=0,buf='';
(function ty(){if(li>=lines.length){setTimeout(()=>{li=0;ci=0;buf='';ty()},4000);return}
 const L=lines[li];if(ci<=L.length){sh.textContent=buf+L.slice(0,ci);ci++;setTimeout(ty,22)}else{buf+=L+'\\n';if(buf.split('\\n').length>3)buf=buf.split('\\n').slice(-3).join('\\n');li++;ci=0;setTimeout(ty,450)}})();
setTimeout(()=>{document.getElementById('arc').style.strokeDashoffset=540*(1-__LEVEL__/100);let n=0;
 const iv=setInterval(()=>{n+=2;document.getElementById('lvn').textContent=Math.min(n,__LEVEL__);if(n>=__LEVEL__)clearInterval(iv)},20)},300);
</script></body></html>"""


def hero(title: str, subtitle: str, badge: str = "Live", icon: str = "🛡️", height: int = 250,
         level: int = 72, lines: list[str] | None = None) -> None:
    lines = lines or ["$ threatsense replay --window test --threshold frozen",
                      "[ok] scorer loaded · hybrid(rf+iforest) · calibrated",
                      "[!!] anomaly cluster detected · src 172.16.4.0/24 · triage queued"]
    doc = (_HERO.replace("__H__", str(height - 6)).replace("__BADGE__", _e(badge)).replace("__TITLE__", _e(title))
           .replace("__SUBH__", _e(subtitle)).replace("__LINES__", json.dumps(lines)).replace("__LEVEL__", str(int(level))))
    components.html(doc, height=height)


def ticker(items: list[str]) -> None:
    body = "".join(f"<span><b>◆</b> {_e(i)}</span>" for i in items) or "<span>No alerts</span>"
    st.markdown(f'<div class="ticker"><div class="tag"><i></i>LIVE</div><div class="track">{body}{body}</div></div>',
                unsafe_allow_html=True)


def kpis(items: Iterable[tuple]) -> None:
    cards = []
    for i, it in enumerate(items):
        label, value, delta, icon, color = (list(it) + [None] * 5)[:5]
        color = color or SECONDARY
        hot = " hot" if color in (PRIMARY, DANGER) else ""
        d = ""
        if delta:
            dc = SUCCESS if str(delta).startswith(("+", "▲")) else DANGER if str(delta).startswith(("-", "−", "▼")) else MUTED
            d = f'<div class="delta" style="color:{dc}">{_e(delta)}</div>'
        cards.append(f'<div class="kpi{hot}" style="--c:{color}88;--vc:{color};animation-delay:{i * .07:.2f}s">'
                     f'<div class="icon">{icon or ""}</div><div class="label">{_e(label)}</div>'
                     f'<div class="value">{_e(value)}</div>{d}</div>')
    st.markdown(f'<div class="kpi-grid">{"".join(cards)}</div>', unsafe_allow_html=True)


def section(title: str, sub: str = "") -> None:
    st.markdown(f'<div class="section"><span class="pr">root@soc:~$</span><h3>{_e(title)}</h3>'
                f'<span class="sub">{"# " + _e(sub) if sub else ""}</span></div>', unsafe_allow_html=True)


def card(title: str, body: str, accent: str = SECONDARY) -> None:
    st.markdown(f'<div class="term"><div class="bar"><i style="background:#ff5f57"></i><i style="background:#febc2e"></i>'
                f'<i style="background:#28c840"></i><span class="t">{_e(title.lower().replace(" ", "_"))}.log</span></div>'
                f'<div class="body" style="border-top:2px solid {accent}"><h4>{_e(title)}</h4><p>{body}</p></div></div>',
                unsafe_allow_html=True)


def chip(text: str, color: str) -> str:
    return f'<span class="chip" style="--c:{color}">{_e(text)}</span>'


def timeline(events: list[dict], limit: int = 8) -> None:
    out = []
    for i, ev in enumerate(events[:limit]):
        sev = SEVERITY_COLORS.get(ev.get("severity", "info"), SECONDARY)
        out.append(f'<div class="tl-item" style="--sev:{sev};animation-delay:{i * .05:.2f}s">'
                   f'<div class="meta">{chip(ev.get("event_type", ""), sev)} {_e(ev.get("batch_id", ""))} · {_e(ev.get("ts", ""))}</div>'
                   f'<div class="msg">{_e(ev.get("message", ""))}</div></div>')
    st.markdown("".join(out) or '<div class="term"><div class="body"><p>no events</p></div></div>', unsafe_allow_html=True)


def ring(value: float, label: str, color: str | None = None) -> None:
    color = color or (SUCCESS if value >= 80 else WARNING if value >= 60 else DANGER)
    st.markdown(f'<div style="text-align:center"><div class="ring" style="--val:{value:.0f};--rc:{color}"><div>{value:.0f}</div></div>'
                f'<div style="color:{MUTED};font-size:.7rem;letter-spacing:.14em;text-transform:uppercase;margin-top:10px">{_e(label)}</div></div>',
                unsafe_allow_html=True)


def flow(nodes: list[tuple[str, str]]) -> None:
    parts = [f'<div class="node" style="animation-delay:{i * .12:.2f}s">{_e(n)}<small>{_e(s)}</small></div>' for i, (n, s) in enumerate(nodes)]
    st.markdown(f'<div class="flow">{"<span class=arr>━━▶</span>".join(parts)}</div>', unsafe_allow_html=True)


def footer() -> None:
    st.markdown(f'<div class="footer"><b>{BRAND.upper()}</b> // DEFENSIVE RESEARCH PROTOTYPE // NO LIVE CAPTURE · NO SCANNING</div>',
                unsafe_allow_html=True)


def style_fig(fig: go.Figure, height: int = 360, title: str | None = None) -> go.Figure:
    fig.update_layout(height=height, title=dict(text=f"› {title}" if title else None, font=dict(size=13, color=SECONDARY)) if title else None)
    return fig
