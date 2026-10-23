"""
NetRunner OS - Detection-validation report

Renders a validate() result (see app/core/detection_match) into a standalone,
printable HTML report an operator can save or hand to a SOC audience: what was
generated, what ExtraHop caught, and where the gaps are.

Pure stdlib (html + time); no templates, no external assets.
"""

import html
import time

_STATUS_LABEL = {"detected": "Detected", "partial": "Partial",
                 "missed": "Missed", "not_run": "Not run"}
_STATUS_COLOR = {"detected": "#10936b", "partial": "#b7791f",
                 "missed": "#d1435b", "not_run": "#8a94ab"}


def _esc(v):
    return html.escape(str(v if v is not None else ""))


def _ms_to_s(ms):
    return f"{round(ms / 1000)}s" if ms is not None else "—"


def build_report_html(result, generated_at=None):
    summary = result.get("summary", {})
    rows = result.get("rows", [])
    coverage = result.get("coverage", [])
    when = generated_at or time.strftime("%Y-%m-%d %H:%M:%S")
    is_sample = bool(result.get("sample"))

    rate = round((summary.get("detection_rate") or 0) * 100)
    banner = ('<div class="banner">Sample data — connect an ExtraHop appliance '
              'to validate real runs.</div>') if is_sample else ""

    row_html = []
    for r in rows:
        st = r.get("status", "missed")
        color = _STATUS_COLOR.get(st, "#8a94ab")
        risk = r.get("risk")
        row_html.append(
            "<tr>"
            f"<td><strong>{_esc(r.get('name'))}</strong><br><span class='mono dim'>{_esc(r.get('technique') or '')}</span></td>"
            f"<td class='mono'>{_esc(r.get('flow'))}</td>"
            f"<td>{_esc(r.get('detection')) or '<span class=\"dim\">—</span>'}</td>"
            f"<td class='mono'>{risk if risk else '—'}</td>"
            f"<td class='mono'>{_ms_to_s(r.get('ttd_ms'))}</td>"
            f"<td><span class='pill' style='background:{color}1f;color:{color}'>{_STATUS_LABEL.get(st, st)}</span></td>"
            "</tr>"
        )

    cov_html = []
    for col in coverage:
        cells = "".join(
            f"<div class='cell' style='border-left:3px solid {_STATUS_COLOR.get(c.get('status'), '#ccc')}'>"
            f"{_esc(c.get('name'))}<br><span class='mono dim'>{_esc(c.get('technique') or '')} · {_STATUS_LABEL.get(c.get('status'), '')}</span></div>"
            for c in col.get("cells", [])
        )
        cov_html.append(f"<div class='cov-col'><h4>{_esc(col.get('tactic'))}</h4>{cells}</div>")

    gaps = [r for r in rows if r.get("status") == "missed"]
    gaps_html = ""
    if gaps:
        items = "".join(f"<li><strong>{_esc(g.get('name'))}</strong> "
                        f"<span class='mono dim'>{_esc(g.get('technique') or '')}</span> — "
                        f"no detection on {_esc(g.get('flow'))}</li>" for g in gaps)
        gaps_html = f"<h2>Coverage gaps</h2><ul class='gaps'>{items}</ul>"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>NetRunner Detection Report — {_esc(when)}</title>
<style>
  :root {{ --fg:#1a2233; --dim:#5a6681; --line:#dde3ef; --accent:#4a44c9; }}
  * {{ box-sizing:border-box; }}
  body {{ font-family:-apple-system,Segoe UI,Roboto,sans-serif; color:var(--fg); margin:0; padding:32px; max-width:980px; }}
  h1 {{ font-size:22px; margin:0 0 4px; }} h2 {{ font-size:16px; margin:28px 0 10px; }}
  h4 {{ font-size:12px; color:var(--dim); margin:0 0 8px; border-bottom:1px solid var(--line); padding-bottom:5px; }}
  .meta {{ color:var(--dim); font-size:13px; }}
  .mono {{ font-family:"JetBrains Mono",ui-monospace,Menlo,monospace; font-variant-numeric:tabular-nums; }}
  .dim {{ color:var(--dim); font-size:11px; }}
  .banner {{ background:#ebe9fd; color:var(--accent); padding:10px 14px; border-radius:8px; font-size:13px; margin:16px 0; }}
  .tiles {{ display:flex; gap:16px; flex-wrap:wrap; margin:18px 0; }}
  .tile {{ border:1px solid var(--line); border-radius:10px; padding:12px 16px; min-width:130px; }}
  .tile .n {{ font-size:26px; font-weight:700; }} .tile .l {{ font-size:11px; color:var(--dim); text-transform:uppercase; letter-spacing:.05em; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; margin-top:8px; }}
  th {{ text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.05em; color:var(--dim); border-bottom:1px solid var(--line); padding:8px; }}
  td {{ padding:9px 8px; border-bottom:1px solid var(--line); vertical-align:top; }}
  .pill {{ font-size:11px; font-weight:600; padding:2px 9px; border-radius:999px; }}
  .cov {{ display:flex; gap:12px; flex-wrap:wrap; }}
  .cov-col {{ flex:1; min-width:150px; }}
  .cell {{ font-size:12px; padding:7px 9px; background:#f4f6fb; border-radius:6px; margin-bottom:6px; }}
  ul.gaps {{ font-size:13px; line-height:1.7; }}
  @media print {{ body {{ padding:0; }} }}
</style></head><body>
  <h1>NetRunner Detection Validation Report</h1>
  <div class="meta">Generated {_esc(when)}{" · live appliance" if not is_sample else ""}</div>
  {banner}
  <div class="tiles">
    <div class="tile"><div class="n" style="color:#10936b">{rate}%</div><div class="l">Detection rate</div></div>
    <div class="tile"><div class="n">{summary.get('detected', 0)}</div><div class="l">Detected</div></div>
    <div class="tile"><div class="n" style="color:#b7791f">{summary.get('partial', 0)}</div><div class="l">Partial</div></div>
    <div class="tile"><div class="n" style="color:#d1435b">{summary.get('missed', 0)}</div><div class="l">Missed</div></div>
    <div class="tile"><div class="n">{_ms_to_s(summary.get('mean_ttd_ms'))}</div><div class="l">Mean TTD</div></div>
  </div>
  <h2>Scenario results</h2>
  <table><thead><tr><th>Scenario</th><th>Flow</th><th>ExtraHop detection</th><th>Risk</th><th>TTD</th><th>Status</th></tr></thead>
  <tbody>{''.join(row_html)}</tbody></table>
  <h2>MITRE ATT&amp;CK coverage</h2>
  <div class="cov">{''.join(cov_html)}</div>
  {gaps_html}
</body></html>"""
