"""
NetRunner OS - Detection Correlation

Closes the loop: given the traffic NetRunner generated (a list of "runs") and the
detections ExtraHop raised in that window, it works out - per scenario - whether
the sensor caught it, and rolls the result up into a MITRE ATT&CK coverage grid.

Matching is by participant IP overlap + time overlap, then the run's expected
MITRE technique against the detection's techniques:

  * detected - a detection on the right hosts/time whose technique matches.
  * partial  - something fired on the right hosts/time, but a different technique.
  * missed   - nothing fired.

Pure stdlib so it unit-tests without an appliance. ExtraHop detections are passed
in already normalized (see app/core/extrahop.normalize_detection).
"""

import time

# scenario key -> (display name, ATT&CK tactic, technique id)
SCENARIOS = {
    "c2_beacon":        ("C2 Beaconing",            "Command & Control", "T1071"),
    "dga":              ("DGA Traffic",             "Command & Control", "T1568.002"),
    "port_scan":        ("Port Scanning",           "Discovery",         "T1046"),
    "lateral_movement": ("Lateral Movement",        "Lateral Movement",  "T1021"),
    "dns_exfil":        ("DNS Exfiltration",        "Exfiltration",      "T1048.003"),
    "http_exfil":       ("HTTP Exfiltration",       "Exfiltration",      "T1048"),
    "icmp_tunnel":      ("ICMP Tunneling",          "Exfiltration",      "T1048.003"),
    "kerberoast":       ("Kerberoasting",           "Credential Access", "T1558.003"),
    "dcsync":           ("DCSync",                  "Credential Access", "T1003.006"),
    "llmnr_poison":     ("LLMNR/NBT-NS Poisoning",  "Credential Access", "T1557.001"),
    "ntlm_relay":       ("NTLM Relay",              "Credential Access", "T1557.001"),
    "arp_spoof":        ("ARP Spoofing",            "Credential Access", "T1557.002"),
}

# ATT&CK tactic column order for the coverage grid.
TACTIC_ORDER = ["Discovery", "Credential Access", "Lateral Movement",
                "Command & Control", "Exfiltration"]

_MATCH_SLACK_MS = 120_000  # ±2 min around a run when correlating detections


def scenario_meta(key):
    name, tactic, tech = SCENARIOS.get(key, (key, "Other", None))
    return {"name": name, "tactic": tactic, "technique": tech}


# ── Matching ──────────────────────────────────────────────────────────────────

def _run_ips(run):
    ips = set()
    for k in ("adversary_ip", "victim_ip", "c2_ip"):
        v = run.get(k)
        if v:
            ips.add(v)
    for v in run.get("ips", []) or []:
        if v:
            ips.add(v)
    return ips


def _now_ms():
    return int(time.time() * 1000)


def _overlaps(det, lo, hi):
    s = det.get("start_ms")
    if s is None:
        return True  # undated detection: fall back to IP match alone
    e = det.get("end_ms") or s
    return not (e < lo or s > hi)


def _match_run(run, detections):
    """Return (status, matched_detections, risk, ttd_ms) for one run."""
    rips = _run_ips(run)
    start = run.get("start_ms") or _now_ms()
    end = run.get("end_ms") or _now_ms()
    lo, hi = start - _MATCH_SLACK_MS, end + _MATCH_SLACK_MS
    tech = scenario_meta(run.get("scenario", "")).get("technique")

    candidates = []
    for det in detections:
        det_ips = {p.get("ip") for p in det.get("participants", []) if p.get("ip")}
        if rips & det_ips and _overlaps(det, lo, hi):
            candidates.append(det)

    if not candidates:
        return "missed", [], None, None

    if not tech:
        # No expected technique (e.g. a PCAP replay): any detection on these
        # hosts in-window counts as caught.
        chosen = candidates
        status = "detected"
    else:
        tech_hits = [d for d in candidates
                     if not d.get("techniques") or tech in d["techniques"]]
        chosen = tech_hits or candidates
        status = "detected" if tech_hits else "partial"
    risk = max((d.get("risk_score") or 0) for d in chosen)
    starts = [d["start_ms"] for d in chosen if d.get("start_ms") is not None]
    ttd = max(0, min(starts) - start) if starts else None
    return status, chosen, risk, ttd


# ── Scorecard + coverage ──────────────────────────────────────────────────────

def build_scorecard(runs, detections):
    """Per-run detection outcome rows plus a summary."""
    rows = []
    for run in runs:
        if run.get("kind") == "replay":
            meta = {"name": run.get("label") or "PCAP replay",
                    "tactic": "Replay", "technique": None}
        else:
            meta = scenario_meta(run.get("scenario", ""))
        status, matched, risk, ttd = _match_run(run, detections)
        rows.append({
            "scenario": run.get("scenario"),
            "name": meta["name"],
            "tactic": meta["tactic"],
            "technique": meta["technique"],
            "flow": _flow(run),
            "status": status,
            "risk": risk,
            "ttd_ms": ttd,
            "detection": matched[0]["title"] if matched else None,
            "detection_count": len(matched),
        })

    detected = [r for r in rows if r["status"] == "detected"]
    partial = [r for r in rows if r["status"] == "partial"]
    ttds = [r["ttd_ms"] for r in detected if r["ttd_ms"] is not None]
    summary = {
        "total": len(rows),
        "detected": len(detected),
        "partial": len(partial),
        "missed": sum(1 for r in rows if r["status"] == "missed"),
        "detection_rate": round(len(detected) / len(rows), 3) if rows else 0.0,
        "mean_ttd_ms": int(sum(ttds) / len(ttds)) if ttds else None,
    }
    return {"summary": summary, "rows": rows}


def build_coverage(runs):
    """MITRE grid: every scenario the tool can run, coloured by outcome."""
    status_by_scenario = {}
    # A scenario may be run more than once; keep the best outcome.
    rank = {"detected": 3, "partial": 2, "missed": 1, "not_run": 0}
    tmp = {}
    for run in runs:
        key = run.get("scenario")
        st = run.get("_status", "missed")
        if rank.get(st, 0) >= rank.get(tmp.get(key, "not_run"), 0):
            tmp[key] = st
    status_by_scenario = tmp

    by_tactic = {}
    for key, (name, tactic, tech) in SCENARIOS.items():
        by_tactic.setdefault(tactic, []).append({
            "scenario": key, "name": name, "technique": tech,
            "status": status_by_scenario.get(key, "not_run"),
        })

    columns = []
    for tactic in TACTIC_ORDER:
        if tactic in by_tactic:
            columns.append({"tactic": tactic, "cells": by_tactic[tactic]})
    for tactic, cells in by_tactic.items():
        if tactic not in TACTIC_ORDER:
            columns.append({"tactic": tactic, "cells": cells})
    return columns


def validate(runs, detections):
    """Full result: scorecard + coverage, from runs and ExtraHop detections."""
    scorecard = build_scorecard(runs, detections)
    # annotate runs with their outcome so the coverage grid reflects results
    annotated = [{**run, "_status": row["status"]}
                 for run, row in zip(runs, scorecard["rows"])]
    coverage = build_coverage(annotated)
    return {
        "sample": False,
        "summary": scorecard["summary"],
        "rows": scorecard["rows"],
        "coverage": coverage,
    }


def _flow(run):
    a = run.get("adversary_ip") or "?"
    b = run.get("victim_ip") or run.get("c2_ip") or "?"
    return f"{a} → {b}"


# ── Sample result (shown before an appliance is connected) ────────────────────

def sample_result():
    """A representative result so the Detections view is populated pre-connect."""
    now = _now_ms()
    runs = [
        {"scenario": "c2_beacon", "adversary_ip": "10.20.9.15", "c2_ip": "185.100.87.42",
         "start_ms": now - 600_000, "end_ms": now - 580_000},
        {"scenario": "http_exfil", "adversary_ip": "10.20.9.15", "c2_ip": "185.100.87.42",
         "start_ms": now - 560_000, "end_ms": now - 550_000},
        {"scenario": "port_scan", "adversary_ip": "10.20.14.66", "victim_ip": "10.20.9.15",
         "start_ms": now - 520_000, "end_ms": now - 515_000},
        {"scenario": "lateral_movement", "adversary_ip": "10.20.14.66", "victim_ip": "10.20.9.20",
         "start_ms": now - 480_000, "end_ms": now - 470_000},
        {"scenario": "dcsync", "adversary_ip": "10.20.14.66", "victim_ip": "10.20.9.4",
         "start_ms": now - 440_000, "end_ms": now - 430_000},
        {"scenario": "kerberoast", "adversary_ip": "10.20.14.66", "victim_ip": "10.20.9.4",
         "start_ms": now - 400_000, "end_ms": now - 395_000},
        {"scenario": "dns_exfil", "adversary_ip": "10.20.9.16", "victim_ip": "10.20.9.53",
         "start_ms": now - 360_000, "end_ms": now - 350_000},
        {"scenario": "icmp_tunnel", "adversary_ip": "10.20.9.15", "victim_ip": "10.20.9.1",
         "start_ms": now - 320_000, "end_ms": now - 315_000},
    ]

    def det(title, tech, ips, start_off, risk):
        return {"id": title, "title": title, "risk_score": risk,
                "techniques": [tech], "tactics": [], "categories": [],
                "participants": [{"role": "offender", "ip": ips[0]},
                                 {"role": "victim", "ip": ips[1]}],
                "start_ms": now - start_off, "end_ms": now - start_off + 5000}

    detections = [
        det("Command-and-Control Beaconing", "T1071", ["10.20.9.15", "185.100.87.42"], 569_000, 82),
        det("Data Exfiltration to External Host", "T1048", ["10.20.9.15", "185.100.87.42"], 548_000, 88),
        det("Port Scan", "T1046", ["10.20.14.66", "10.20.9.15"], 514_000, 55),
        det("Lateral Movement via SMB", "T1021", ["10.20.14.66", "10.20.9.20"], 468_000, 79),
        det("Suspected DCSync", "T1003.006", ["10.20.14.66", "10.20.9.4"], 429_000, 95),
        det("Kerberoasting", "T1558.003", ["10.20.14.66", "10.20.9.4"], 394_000, 77),
        # dns_exfil intentionally not detected (a gap); icmp_tunnel gets a
        # different-technique detection -> partial.
        det("Unusual ICMP Payload", "T1572", ["10.20.9.15", "10.20.9.1"], 314_000, 48),
    ]

    result = validate(runs, detections)
    result["sample"] = True
    return result
