"""
NetRunner OS - Rewrite Audit

Answers the operator question: "I pulled this capture from somewhere else - which
entries do I need to rewrite before replaying it so it looks native to my lab,
and which must I leave alone so the detections still fire?"

Every distinct identifier in a capture falls into one of three buckets:

  * rewrite  - places the traffic *in your environment* (internal IPs, host/
               gateway MACs, VLAN tag). Leave them foreign and the NDR files the
               devices as unknown/external.
  * protect  - makes the attack still *look like the attack* (external/C2 IPs,
               service ports, relative timing). Changing these breaks the
               detection you are trying to validate.
  * review   - betrays the capture's origin but lives in the packet payload
               (embedded domains, SNI, HTTP Host, AD realm, odd TTLs). Rewriting
               these shifts TCP sequence numbers and record lengths, so it is
               high-effort and usually skipped.

This module is pure stdlib so it backs both the web route and any CLI without
pulling in scapy. It consumes the neutral `addressing` summary that
rewrite_planner already produces, plus a small `facts` dict of extra observations
the PCAP parse collects (VLAN IDs, TTLs, DNS names, HTTP hosts).
"""

import ipaddress
from collections import OrderedDict

from app.core.rewrite_planner import classify_ip, suggest_plan


# A tiny OUI table - just enough to name the common virtualization/lab vendors so
# the audit can say something concrete about a MAC instead of echoing the bytes.
_OUI_VENDORS = {
    "00:50:56": "VMware", "00:0c:29": "VMware", "00:05:69": "VMware",
    "00:1c:14": "VMware", "08:00:27": "VirtualBox", "0a:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM", "00:16:3e": "Xen", "00:15:5d": "Hyper-V",
    "00:00:0c": "Cisco", "00:1a:a1": "Cisco", "00:0d:3a": "Microsoft Azure",
    "00:25:90": "Supermicro", "00:1b:21": "Intel", "3c:fd:fe": "Intel",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
}

# TTL "birth" values. A capture whose TTLs sit well below one of these has been
# through routers on its way to the original sensor - a hint it was routed, not
# flat, in its home network.
_TTL_ORIGINS = (64, 128, 255)

_IGNORE_MACS = {"", "n/a", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _mac_oui(mac):
    return ":".join(mac.lower().split(":")[:3]) if mac else ""


def _is_locally_administered(mac):
    """True if the MAC's locally-administered bit is set (synthetic / VM MAC)."""
    try:
        first = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first & 0x02)


def _is_documentation_range(ip):
    """RFC5737 TEST-NET and RFC3849-style ranges that masquerade as external."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    doc_nets = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
    return any(addr in ipaddress.ip_network(n) for n in doc_nets)


def _is_cgnat(ip):
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network("100.64.0.0/10")
    except ValueError:
        return False


def _base_domain(name):
    """Registrable-ish base domain: the last two labels of a DNS/host name."""
    labels = [l for l in str(name).rstrip(".").split(".") if l]
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return labels[0] if labels else ""


def _finding(bucket, category, value, action, detail, severity,
             suggestion=None):
    f = {
        "bucket": bucket,          # rewrite | protect | review
        "category": category,
        "value": value,
        "action": action,
        "detail": detail,
        "severity": severity,      # high | medium | low
    }
    if suggestion:
        f["suggestion"] = suggestion
    return f


# ── Main entry point ──────────────────────────────────────────────────────────

def audit_capture(addressing, facts=None, lab_subnet=None):
    """
    Produce a per-identifier rewrite checklist for a capture.

    `addressing` - output of rewrite_planner.summarize_addressing().
    `facts`      - optional dict with any of:
                     hosts       [{"ip","mac"}]
                     vlans       [int]
                     ttls        [int]
                     dns_qnames  [str]
                     http_hosts  [str]
                     realms      [str]
    `lab_subnet` - optional target range (e.g. "10.99.0.0/16"); when given, the
                   rewrite findings carry the concrete target IP as a suggestion.

    Returns {"summary": {...}, "findings": [...]} with findings ordered
    rewrite -> review -> protect.
    """
    facts = facts or {}
    findings = []

    _audit_internal_ips(addressing, lab_subnet, findings)
    _audit_external_ips(addressing, findings)
    _audit_macs(addressing, facts, findings)
    _audit_vlans(facts, findings)
    _audit_ttls(facts, findings)
    _audit_ports(addressing, findings)
    _audit_embedded(facts, findings)
    _audit_timing(findings)

    # Order: rewrite first (what you must do), then review, then protect.
    bucket_rank = {"rewrite": 0, "review": 1, "protect": 2}
    sev_rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (bucket_rank.get(f["bucket"], 9),
                                 sev_rank.get(f["severity"], 9)))

    counts = {"rewrite": 0, "protect": 0, "review": 0}
    for f in findings:
        counts[f["bucket"]] = counts.get(f["bucket"], 0) + 1

    return {"summary": {**counts, "verdict": _verdict(counts)}, "findings": findings}


def _verdict(counts):
    parts = []
    if counts["rewrite"]:
        parts.append(f"{counts['rewrite']} identifier(s) to rewrite")
    else:
        parts.append("nothing requires rewriting")
    if counts["review"]:
        parts.append(f"{counts['review']} to review")
    parts.append(f"{counts['protect']} to protect")
    return ", ".join(parts) + "."


# ── Detectors ─────────────────────────────────────────────────────────────────

def _audit_internal_ips(addressing, lab_subnet, findings):
    """Internal (RFC1918) hosts must be pulled into the lab range."""
    internal = addressing.get("internal", [])
    if not internal:
        return

    ip_map = {}
    if lab_subnet:
        plan = suggest_plan(addressing, lab_subnet)
        ip_map = plan.get("ip_map", {})

    subnets = addressing.get("subnets", [])
    sub_label = ", ".join(s["cidr"] for s in subnets) if subnets else "RFC1918 space"

    for ip in internal:
        findings.append(_finding(
            "rewrite", "Internal host IP", ip,
            "Remap into your lab range",
            f"Private address from {sub_label}. Replayed as-is it will not match "
            f"your lab's addressing, so the NDR files it as an unknown device.",
            "high",
            suggestion=ip_map.get(ip),
        ))


def _audit_external_ips(addressing, findings):
    """External / C2 IPs are kept; documentation/CGNAT ranges are ambiguous."""
    for ip in addressing.get("external", []):
        if _is_documentation_range(ip):
            findings.append(_finding(
                "review", "Ambiguous locality", ip,
                "Confirm which side of the wire this is",
                "Sits in an RFC5737 documentation range. Depending on the parser "
                "it may be read as internal or as a bogon, so its role as an "
                "'external' host is not reliable - verify before you trust it.",
                "medium"))
        elif _is_cgnat(ip):
            findings.append(_finding(
                "review", "Ambiguous locality", ip,
                "Confirm locality",
                "Carrier-grade NAT range (100.64/10) - neither cleanly internal "
                "nor public. Decide which side it represents in your lab.",
                "low"))
        else:
            findings.append(_finding(
                "protect", "External host IP", ip,
                "Keep as-is",
                "Routable address. Leave it untouched so an outbound-to-C2 flow "
                "still looks external to the sensor.",
                "low"))


def _audit_macs(addressing, facts, findings):
    """Host / gateway MACs - shaped by whether the capture is routed or flat."""
    hosts = facts.get("hosts", [])
    macs = []
    seen = set()
    for h in hosts:
        mac = (h.get("mac") or "").lower().strip()
        if mac in _IGNORE_MACS or mac in seen:
            continue
        seen.add(mac)
        macs.append(mac)

    if not macs:
        return

    routed = addressing.get("routed")
    gateway = (addressing.get("gateway_mac") or "").lower()

    for mac in macs:
        vendor = _OUI_VENDORS.get(_mac_oui(mac))
        tells = []
        if vendor:
            tells.append(f"vendor {vendor}")
        if _is_locally_administered(mac):
            tells.append("locally-administered (synthetic/VM MAC)")
        tell_str = f" ({', '.join(tells)})" if tells else ""

        is_gw = gateway and mac == gateway
        if routed and not is_gw:
            findings.append(_finding(
                "review", "Host MAC (behind router)", mac,
                "Usually no change needed",
                f"Routed capture{tell_str}: this MAC belongs to the first-hop "
                f"router, not the end host, so it rarely needs rewriting unless "
                f"your sensor keys devices on MAC.",
                "low"))
        elif is_gw:
            findings.append(_finding(
                "rewrite", "Gateway MAC", mac,
                "Map to your lab gateway MAC (if an L2 device is in path)",
                f"Inferred first-hop router MAC{tell_str}. Rewrite it only when "
                f"your replay path has an active L2 device that filters on MAC.",
                "medium"))
        else:
            findings.append(_finding(
                "rewrite", "Host MAC (flat L2)", mac,
                "Rewrite for device continuity",
                f"Flat segment{tell_str}: the NDR may key this device on its MAC, "
                f"so align it with your lab or it shows up as a brand-new device.",
                "medium"))


def _audit_vlans(facts, findings):
    vlans = facts.get("vlans", [])
    if vlans:
        findings.append(_finding(
            "rewrite", "VLAN tag", ", ".join(str(v) for v in vlans),
            "Set to your sensor's segment VLAN",
            "Capture carries 802.1Q tags. Unless they already match the segment "
            "your ExtraHop sensor watches, the frames land on the wrong VLAN.",
            "medium"))
    else:
        findings.append(_finding(
            "review", "VLAN tag", "untagged",
            "Add a tag only if your sensor segment is tagged",
            "No 802.1Q tags present. If the monitored segment is a tagged VLAN, "
            "add the matching tag on replay; otherwise leave it untagged.",
            "low"))


def _audit_ttls(facts, findings):
    ttls = [int(t) for t in facts.get("ttls", []) if str(t).isdigit()]
    if not ttls:
        return
    low = [t for t in ttls if min((o - t) for o in _TTL_ORIGINS if o >= t) >= 3] \
        if any(o >= t for t in ttls for o in _TTL_ORIGINS) else []
    if low:
        findings.append(_finding(
            "review", "TTL / hop count", ", ".join(str(t) for t in sorted(set(ttls))),
            "Normalize only for deep realism",
            "Some TTLs sit several hops below a fresh value, so the capture was "
            "routed in its origin network. On a flat lab segment that is a faint "
            "tell; normalize to a single value if you care, but it rarely matters "
            "to the NDR.",
            "low"))


def _audit_ports(addressing, findings):
    mix = addressing.get("protocol_mix", [])
    if mix:
        protos = ", ".join(m["protocol"] for m in mix[:6])
        findings.append(_finding(
            "protect", "Service ports", protos,
            "Keep service ports unchanged",
            "Ports are how the NDR classifies each protocol (443 as TLS, 88 as "
            "Kerberos, and so on). Renumbering them hides the very behavior you "
            "want detected.",
            "low"))


def _audit_embedded(facts, findings):
    """Domains / hostnames in the payload - betray origin, high cost to change."""
    domains = set()
    for name in facts.get("dns_qnames", []):
        b = _base_domain(name)
        if b:
            domains.add(b)
    for host in facts.get("http_hosts", []):
        b = _base_domain(host.split(":")[0])
        if b:
            domains.add(b)
    realms = {r for r in facts.get("realms", []) if r}

    if domains:
        shown = sorted(domains)[:8]
        extra = "" if len(domains) <= 8 else f" (+{len(domains) - 8} more)"
        findings.append(_finding(
            "review", "Embedded domains", ", ".join(shown) + extra,
            "Usually leave as-is",
            "These names appear in DNS/HTTP payloads. They reveal the capture's "
            "origin, but rewriting a string shifts every later TCP sequence "
            "number and breaks record-length fields - high effort for little "
            "detection gain, since the NDR keys on behavior, not the domain.",
            "medium"))
    if realms:
        findings.append(_finding(
            "review", "Kerberos / AD realm", ", ".join(sorted(realms)),
            "Leave unless mirroring your AD",
            "The capture's Active Directory realm differs from your lab domain. "
            "Rewriting it inside Kerberos is fragile; most labs accept the "
            "mismatch.",
            "low"))


def _audit_timing(findings):
    findings.append(_finding(
        "protect", "Relative timing", "inter-packet gaps",
        "Replay with original timing",
        "Beaconing and other behavioral detections baseline on the gaps between "
        "packets. Preserve original timing; compressing it can erase the pattern "
        "you are testing for.",
        "low"))
