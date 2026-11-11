"""
NetRunner OS - Play all (capture playlist)

Replay a set of saved captures back to back as one job. Each capture is
rewritten into its own non-overlapping block of the lab range (so two captures
never collapse onto the same lab hosts in the NDR's device inventory), replayed,
and recorded as its own run so the detection loop can attribute detections to
the capture that caused them. Captures run one after another, with an optional
gap, to keep attribution clean.
"""

import os
import time

from app.core.rewrite_planner import summarize_addressing, suggest_plan, classify_ip
from app.core.engine import (active_task_status, log_message, replay_once,
                             register_run, finish_run)

CAPTURE_EXTS = ('.pcap', '.pcapng', '.cap', '.gz')

# (path, mtime, size) -> hosts, so preview + play don't parse a capture twice.
_hosts_cache = {}


# ── Library ───────────────────────────────────────────────────────────────────

def is_capture_name(name):
    return (bool(name) and not name.startswith('rewritten_')
            and name.lower().endswith(CAPTURE_EXTS))


def list_captures(folder):
    """Saved captures in `folder` (rewrite outputs excluded), sorted by name."""
    out = []
    if not os.path.isdir(folder):
        return out
    for name in sorted(os.listdir(folder)):
        path = os.path.join(folder, name)
        if not is_capture_name(name) or not os.path.isfile(path):
            continue
        st = os.stat(path)
        out.append({'name': name, 'size': st.st_size, 'modified': st.st_mtime})
    return out


def resolve_capture(folder, name):
    """Absolute path of a saved capture, or None. Refuses any path traversal."""
    if not name or os.path.basename(name) != name or not is_capture_name(name):
        return None
    root = os.path.realpath(folder)
    path = os.path.realpath(os.path.join(root, name))
    if not path.startswith(root + os.sep) or not os.path.isfile(path):
        return None
    return path


def capture_hosts(path):
    """[{'ip', 'mac'}] observed in a capture. Cached by path + mtime + size."""
    st = os.stat(path)
    key = (path, st.st_mtime, st.st_size)
    if key in _hosts_cache:
        return _hosts_cache[key]

    from scapy.all import PcapReader, IP, Ether
    ip_to_mac = {}
    with PcapReader(path) as reader:
        for pkt in reader:
            if not pkt.haslayer(IP):
                continue
            src, dst = pkt[IP].src, pkt[IP].dst
            if pkt.haslayer(Ether):
                ip_to_mac[src] = pkt[Ether].src
                ip_to_mac[dst] = pkt[Ether].dst
            else:
                ip_to_mac.setdefault(src, '')
                ip_to_mac.setdefault(dst, '')
    hosts = [{'ip': ip, 'mac': mac} for ip, mac in ip_to_mac.items()]
    _hosts_cache[key] = hosts
    return hosts


# ── Planning ──────────────────────────────────────────────────────────────────

def internal_block_count(hosts):
    return len(summarize_addressing(hosts).get('subnets', []))


def build_playlist_plan(entries, lab_subnet, internal_networks=None):
    """
    Plan every capture into its own blocks of `lab_subnet`.

    `entries` is [{'name', 'path', 'hosts'}]. Each capture's internal /24s start
    where the previous capture's stopped, so no two captures share lab hosts.
    Returns one plan dict per capture, in order.
    """
    offset = 0
    plans = []
    for e in entries:
        addressing = summarize_addressing(e['hosts'])
        plan = suggest_plan(addressing, lab_subnet,
                            internal_networks=internal_networks, block_offset=offset)
        offset += len(addressing.get('subnets', []))

        mapped = set(plan['ip_map'])
        # On the wire after rewrite: the lab addresses plus untouched externals.
        wire_ips = list(plan['ip_map'].values()) + [
            h['ip'] for h in e['hosts']
            if h['ip'] not in mapped and classify_ip(h['ip']) == 'external'
        ]
        plans.append({
            'name': e['name'],
            'path': e['path'],
            'host_count': len(e['hosts']),
            'ip_map': plan['ip_map'],
            'subnet_map': plan['subnet_map'],
            'notes': plan['notes'],
            'warnings': plan['warnings'],
            'wire_ips': wire_ips,
        })
    return plans


# ── Runner ────────────────────────────────────────────────────────────────────

def run_playlist(plans, options):
    """
    Job body: replay each planned capture in turn, recording a run for each.
    Stop-aware between and during captures; one capture failing doesn't stop
    the rest.
    """
    total = len(plans)
    gap = float(options.get('gap_seconds') or 0)
    failures = []
    log_message(f"[*] Play all starting: {total} capture(s).")

    for i, p in enumerate(plans):
        if not active_task_status['is_running']:
            log_message("[!] Play all stopped.")
            break
        active_task_status['label'] = f"Play all ({i + 1}/{total}): {p['name']}"
        log_message(f"[*] Capture {i + 1}/{total}: {p['name']}")

        rid = register_run({
            'kind': 'replay',
            'scenario': None,
            'label': f"Replay: {p['name']}",
            'ips': p['wire_ips'],
            'interface': options['interface'],
        })
        params = {
            'filepath': p['path'],
            'interface': options['interface'],
            'replay_speed': options.get('speed', 'original'),
            'loop_replay': False,
            'loop_count': 0,
            'ttl': options.get('ttl'),
            'vlan_id': options.get('vlan_id'),
            'ip_map': p['ip_map'],
            'mac_map': {},
            'port_map': {},
            'max_seconds': options.get('max_seconds'),
        }
        try:
            replay_once(params)
        except Exception as e:  # keep going with the next capture
            failures.append(p['name'])
            log_message(f"[!] {p['name']} failed: {e}")
        finally:
            finish_run(rid)

        if i < total - 1 and gap > 0:
            waited = 0.0
            while waited < gap and active_task_status['is_running']:
                step = min(0.5, gap - waited)
                time.sleep(step)
                waited += step

    if failures:
        active_task_status['error'] = (
            f"{len(failures)} of {total} capture(s) failed: {', '.join(failures)}")
    if active_task_status['is_running']:
        active_task_status['message'] = f"Play all finished: {total} capture(s)."
        log_message("[+] Play all complete.")
