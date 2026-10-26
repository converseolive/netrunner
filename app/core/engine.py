"""
NetRunner OS - Core Engine
Handles PCAP replay and status tracking.
"""

import time
import threading
from collections import deque
from scapy.all import PcapReader, sendp, get_if_hwaddr, Ether, IP, TCP, UDP, ICMP, Raw, Dot1Q

# ── Job manager ──────────────────────────────────────────────────────────────
# Each task (replay / generate / campaign) runs with its own status, so several
# can run concurrently without clobbering one another. Task code keeps using the
# module-level `active_task_status`; a thread-local proxy routes each thread's
# reads and writes to its own job's status dict (and to a shared fallback for any
# thread with no bound job).

MAX_CONCURRENT_JOBS = 10

_jobs = {}
_jobs_lock = threading.Lock()
_tls = threading.local()


def _new_status():
    return {
        'is_running': False, 'task_type': None, 'label': '', 'message': 'Ready.',
        'progress': 0, 'total': 0, 'loop_count': 0, 'packets_per_second': 0,
        'logs': deque(maxlen=200), 'error': None,
        'id': None, 'started_at': None, 'ended_at': None,
    }


_global_status = _new_status()  # fallback for threads with no bound job


class _StatusProxy:
    """Route active_task_status access to the calling thread's job, else global."""
    def _t(self):
        return getattr(_tls, 'status', _global_status)

    def __getitem__(self, k):
        return self._t()[k]

    def __setitem__(self, k, v):
        self._t()[k] = v

    def __contains__(self, k):
        return k in self._t()

    def get(self, k, default=None):
        return self._t().get(k, default)


active_task_status = _StatusProxy()


def log_message(msg):
    """Log to the console and the calling thread's job log."""
    print(msg)
    active_task_status['logs'].append(f'[{time.strftime("%H:%M:%S")}] {msg}')


def running_job_count():
    with _jobs_lock:
        return sum(1 for s in _jobs.values() if s.get('is_running'))


def new_job(task_type, label=''):
    jid = f"job-{int(time.time() * 1000)}-{len(_jobs)}"
    st = _new_status()
    st.update({'id': jid, 'task_type': task_type, 'label': label,
               'is_running': True, 'message': 'Starting...', 'started_at': time.time()})
    with _jobs_lock:
        _jobs[jid] = st
    return jid


def bind_job(jid):
    """Bind the calling thread's status to job `jid`."""
    _tls.status = _jobs[jid]


def run_job(task_type, target, args=(), label=''):
    """Start `target` on a daemon thread bound to a fresh job; return its id."""
    jid = new_job(task_type, label)

    def _runner():
        bind_job(jid)
        try:
            target(*args)
        except Exception as e:  # noqa: BLE001 - record on the job, keep others alive
            st = _jobs.get(jid)
            if st:
                st['error'] = str(e)
            log_message(f"[!!!] Task error: {e}")
        finally:
            st = _jobs.get(jid)
            if st:
                st['is_running'] = False
                st['packets_per_second'] = 0
                st['ended_at'] = time.time()

    threading.Thread(target=_runner, daemon=True).start()
    return jid


def get_job(jid):
    return _jobs.get(jid)


def stop_job(jid):
    st = _jobs.get(jid)
    if st:
        st['is_running'] = False
        return True
    return False


def stop_all_jobs():
    with _jobs_lock:
        for st in _jobs.values():
            st['is_running'] = False


def list_jobs(limit=30):
    with _jobs_lock:
        jobs = sorted(_jobs.values(), key=lambda s: s.get('started_at') or 0,
                      reverse=True)[:limit]
    return [{
        'id': s['id'], 'task_type': s['task_type'], 'label': s['label'],
        'is_running': s['is_running'], 'progress': s['progress'], 'total': s['total'],
        'packets_per_second': s['packets_per_second'], 'message': s['message'],
        'loop_count': s['loop_count'], 'error': s['error'],
        'started_at': s['started_at'], 'ended_at': s['ended_at'],
        'logs': list(s['logs'])[-40:],
    } for s in jobs]


def clear_finished_jobs():
    with _jobs_lock:
        for jid in [j for j, s in _jobs.items() if not s.get('is_running')]:
            del _jobs[jid]


# ── Run registry ─────────────────────────────────────────────────────────────
# Records of what traffic was generated/replayed, so the ExtraHop detection loop
# can correlate detections back to a scenario by IP + time window. Backed by the
# JSON-persisted store in app.core.runs and re-exported here so existing imports
# (from app.core.engine import register_run) keep working.
from app.core.runs import (  # noqa: E402,F401
    recent_runs, register_run, finish_run, clear_runs)


# ── PCAP Replay ──────────────────────────────────────────────────────────────

def replay_pcap_task(params: dict):
    """Replay a PCAP with optional rewrite rules applied on-the-fly."""
    try:
        log_message("[*] PCAP Replay Task Initialized.")
        log_message(f"    Interface: {params['interface']}")
        log_message(f"    Speed: {params['replay_speed']}, Loop: {params['loop_replay']}")

        if params['loop_replay']:
            loop_target = params['loop_count'] if params['loop_count'] > 0 else "Infinite"
            log_message(f"    Loop Count: {loop_target}")
        if params.get('ttl'):
            log_message(f"    Set TTL: {params['ttl']}")
        if params.get('vlan_id'):
            log_message(f"    Set VLAN ID: {params['vlan_id']}")
        if params.get('ip_map'):
            log_message(f"    IP Maps: {params['ip_map']}")
        if params.get('mac_map'):
            log_message(f"    MAC Maps: {params['mac_map']}")
        if params.get('port_map'):
            log_message(f"    Port Maps: {params['port_map']}")

        # Count packets
        log_message("[*] Counting packets...")
        with PcapReader(params['filepath']) as reader:
            total_packets = sum(1 for _ in reader)
        active_task_status['total'] = total_packets
        log_message(f"[*] Found {total_packets} packets.")

        current_loop = 1
        ip_map = params.get('ip_map', {})
        mac_map = params.get('mac_map', {})
        port_map = params.get('port_map', {})
        vlan_id = params.get('vlan_id')
        ttl = params.get('ttl')
        replay_speed = params.get('replay_speed', 'original')
        interface = params['interface']

        while active_task_status['is_running']:
            active_task_status['loop_count'] = current_loop
            log_message(f"[*] Starting replay loop #{current_loop}...")

            packets = PcapReader(params['filepath'])
            last_packet_time = None
            pps_start_time = time.time()
            pps_packet_count = 0

            for i, packet in enumerate(packets):
                if not active_task_status['is_running']:
                    log_message("[!] Stop signal received. Halting replay.")
                    break

                active_task_status['progress'] = i + 1
                active_task_status['message'] = f"Loop {current_loop}: Sending packet {i+1}/{total_packets}"

                pps_packet_count += 1
                if time.time() - pps_start_time >= 1.0:
                    active_task_status['packets_per_second'] = pps_packet_count
                    pps_packet_count = 0
                    pps_start_time = time.time()

                # Original timing
                if replay_speed == 'original':
                    if last_packet_time is None:
                        last_packet_time = packet.time
                    delay = packet.time - last_packet_time
                    if delay > 0:
                        time.sleep(float(delay))
                    last_packet_time = packet.time

                modified = packet.copy()

                # VLAN
                if vlan_id is not None:
                    if modified.haslayer(Dot1Q):
                        modified.getlayer(Dot1Q).vlan = vlan_id
                    elif modified.haslayer(Ether):
                        payload = modified[Ether].payload
                        modified = Ether(src=modified[Ether].src, dst=modified[Ether].dst) / Dot1Q(vlan=vlan_id) / payload

                # MAC rewrite
                if mac_map and modified.haslayer(Ether):
                    eth = modified.getlayer(Ether)
                    if eth.src in mac_map:
                        eth.src = mac_map[eth.src]
                    if eth.dst in mac_map:
                        eth.dst = mac_map[eth.dst]

                # IP rewrite
                if modified.haslayer(IP):
                    ip_layer = modified.getlayer(IP)
                    if ip_map:
                        if ip_layer.src in ip_map:
                            ip_layer.src = ip_map[ip_layer.src]
                        if ip_layer.dst in ip_map:
                            ip_layer.dst = ip_map[ip_layer.dst]
                    if ttl is not None:
                        ip_layer.ttl = ttl

                    # Port rewrite
                    if port_map:
                        if ip_layer.haslayer(TCP):
                            tcp = ip_layer.getlayer(TCP)
                            if str(tcp.sport) in port_map:
                                tcp.sport = int(port_map[str(tcp.sport)])
                            if str(tcp.dport) in port_map:
                                tcp.dport = int(port_map[str(tcp.dport)])
                        elif ip_layer.haslayer(UDP):
                            udp = ip_layer.getlayer(UDP)
                            if str(udp.sport) in port_map:
                                udp.sport = int(port_map[str(udp.sport)])
                            if str(udp.dport) in port_map:
                                udp.dport = int(port_map[str(udp.dport)])

                    # Recalculate checksums
                    if ip_layer.chksum is not None:
                        del ip_layer.chksum
                    if ip_layer.haslayer(TCP) and ip_layer[TCP].chksum is not None:
                        del ip_layer[TCP].chksum
                    elif ip_layer.haslayer(UDP) and ip_layer[UDP].chksum is not None:
                        del ip_layer[UDP].chksum

                sendp(modified, iface=interface, verbose=0)

            if not params['loop_replay']:
                break
            if params['loop_count'] > 0 and current_loop >= params['loop_count']:
                log_message(f"[*] Reached loop count ({params['loop_count']}).")
                break

            current_loop += 1
            active_task_status['progress'] = 0
            time.sleep(1)

        if active_task_status['is_running']:
            log_message("[+] Replay finished.")
            active_task_status['message'] = "Replay finished."

    except Exception as e:
        log_message(f"[!!!] Replay error: {e}")
        active_task_status['error'] = str(e)
        active_task_status['message'] = f"Error: {e}"
    finally:
        active_task_status['is_running'] = False
        active_task_status['packets_per_second'] = 0
        log_message("[+] Replay thread finished.")
