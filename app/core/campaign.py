"""
NetRunner OS - Adversary Campaign

Runs the full adversary suite (or a chosen subset) as one sequential task: each
scenario fires to completion, is recorded in the run registry, then the next
starts. Running them one at a time keeps each technique's detections cleanly
separated on the ExtraHop timeline, and fills the Detections scorecard and
coverage matrix in a single click.

campaign_plan() is pure (easy to unit-test); run_campaign() is the task body the
route spawns on a background thread.
"""

from app.core.engine import active_task_status, register_run, log_message
from app.core.generators import adversary
from app.core.detection_match import SCENARIOS, scenario_meta

# Canonical run order: recon -> C2 -> exfil -> lateral -> credential, roughly
# the order these show up in an intrusion, following the scenario catalog.
CAMPAIGN_ORDER = list(SCENARIOS.keys())


def campaign_plan(settings, scenarios=None):
    """
    Build the ordered list of per-scenario generator params.

    `scenarios` optionally restricts the suite; unknown keys are dropped and the
    canonical order is always preserved.
    """
    wanted = set(scenarios) if scenarios else set(CAMPAIGN_ORDER)
    plan = []
    for key in CAMPAIGN_ORDER:
        if key not in wanted:
            continue
        plan.append({
            'interface': settings.get('interface', 'eth0'),
            'simulation': key,
            'src_ip': settings.get('src_ip', '10.0.0.100'),
            'dst_ip': settings.get('dst_ip', '10.0.0.1'),
            'c2_host': settings.get('c2_host', '185.100.87.42'),
            'src_mac': settings.get('src_mac'),
            'dst_mac': settings.get('dst_mac', 'ff:ff:ff:ff:ff:ff'),
            'count': int(settings.get('count', 30)),
            'delay': float(settings.get('delay', 0.1)),
            'domain': settings.get('domain', 'evil-c2.xyz'),
            'ipjitter': float(settings.get('ipjitter', 0) or 0),
        })
    return plan


def run_campaign(settings, scenarios=None):
    """Task body: fire each scenario in turn, recording a run for each."""
    plan = campaign_plan(settings, scenarios)
    total = len(plan)
    log_message(f"[*] Adversary campaign starting: {total} scenario(s).")
    try:
        for i, params in enumerate(plan):
            if not active_task_status['is_running']:
                log_message("[!] Campaign stopped.")
                break
            name = scenario_meta(params['simulation'])['name']
            active_task_status['message'] = f"Campaign {i + 1}/{total}: {name}"
            active_task_status['loop_count'] = i + 1

            register_run({
                'scenario': params['simulation'],
                'kind': 'adversary',
                'adversary_ip': params['src_ip'],
                'victim_ip': params['dst_ip'],
                'c2_ip': params['c2_host'],
                'interface': params['interface'],
            })
            try:
                adversary.run_one(params)
            except Exception as e:  # one scenario failing must not abort the suite
                log_message(f"[!] {params['simulation']} failed: {e}")
                continue

        if active_task_status['is_running']:
            active_task_status['message'] = f"Campaign finished: {total} scenario(s)."
            log_message("[+] Adversary campaign complete.")
    except Exception as e:  # noqa: BLE001
        active_task_status['error'] = str(e)
        log_message(f"[!!!] Campaign error: {e}")
    finally:
        active_task_status['is_running'] = False
        active_task_status['packets_per_second'] = 0
