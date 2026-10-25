"""
NetRunner OS - Detection validation orchestration

Shared by the /detections routes and the detect_check CLI: take the recorded
runs, ask ExtraHop which detections fired in that window, and correlate them into
a scorecard + coverage grid. Falls back to a labelled sample result when no
appliance is configured, so the output is always usable.

Stdlib + the local core modules only (no scapy), so it runs headless.
"""

import time

from app.core import extrahop, detection_match
from app.core.runs import recent_runs
from app.core.settings import get_settings

WINDOW_SLACK_MS = 300_000  # widen the detection search 5 min each side of a run


def checkable_runs():
    """Recorded runs the detection loop can correlate (adversary + replay)."""
    runs = [r for r in recent_runs
            if r.get('scenario') in detection_match.SCENARIOS
            or r.get('kind') == 'replay']
    return list(reversed(runs))


def run_validation():
    """Return a validation result dict (sample, no_runs, appliance_error, or live)."""
    cfg = get_settings().get('extrahop', {})
    runs = checkable_runs()

    if not extrahop.is_configured(cfg):
        result = detection_match.sample_result()
        result['note'] = 'not_configured'
        return result

    if not runs:
        empty = detection_match.validate([], [])
        empty['note'] = 'no_runs'
        return empty

    now = int(time.time() * 1000)
    starts = [r['start_ms'] for r in runs if r.get('start_ms')]
    from_ms = (min(starts) - WINDOW_SLACK_MS) if starts else now - 3_600_000
    until_ms = now + WINDOW_SLACK_MS

    try:
        detections = extrahop.search_detections(cfg, from_ms, until_ms)
    except Exception as e:  # noqa: BLE001 - surface the error, keep output usable
        result = detection_match.sample_result()
        result['note'] = 'appliance_error'
        result['error'] = str(e)
        return result

    result = detection_match.validate(runs, detections)
    result['detection_total'] = len(detections)
    return result
