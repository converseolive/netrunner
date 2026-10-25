"""
NetRunner OS - Beacon scheduling

ExtraHop (and other NDR) beaconing detections baseline on *behaviour over time*:
a host calling out at a regular cadence, with low jitter, across a window. A
one-shot burst of callbacks does not exercise that. This computes a sustained
beacon schedule - a gap (seconds) before each callback - so the C2 simulation
can run for a set duration at a chosen interval with realistic jitter.

Pure stdlib; the random source is injectable so schedules are unit-testable.
"""

import random as _random


def beacon_schedule(duration_s, interval_s, jitter_pct, rng=None):
    """
    Return the list of inter-beacon gaps (seconds) for a campaign.

    Beacons fire about every `interval_s`, each gap jittered by +/- `jitter_pct`
    (0-95), for roughly `duration_s` in total. Returns [] for a non-positive
    duration or interval.
    """
    if interval_s <= 0 or duration_s <= 0:
        return []
    rng = rng or _random
    j = max(0.0, min(float(jitter_pct), 95.0)) / 100.0

    gaps = []
    elapsed = 0.0
    while elapsed < duration_s:
        gap = interval_s * (1 + rng.uniform(-j, j)) if j else interval_s
        gap = max(0.05, gap)
        gaps.append(gap)
        elapsed += gap
    return gaps


def jittered_delay(base_delay, jitter_pct, rng=None):
    """
    Return `base_delay` varied by +/- `jitter_pct` (0-95), floored at 0.

    Used between packets so generated traffic doesn't have robotically fixed
    timing. jitter_pct of 0 returns the base delay unchanged.
    """
    if base_delay <= 0:
        return 0.0
    j = max(0.0, min(float(jitter_pct), 95.0)) / 100.0
    if not j:
        return base_delay
    rng = rng or _random
    return max(0.0, base_delay * (1 + rng.uniform(-j, j)))
