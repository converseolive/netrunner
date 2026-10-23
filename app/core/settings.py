"""
NetRunner OS - Settings store

Persists lab/appliance configuration as JSON. Right now it holds the ExtraHop
connection and the "internal networks" the appliance is configured to treat as
inside - the rewrite planner reads those so it can pick a lab range ExtraHop will
classify as internal, and warn when a chosen range falls outside them.

Pure stdlib (os/json/ipaddress) so it imports without Flask or scapy.
"""

import os
import json
import ipaddress

SETTINGS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    'data', 'settings.json'
)

_DEFAULTS = {
    "extrahop": {
        "base_url": "",
        "api_key_id": "",
        "api_key": "",
        "verify_tls": False,
        "internal_networks": [],
    }
}


def _ensure_file():
    os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
    if not os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'w') as f:
            json.dump(_DEFAULTS, f, indent=2)


def get_settings():
    """Return the stored settings merged over defaults."""
    _ensure_file()
    try:
        with open(SETTINGS_FILE) as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError):
        data = {}
    merged = {**_DEFAULTS, **data}
    merged["extrahop"] = {**_DEFAULTS["extrahop"], **(data.get("extrahop") or {})}
    return merged


def validate_networks(networks):
    """
    Validate a list of CIDR strings.

    Returns (ok, error_message, normalized_list). Blank entries are dropped;
    each kept entry is normalized to its canonical network form.
    """
    norm = []
    for n in networks or []:
        n = str(n).strip()
        if not n:
            continue
        try:
            net = ipaddress.ip_network(n, strict=False)
        except ValueError:
            return False, f"'{n}' is not a valid CIDR (e.g. 10.20.0.0/16).", []
        norm.append(str(net))
    return True, "", norm


def save_settings(data):
    """
    Merge `data` into the stored settings and persist. Raises ValueError if the
    ExtraHop internal_networks contain an invalid CIDR.

    The API key is only overwritten when a non-empty value is supplied, so a UI
    that never echoes the secret back can save other fields without wiping it.
    """
    current = get_settings()
    incoming = (data or {}).get("extrahop") or {}

    eh = dict(current["extrahop"])
    for k, v in incoming.items():
        if k == "internal_networks":
            continue
        if k == "api_key":
            if v:  # don't clobber a stored key with a blank
                eh["api_key"] = v
            continue
        if k == "verify_tls":
            eh["verify_tls"] = bool(v)
            continue
        eh[k] = v

    if "internal_networks" in incoming:
        ok, err, norm = validate_networks(incoming["internal_networks"])
        if not ok:
            raise ValueError(err)
        eh["internal_networks"] = norm

    current["extrahop"] = eh
    _ensure_file()
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(current, f, indent=2)
    return current


def public_settings():
    """Settings safe to send to the browser: the API key secret is masked."""
    s = get_settings()
    eh = dict(s["extrahop"])
    eh["api_key_set"] = bool(eh.get("api_key"))
    eh["api_key"] = ""
    s["extrahop"] = eh
    return s
