"""
NetRunner OS - ExtraHop Reveal(x) REST client

Thin stdlib client the app uses to ask the ExtraHop appliance which detections it
raised, so a generated attack can be matched back to what the sensor caught.

Self-managed Reveal(x) appliances authenticate with a REST API key passed as
    Authorization: ExtraHop apikey=<KEY>
Lab appliances often present a self-signed certificate, so TLS verification is
configurable (and off by default for a lab).

The HTTP call is isolated behind a `fetch` callable so the request-building and
response-normalizing logic can be unit-tested without a live appliance.
"""

import json
import ssl
import urllib.request
import urllib.error


def _http_json(url, method, headers, body, verify_tls, timeout=15):
    """Perform one JSON request. Returns (status_code, parsed_json_or_None)."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    ctx = None
    if url.lower().startswith("https") and not verify_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        raw = resp.read()
        status = getattr(resp, "status", resp.getcode())
        return status, (json.loads(raw) if raw else None)


def _headers(cfg):
    return {
        "Authorization": f"ExtraHop apikey={cfg.get('api_key', '')}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _base(cfg):
    return (cfg.get("base_url") or "").rstrip("/")


def is_configured(cfg):
    return bool(_base(cfg) and cfg.get("api_key"))


def test_connection(cfg, fetch=_http_json):
    """Ping the appliance. Returns {ok, appliance?, version?, error?}."""
    base = _base(cfg)
    if not base:
        return {"ok": False, "error": "No base URL configured."}
    if not cfg.get("api_key"):
        return {"ok": False, "error": "No API key configured."}
    try:
        status, data = fetch(base + "/api/v1/extrahop", "GET",
                             _headers(cfg), None, cfg.get("verify_tls", False))
    except urllib.error.HTTPError as e:
        msg = "401 - check the API key" if e.code == 401 else f"HTTP {e.code} {e.reason}"
        return {"ok": False, "error": msg}
    except Exception as e:  # noqa: BLE001 - surface any transport error to the UI
        return {"ok": False, "error": str(e)}
    if status != 200:
        return {"ok": False, "error": f"HTTP {status}"}
    data = data or {}
    return {"ok": True,
            "appliance": data.get("display_name") or data.get("platform") or "ExtraHop",
            "version": data.get("version")}


def search_detections(cfg, from_ms, until_ms, limit=200, fetch=_http_json):
    """Return normalized detections in [from_ms, until_ms] (epoch ms)."""
    base = _base(cfg)
    body = {
        "from": int(from_ms),
        "until": int(until_ms),
        "limit": int(limit),
        "sort": [{"direction": "desc", "field": "start_time"}],
    }
    status, data = fetch(base + "/api/v1/detections/search", "POST",
                         _headers(cfg), body, cfg.get("verify_tls", False))
    if status not in (200, 201):
        raise RuntimeError(f"Detection search failed (HTTP {status}).")
    items = data if isinstance(data, list) else (data or {}).get("detections", [])
    return [normalize_detection(d) for d in (items or [])]


def normalize_detection(raw):
    """Map an ExtraHop detection object to the shape detection_match expects."""
    participants = []
    for p in raw.get("participants", []) or []:
        otype = p.get("object_type")
        ip = p.get("object_value") if otype in ("ipaddr", "device", None) else None
        participants.append({"role": p.get("role"), "ip": ip})

    def _ids(key):
        out = []
        for t in raw.get(key, []) or []:
            if isinstance(t, dict):
                out.append(t.get("id") or t.get("tech_id") or t.get("name"))
            else:
                out.append(t)
        return [x for x in out if x]

    return {
        "id": raw.get("id"),
        "title": raw.get("title") or raw.get("type"),
        "risk_score": raw.get("risk_score"),
        "techniques": _ids("mitre_techniques"),
        "tactics": _ids("mitre_tactics"),
        "categories": raw.get("categories", []) or [],
        "participants": participants,
        "start_ms": raw.get("start_time"),
        "end_ms": raw.get("end_time") or raw.get("update_time") or raw.get("start_time"),
    }
