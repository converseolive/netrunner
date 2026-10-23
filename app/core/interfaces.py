"""
NetRunner OS - Network interface enumeration

Generated and replayed traffic only reaches the ExtraHop sensor if it egresses
the interface the sensor watches (a SPAN/tap/monitor port). A free-text field
makes a typo fail silently, so the UI offers the host's real interfaces and the
routes preflight the chosen one.

Enumeration is best-effort and defensive: if scapy can't list interfaces, callers
fall back to not blocking rather than guessing wrong.
"""


def list_interfaces():
    """Return [{'name', 'mac'?, 'ip'?}] for the host's usable interfaces."""
    try:
        from scapy.all import get_working_ifaces
        out = []
        for iface in get_working_ifaces():
            name = getattr(iface, 'name', None)
            if not name:
                continue
            out.append({
                'name': name,
                'mac': getattr(iface, 'mac', None) or None,
                'ip': getattr(iface, 'ip', None) or None,
            })
        if out:
            return sorted(out, key=lambda i: i['name'])
    except Exception:
        pass

    try:
        from scapy.all import get_if_list
        return [{'name': n} for n in sorted(get_if_list())]
    except Exception:
        return []


def interface_names():
    return [i['name'] for i in list_interfaces()]


def validate_interface(iface):
    """
    Return (ok, error_message) for a chosen egress interface.

    Only rejects when interfaces could be enumerated and the name isn't among
    them - if enumeration fails we don't block, to avoid false negatives.
    """
    if not iface:
        return False, 'An egress interface is required.'
    names = interface_names()
    if names and iface not in names:
        return False, (f"Interface '{iface}' not found on this host. "
                       f"Available: {', '.join(names)}")
    return True, ''
