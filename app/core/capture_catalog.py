"""
NetRunner OS - Recommended capture catalog

A short, curated list of public captures that exercise the same behaviours as
NetRunner's adversary scenarios, so a lab can validate detections with real
traffic rather than only synthetic generation.

Each entry was validated from its source's pages, directory listings and READMEs
(not by downloading the capture). Entries are real malware/attack traffic: keep
them off Windows hosts and replay them only into an isolated lab.
"""

from app.core.detection_match import SCENARIOS

_OTRF_RAW = ("https://github.com/OTRF/Security-Datasets/raw/refs/heads/master/"
             "datasets/atomic/windows/")
_OTRF_TREE = ("https://github.com/OTRF/Security-Datasets/tree/master/"
              "datasets/atomic/windows/")
_MCFP = "https://mcfp.felk.cvut.cz/publicDatasets/"
_MTA = "https://www.malware-traffic-analysis.net/"

SOURCES = {
    "stratosphere": {
        "name": "Stratosphere Lab (CTU)",
        "url": "https://www.stratosphereips.org/datasets-malware",
        "password": "Raw .pcap files are not zipped. Zipped extras use the password 'infected'.",
        "terms": "Cite: Garcia, Sebastian. Malware Capture Facility Project. stratosphereips.org.",
    },
    "mta": {
        "name": "Malware-Traffic-Analysis.net",
        "url": "https://www.malware-traffic-analysis.net/",
        "password": "Zips are password-protected; the current password scheme is on the "
                    "site's About page (malware-traffic-analysis.net/about.html).",
        "terms": "No licence stated; provided for researchers, use at your own risk. "
                 "Antivirus may flag the files.",
    },
    "otrf": {
        "name": "OTRF Security-Datasets",
        "url": "https://github.com/OTRF/Security-Datasets",
        "password": "Zips in the network/ folders; no password stated. Confirm the zip "
                    "contains a capture when you first extract it.",
        "terms": "Open-source research datasets (see repository licence).",
    },
    "netresec": {
        "name": "Netresec",
        "url": "https://www.netresec.com/?page=PcapFiles",
        "password": "Not password-protected.",
        "terms": "No licence stated on the page.",
    },
}

CATALOG = [
    # ── C2 beaconing ───────────────────────────────────────────────────────────
    {
        "id": "ctu13-neris",
        "title": "CTU-13 Scenario 1: Neris botnet",
        "source": "stratosphere",
        "page_url": _MCFP + "CTU-Malware-Capture-Botnet-42/",
        "file_url": _MCFP + "CTU-Malware-Capture-Botnet-42/botnet-capture-20110810-neris.pcap",
        "size": "56 MB", "format": "pcap",
        "scenarios": ["c2_beacon"],
        "techniques": ["T1071"],
        "summary": "About 6 hours of a bot calling an HTTP command-and-control server on a "
                   "regular schedule, plus spam and click-fraud.",
        "notes": "Botnet traffic only (no background). Best sustained-beaconing example in the set.",
    },
    {
        "id": "mta-2024-04-18-cobalt-strike",
        "title": "SSLoad loader followed by Cobalt Strike",
        "source": "mta",
        "page_url": _MTA + "2024/04/18/index.html",
        "file_url": _MTA + "2024/04/18/2024-04-18-SSLoad-with-follow-up-Cobalt-Strike-DLL.pcap.zip",
        "size": "4.6 MB", "format": "zip (password)",
        "scenarios": ["c2_beacon"],
        "techniques": ["T1071"],
        "summary": "A single infected Windows host loading Cobalt Strike, the C2 framework "
                   "most NDR beaconing detections are tuned against.",
        "notes": "C2 domains and IPs are in the post's separate IOC file, not the post text.",
    },
    {
        "id": "mta-2024-12-17-netsupport",
        "title": "Fake browser update leads to NetSupport RAT",
        "source": "mta",
        "page_url": _MTA + "2024/12/17/index.html",
        "file_url": _MTA + "2024/12/17/2024-12-17-SmartApeSG-to-NetSupport-RAT.pcap.zip",
        "size": "22.4 MB", "format": "zip (password)",
        "scenarios": ["c2_beacon"],
        "techniques": ["T1071"],
        "summary": "Remote-access trojan C2 as repeated HTTP POSTs to 194.180.191.64 on "
                   "port 443, after a fake-update download chain.",
        "notes": "",
    },
    # ── Data exfiltration ──────────────────────────────────────────────────────
    {
        "id": "mta-2025-03-26-stealc",
        "title": "NetSupport RAT and StealC data theft",
        "source": "mta",
        "page_url": _MTA + "2025/03/26/index.html",
        "file_url": _MTA + "2025/03/26/2025-03-26-SmartApeSG-leads-to-NetSupport-RAT-and-StealC.pcap.zip",
        "size": "35.7 MB", "format": "zip (password)",
        "scenarios": ["http_exfil", "c2_beacon"],
        "techniques": ["T1048", "T1071"],
        "summary": "StealC sending stolen data as repeated HTTP POSTs to "
                   "193.239.237.40, alongside NetSupport RAT C2.",
        "notes": "Strongest HTTP exfiltration example found.",
    },
    {
        "id": "mta-2025-01-31-smtp-exfil",
        "title": "Data exfiltration over SMTP (VIP Recovery)",
        "source": "mta",
        "page_url": _MTA + "2025/01/31/index.html",
        "file_url": _MTA + "2025/01/31/2025-01-31-VIP-Recovery-data-exfil-over-SMTP.pcap.zip",
        "size": "142 KB", "format": "zip (password)",
        "scenarios": ["http_exfil"],
        "techniques": ["T1048"],
        "summary": "A small, clean capture of stolen data sent out over SMTP.",
        "notes": "Exfiltration over SMTP, not HTTP. The same post has an FTP-exfil capture (5.8 KB).",
    },
    # ── DGA ────────────────────────────────────────────────────────────────────
    {
        "id": "ctu-zbot-25-5",
        "title": "Zbot (Zeus) with DGA lookups",
        "source": "stratosphere",
        "page_url": _MCFP + "CTU-Malware-Capture-Botnet-25-5/",
        "file_url": _MCFP + "CTU-Malware-Capture-Botnet-25-5/2014-03-12_capture-win3.pcap",
        "size": "282 MB", "format": "pcap",
        "scenarios": ["dga"],
        "techniques": ["T1568.002"],
        "summary": "Weeks of a bot querying algorithmically generated domains through 8.8.8.8.",
        "notes": "Spans about 30 days: replay with Fast speed and a per-capture time cap.",
    },
    # ── Scanning ───────────────────────────────────────────────────────────────
    {
        "id": "ctu-conficker-90",
        "title": "Conficker scanning the LAN",
        "source": "stratosphere",
        "page_url": _MCFP + "CTU-Malware-Capture-Botnet-90/",
        "file_url": _MCFP + "CTU-Malware-Capture-Botnet-90/192.168.3.104-unvirus.pcap",
        "size": "13 MB", "format": "pcap",
        "scenarios": ["port_scan"],
        "techniques": ["T1046"],
        "summary": "An infected host scanning a /16 for other hosts in bursts, with IRC C2 "
                   "on port 2081.",
        "notes": "Single-VM experiment, no background traffic.",
    },
    # ── Lateral movement ───────────────────────────────────────────────────────
    {
        "id": "otrf-empire-psexec",
        "title": "Empire PsExec-style service creation (SMB / SVCCTL)",
        "source": "otrf",
        "page_url": _OTRF_TREE + "lateral_movement/network",
        "file_url": _OTRF_RAW + "lateral_movement/network/empire_psexec_dcerpc_tcp_svcctl.zip",
        "size": "100 KB", "format": "zip",
        "scenarios": ["lateral_movement"],
        "techniques": ["T1021.002"],
        "summary": "Remote service creation over DCERPC/SVCCTL, the PsExec pattern.",
        "notes": "Same folder also has SMBExec and DCOM variants.",
    },
    {
        "id": "otrf-empire-psremoting",
        "title": "Empire PowerShell Remoting stager (WinRM)",
        "source": "otrf",
        "page_url": _OTRF_TREE + "lateral_movement/network",
        "file_url": _OTRF_RAW + "lateral_movement/network/empire_psremoting_stager.zip",
        "size": "not listed", "format": "zip",
        "scenarios": ["lateral_movement"],
        "techniques": ["T1021.006"],
        "summary": "Lateral movement over WinRM / PowerShell Remoting.",
        "notes": "",
    },
    {
        "id": "otrf-covenant-sharpwmi",
        "title": "Covenant SharpWMI remote process creation",
        "source": "otrf",
        "page_url": _OTRF_TREE + "lateral_movement/network",
        "file_url": _OTRF_RAW + "lateral_movement/network/covenant_sharpwmi_create_dcerpc_wmi.zip",
        "size": "not listed", "format": "zip",
        "scenarios": ["lateral_movement"],
        "techniques": ["T1047"],
        "summary": "Remote process creation through WMI over DCERPC.",
        "notes": "",
    },
    # ── DCSync ─────────────────────────────────────────────────────────────────
    {
        "id": "otrf-covenant-dcsync",
        "title": "Covenant DCSync (DRSUAPI DsGetNCChanges)",
        "source": "otrf",
        "page_url": _OTRF_TREE + "credential_access/network",
        "file_url": _OTRF_RAW + "credential_access/network/covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip",
        "size": "1.3 MB", "format": "zip",
        "scenarios": ["dcsync"],
        "techniques": ["T1003.006"],
        "summary": "A non-DC host pulling directory replication data from a domain "
                   "controller, the DCSync pattern.",
        "notes": "An Empire variant sits in the same folder.",
    },
    # ── Extra ExtraHop-relevant behaviour ──────────────────────────────────────
    {
        "id": "otrf-covenant-ldap-enum",
        "title": "Covenant LDAP domain-user enumeration",
        "source": "otrf",
        "page_url": _OTRF_TREE + "discovery/network",
        "file_url": _OTRF_RAW + "discovery/network/covenant_ldap_searchrequest_domainuser.cap",
        "size": "430 KB", "format": "cap",
        "scenarios": [],
        "techniques": ["T1087.002"],
        "summary": "LDAP queries enumerating domain users, a common recon detection.",
        "notes": "Not one of NetRunner's scenarios, but a useful extra detection to test. "
                 "Raw capture, no extraction needed.",
    },
    # ── Background realism ─────────────────────────────────────────────────────
    {
        "id": "netresec-maccdc-2012",
        "title": "MACCDC 2012 competition traffic",
        "source": "netresec",
        "page_url": "https://www.netresec.com/?page=MACCDC",
        "file_url": "https://share.netresec.com/s/7qgDSGNGw2NY8ea",
        "size": "multi-GB", "format": "pcap set",
        "scenarios": [],
        "techniques": [],
        "summary": "Busy, realistic network traffic from a cyber-defence competition with "
                   "an active red team.",
        "notes": "Background noise rather than a single technique. Very large: use a "
                 "per-capture time cap.",
        "category": "background",
    },
]


def catalog():
    """Catalog entries with their source details attached."""
    out = []
    for entry in CATALOG:
        e = dict(entry)
        e.setdefault("category", "technique")
        e["source_info"] = SOURCES[e["source"]]
        e["scenario_names"] = [SCENARIOS[s][0] for s in e["scenarios"] if s in SCENARIOS]
        out.append(e)
    return out


def coverage():
    """For each NetRunner scenario: which catalog entries cover it."""
    rows = []
    for key, (name, tactic, tech) in SCENARIOS.items():
        ids = [e["id"] for e in CATALOG if key in e["scenarios"]]
        rows.append({"scenario": key, "name": name, "technique": tech,
                     "captures": ids, "covered": bool(ids)})
    return rows
