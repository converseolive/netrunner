# NetRunner Console

NetRunner is a lab tool for **validating NDR detections on an ExtraHop Reveal(x) sensor**. You generate adversary and protocol traffic (or replay a captured PCAP) onto the segment the sensor watches, then NetRunner asks the appliance which detections fired and scores the result against MITRE ATT&CK — closing the loop from *traffic sent* to *detection caught*.

It runs as a self-contained Flask app with a browser console. Packet work is done with Scapy, so sending traffic requires root; everything else (analysis, auditing, planning, reporting) runs unprivileged.

## What it does

- **PCAP analysis** — upload a capture and inspect it: a Wireshark-style packet view, endpoints, conversations, a traffic-flow diagram, and heuristic threat scoring that flags likely adversary→victim streams with MITRE technique tags (no external intel; all local).
- **Rewrite audit** — before you replay a downloaded capture, it sorts every identifier into **rewrite** (make it native), **review** (betrays origin, costly to change), or **protect** (leave it or the detection breaks), so you know exactly what to change.
- **Rewrite planner** — maps the capture's internal subnets into your lab range while preserving host octets, leaves external/C2 addresses alone, and (when you configure your ExtraHop internal networks) picks a lab range the sensor will treat as internal and warns when a chosen range would classify as external.
- **Replay** — stream a PCAP to an interface with on-the-fly IP/MAC/port/TTL/VLAN rewrites.
- **Traffic generator** — benign protocol sessions (DNS, HTTP, FTP, SMTP, SNMP, NTP, ICMP) and twelve adversary simulations (C2 beaconing, DNS/HTTP/ICMP exfiltration, port scan, lateral movement, DGA, Kerberoasting, DCSync, LLMNR/NBT-NS poisoning, NTLM relay, ARP spoofing), each crafted to exercise the matching detector.
  - **Sustained C2 beaconing** — run a jittered beacon campaign over a set duration, which is what trips behavioural beaconing detection, instead of a one-shot burst.
  - **Full adversary suite** — fire every scenario in sequence from one click so coverage fills in comprehensively.
- **ExtraHop detection loop** — after traffic is sent, query the appliance for detections in that window, correlate them back to each scenario (detected / partial / missed), show the time-to-detect and risk, and roll it up into a MITRE coverage matrix. Export a standalone HTML validation report. Before an appliance is connected it shows a clearly-labelled sample so the views are usable.
- **Run history** — every generated and replayed run is recorded and persisted, so validation and reports survive an app restart.
- **Address book & profiles** — save IP/MAC pairs and reusable rewrite/replay/generator configurations.

## Requirements

- Python 3.8+ and `pip`.
- `libpcap` for Scapy (preinstalled on most macOS/Linux; `apt install libpcap-dev` or `brew install libpcap` if missing).
- Root is only needed to transmit packets (replay/generate).

## Install

```bash
bash setup.sh          # creates venv, installs deps, validates Flask + Scapy
```

or manually:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
sudo python3 run.py
```

Then open `http://127.0.0.1:9000`.

The server binds to loopback with the debug console **off** by default. Override with environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `PORT`   | `9000`  | Listen port |
| `HOST`   | `127.0.0.1` | Bind address — set to `0.0.0.0` only on a trusted lab network |
| `DEBUG`  | off     | Set to `1` to enable the Flask debug reloader (never expose it off-host) |

`sudo` is required so Scapy can send on the wire. Analysis-only use does not need it.

## Connect your ExtraHop appliance

On the **Settings** tab, enter your Reveal(x) base URL and a REST API key, choose whether to verify TLS (leave off for self-signed lab appliances), and list your **internal networks** (one CIDR per line). The API key is stored locally and never echoed back to the browser.

The internal networks do two things: the rewrite planner keeps your lab range inside them so remapped hosts classify as internal to the sensor, and the detection loop uses the configured connection to pull real detections. Use **Test connection** to confirm the appliance is reachable.

## Workflow

**Validate detection coverage from generated traffic**

1. On **Generate**, set the attacker, victim, and C2 addresses and pick the sensor-visible interface.
2. Run a single scenario, a sustained beacon campaign, or the full suite.
3. On **Detections**, click *Check ExtraHop* to see which scenarios the sensor caught, their risk and time-to-detect, and any gaps.
4. On **Coverage**, read the MITRE matrix; download an HTML report to share.

**Replay a downloaded capture at the sensor**

1. On **Viewer**, upload the PCAP and inspect it.
2. On **Rewrite**, read the audit, suggest a plan into your lab range, apply it, and set replay options.
3. Replay to the sensor-visible interface, then validate on **Detections** as above.

## Command-line tools

- `pcap_planner.py` — print or apply a rewrite plan for a capture without the UI:
  ```bash
  python3 pcap_planner.py capture.pcap --lab-subnet 10.99.0.0/16
  python3 pcap_planner.py capture.pcap --lab-subnet 10.99.0.0/16 --write-pcap lab.pcap
  ```
- `smoke_test_generator.py` — prove the generator actually transmits on an interface (needs root):
  ```bash
  sudo python3 smoke_test_generator.py eth0 --proto dns --count 20
  ```

## Testing

The analysis, auditing, planning, correlation, scheduling, and settings logic is unit-tested and runs without root or an appliance:

```bash
python3 -m unittest discover -s tests
```

## Project structure

```
netrunner/
├── app/
│   ├── __init__.py            # App factory, blueprint registration
│   ├── core/
│   │   ├── engine.py          # Replay task + shared task status
│   │   ├── runs.py            # Persistent run registry
│   │   ├── threat_analysis.py # Heuristic adversary→victim scoring
│   │   ├── rewrite_audit.py   # Rewrite / review / protect checklist
│   │   ├── rewrite_planner.py # Lab-range plan + internal-network locality
│   │   ├── extrahop.py        # Reveal(x) REST client
│   │   ├── detection_match.py # Correlate runs ↔ detections + coverage
│   │   ├── report.py          # HTML validation report
│   │   ├── beacon.py          # Jittered beacon schedule
│   │   ├── campaign.py        # Full adversary-suite runner
│   │   ├── interfaces.py      # NIC enumeration + preflight
│   │   ├── settings.py        # ExtraHop connection + internal networks
│   │   ├── addresses.py / profiles.py
│   │   └── generators/
│   │       ├── protocol.py    # Benign protocol traffic
│   │       └── adversary.py   # Adversary simulations
│   ├── routes/                # pcap, replay, generator, detections,
│   │                          #   settings, system, addresses, profiles
│   ├── templates/index.html
│   └── static/{css,js}
├── tests/                     # unittest suite (no root needed)
├── run.py                     # Entry point
├── pcap_planner.py            # Rewrite-plan CLI
├── smoke_test_generator.py    # Generator smoke test
└── requirements.txt
```

## Safety

This tool emits attack-shaped traffic. Run it only on an isolated lab segment you are authorized to test. Keep the destination within your lab, keep the server bound to a trusted network, and never enable debug mode on an exposed host.
