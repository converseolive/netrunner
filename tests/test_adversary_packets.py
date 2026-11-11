"""
Packet-construction tests for the adversary generator.

These exercise the crafting directly (sendp is mocked, so nothing hits the
wire and no root/interface is needed) and assert the properties ExtraHop needs:
distinct per-host MACs, two-sided conversations, intensity scaling, and a
well-formed Kerberos request.
"""

import unittest
from unittest import mock

from scapy.all import Ether, IP, TCP, UDP, DNS

from app.core import engine
from app.core.generators import adversary


def _capture(sim, params):
    """Run a scenario with sendp mocked; return the list of sent packets."""
    base = {'interface': 'test0', 'src_mac': '02:aa:aa:aa:aa:aa',
            'src_ip': '10.0.0.50', 'dst_ip': '10.0.0.1',
            'c2_host': '203.0.113.9', 'delay': 0, 'intensity': 'demo'}
    base.update(params)
    engine.active_task_status['is_running'] = True
    sent = []
    with mock.patch.object(adversary, 'sendp', side_effect=lambda p, **k: sent.append(p)):
        sim(base)
    return sent


def _src_macs(pkts):
    return {p[Ether].src for p in pkts if Ether in p}


class MacAddressingTests(unittest.TestCase):
    def test_mac_for_ip_is_stable_unicast_laa(self):
        m1 = adversary._mac_for_ip('10.0.0.7')
        m2 = adversary._mac_for_ip('10.0.0.7')
        self.assertEqual(m1, m2)
        self.assertNotEqual(m1, adversary._mac_for_ip('10.0.0.8'))
        first = int(m1.split(':')[0], 16)
        self.assertTrue(first & 0x02, 'locally-administered bit set')
        self.assertFalse(first & 0x01, 'unicast (multicast bit clear)')

    def test_attacker_keeps_real_mac_others_distinct(self):
        mac = adversary._mac_resolver(
            {'interface': 't', 'src_mac': '02:aa:aa:aa:aa:aa', 'src_ip': '10.0.0.50'})
        self.assertEqual(mac('10.0.0.50'), '02:aa:aa:aa:aa:aa')     # attacker = VM
        self.assertNotEqual(mac('10.0.0.1'), '02:aa:aa:aa:aa:aa')   # victim distinct
        self.assertEqual(mac('224.0.0.252'), 'ff:ff:ff:ff:ff:ff')   # multicast
        self.assertEqual(mac('10.0.0.255'), 'ff:ff:ff:ff:ff:ff')    # broadcast

    def test_dns_exfil_is_two_sided_with_distinct_macs(self):
        pkts = _capture(adversary._sim_dns_exfil, {})
        # both the resolver and the server appear as sources
        self.assertEqual(_src_macs(pkts),
                         {'02:aa:aa:aa:aa:aa', adversary._mac_for_ip('10.0.0.1')})
        self.assertTrue(any(p.haslayer(DNS) and p[DNS].qr == 1 for p in pkts),
                        'server answers present')

    def test_port_scan_has_responses_and_sweeps_hosts(self):
        pkts = _capture(adversary._sim_port_scan, {'intensity': 'standard'})
        syns = [p for p in pkts if TCP in p and p[TCP].flags == 'S']
        synack = [p for p in pkts if TCP in p and p[TCP].flags == 'SA']
        rst = [p for p in pkts if TCP in p and 'R' in p[TCP].flags]
        self.assertTrue(synack and rst, 'target responds open and closed')
        targets = {p[IP].dst for p in syns}
        self.assertGreater(len(targets), 1, 'scan sweeps more than one host')

    def test_dga_sends_nxdomain_answers(self):
        pkts = _capture(adversary._sim_dga, {})
        answers = [p for p in pkts if p.haslayer(DNS) and p[DNS].qr == 1]
        self.assertTrue(answers)
        self.assertTrue(any(p[DNS].rcode == 3 for p in answers), 'NXDOMAIN present')


class IntensityTests(unittest.TestCase):
    def test_vol_scales_with_intensity(self):
        self.assertEqual(adversary._vol({'intensity': 'demo'}, 10), 10)
        self.assertEqual(adversary._vol({'intensity': 'standard'}, 10), 50)
        self.assertEqual(adversary._vol({'intensity': 'detection'}, 10), 150)
        self.assertEqual(adversary._vol({}, 10), 50)  # default standard

    def test_more_intensity_sends_more_packets(self):
        demo = _capture(adversary._sim_dga, {'intensity': 'demo', 'count': 10})
        det = _capture(adversary._sim_dga, {'intensity': 'detection', 'count': 10})
        self.assertGreater(len(det), len(demo) * 5)


class KerberosEncodingTests(unittest.TestCase):
    def test_tgs_req_length_fields_are_consistent(self):
        # The padata SEQUENCE length must match its contents for any ticket size,
        # including the >255-byte tickets that used to produce a malformed request.
        for size in (120, 200, 300, 400):
            tgt = b'\x00' * size
            pa_body = b'\xa1\x03\x02\x01\x01' + b'\xa2' + adversary._asn1_len(len(tgt)) + tgt
            pa_tgs = b'\x30' + adversary._asn1_len(len(pa_body)) + pa_body
            # decode the declared length and confirm it equals the real body
            self.assertTrue(_asn1_wellformed(pa_tgs), f'malformed at ticket size {size}')

    def test_kerberoast_runs_and_targets_port_88(self):
        pkts = _capture(adversary._sim_kerberoast, {'intensity': 'demo', 'count': 5})
        self.assertTrue(any(TCP in p and (p[TCP].dport == 88 or p[TCP].sport == 88)
                            for p in pkts))


def _asn1_wellformed(buf):
    """True if buf is a single TLV whose length field matches its contents."""
    if buf[0] != 0x30:
        return False
    i = 1
    b0 = buf[i]
    if b0 < 0x80:
        length, i = b0, i + 1
    elif b0 == 0x81:
        length, i = buf[i + 1], i + 2
    elif b0 == 0x82:
        length, i = (buf[i + 1] << 8) | buf[i + 2], i + 3
    else:
        return False
    return len(buf) - i == length


if __name__ == '__main__':
    unittest.main()
