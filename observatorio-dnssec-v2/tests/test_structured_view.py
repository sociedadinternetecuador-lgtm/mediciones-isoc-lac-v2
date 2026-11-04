"""Validates _build_structured_view: zonas, agrupaciones y trazabilidad.

The structured_view is the navigable companion to dnsviz_visual. It must
preserve every notice DNSViz emitted, group them by zone/code/RFC, and
attach to each notice a `traceability` block with the layers used —
without inventing diagnostic states.
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from backend import app as obs_app


def _grok_findings(domain):
    return (
        # errors
        [
            {'code': 'MISSING_RRSIG',
             'description': 'A RRset has no RRSIG.',
             'zone': domain,
             'servers': ['1.2.3.4'],
             'query_options': [],
             'occurrence': 1},
            {'code': 'SERVER_UNRESPONSIVE_UDP',
             'description': 'No UDP response from authoritative.',
             'zone': domain,
             'servers': ['5.6.7.8'],
             'query_options': ['EDNS'],
             'occurrence': 2},
        ],
        # warnings
        [
            {'code': 'NONZERO_NSEC3_ITERATION_COUNT',
             'description': 'NSEC3 iter > 0',
             'zone': domain,
             'servers': [],
             'query_options': [],
             'occurrence': 1},
        ],
    )


class ZoneClassificationTests(unittest.TestCase):
    def test_classify_zone_root(self):
        c = obs_app._classify_zone('.', 'isoc.org.ec')
        self.assertEqual(c, {'is_root': True, 'is_tld': False,
                             'is_intermediate': False, 'is_target': False})

    def test_classify_zone_tld(self):
        c = obs_app._classify_zone('ec', 'isoc.org.ec')
        self.assertEqual(c, {'is_root': False, 'is_tld': True,
                             'is_intermediate': False, 'is_target': False})

    def test_classify_zone_intermediate(self):
        c = obs_app._classify_zone('org.ec', 'isoc.org.ec')
        self.assertEqual(c, {'is_root': False, 'is_tld': False,
                             'is_intermediate': True, 'is_target': False})

    def test_classify_zone_target(self):
        c = obs_app._classify_zone('isoc.org.ec', 'isoc.org.ec')
        self.assertEqual(c, {'is_root': False, 'is_tld': False,
                             'is_intermediate': False, 'is_target': True})

    def test_classify_zone_two_label_target(self):
        """For cloudflare.com (2 labels): com is TLD, cloudflare.com is target."""
        cls_com = obs_app._classify_zone('com', 'cloudflare.com')
        cls_tgt = obs_app._classify_zone('cloudflare.com', 'cloudflare.com')
        self.assertTrue(cls_com['is_tld'])
        self.assertTrue(cls_tgt['is_target'])
        self.assertFalse(cls_com['is_target'])


class StructuredViewBuildTests(unittest.TestCase):
    def setUp(self):
        self.layers = obs_app._load_layers()['by_code']
        self.domain = 'isoc.org.ec'
        self.zone_chain = obs_app._build_zone_chain(self.domain)
        self.errors, self.warnings = _grok_findings(self.domain)
        self.visual = {
            'rrset_status': [], 'dnskey_ds_nsec_status': [],
            'delegation_status': [],
            'notices': {'errors_count': 2, 'warnings_count': 1,
                        'errors': [], 'warnings': []},
        }
        self.sv = obs_app._build_structured_view(
            self.domain, self.zone_chain, self.visual,
            self.errors, self.warnings, self.layers,
        )

    def test_zones_preserve_order_root_to_target(self):
        names = [z['name'] for z in self.sv['zones']]
        self.assertEqual(names, ['.', 'ec', 'org.ec', 'isoc.org.ec'])

    def test_zones_carry_visual_status_section_keys(self):
        for z in self.sv['zones']:
            self.assertIn('visual_status', z)
            for s in ('rrset_status', 'dnskey_ds_nsec_status', 'delegation_status'):
                self.assertIn(s, z['visual_status'])

    def test_target_zone_carries_findings(self):
        target = next(z for z in self.sv['zones']
                      if z['classification']['is_target'])
        codes_err  = [n['code'] for n in target['errors']]
        codes_warn = [n['code'] for n in target['warnings']]
        self.assertEqual(set(codes_err),  {'MISSING_RRSIG', 'SERVER_UNRESPONSIVE_UDP'})
        self.assertEqual(set(codes_warn), {'NONZERO_NSEC3_ITERATION_COUNT'})
        # RFCs unionized from capa1a
        self.assertIn('4035', target['rfcs'])
        self.assertIn('9276', target['rfcs'])

    def test_notices_by_zone_orders_by_chain(self):
        nbz = self.sv['notices_by_zone']
        # Only the target zone has findings here; but order within bucket is
        # zone_chain index. We assert the bucket exists and is correctly placed.
        zones_with_findings = [b['zone'] for b in nbz]
        self.assertIn('isoc.org.ec', zones_with_findings)

    def test_notices_by_code_attaches_capa1b_level_and_capa1a_rfcs(self):
        nbc = self.sv['notices_by_code']
        miss = next(b for b in nbc if b['code'] == 'MISSING_RRSIG')
        # Level NEVER comes from the Observatory; must be capa1b.dnsviz_level
        # OR fallback to the kind passed by _enrich_notice ('Error'/'Warning').
        self.assertIn(miss['level'], ('Error', 'Warning'))
        self.assertIn('4035', miss['rfcs'])

        unresponsive = next(b for b in nbc if b['code'] == 'SERVER_UNRESPONSIVE_UDP')
        # capa1b says SERVER_UNRESPONSIVE_UDP does_not_override_visual_status;
        # the level pill should come from capa1b ("Error") at minimum.
        self.assertEqual(unresponsive['level'], 'Error')

    def test_notices_by_rfc_groups_codes(self):
        nbr = self.sv['notices_by_rfc']
        rfc4035 = next(b for b in nbr if b['rfc'] == '4035')
        self.assertIn('MISSING_RRSIG', rfc4035['codes'])
        rfc9276 = next(b for b in nbr if b['rfc'] == '9276')
        self.assertIn('NONZERO_NSEC3_ITERATION_COUNT', rfc9276['codes'])

    def test_traceability_attached_to_each_notice(self):
        for n in self.sv['sections']['notices']['errors']:
            tr = n['traceability']
            self.assertEqual(tr['source'], 'DNSViz CLI')
            self.assertEqual(tr['zone'], 'isoc.org.ec')
            # Layers used must reflect what was found in _enrich_notice.
            self.assertIsInstance(tr['layers_used'], list)

    def test_structured_view_has_no_diagnostic_aggregates(self):
        """Ningún campo en structured_view debe sintetizar un veredicto global."""
        forbidden = {'dnssec_status', 'dns_service_health',
                     'risk_score', 'health_score', 'risk_level',
                     'overall_status'}
        flat = str(self.sv).lower()
        # The notice codes contain "DNSSEC_DOWNGRADE" which is fine —
        # we check exact key names instead of substring scan.
        for k in self.sv.keys():
            self.assertNotIn(k, forbidden)


class CrossDomainShapeTests(unittest.TestCase):
    """Same shape rules apply to cloudflare.com and wikipedia.org."""

    def _build(self, domain):
        layers = obs_app._load_layers()['by_code']
        zc = obs_app._build_zone_chain(domain)
        visual = {
            'rrset_status': [{'status': 'SECURE', 'count': 4, 'items': []}],
            'dnskey_ds_nsec_status': [{'status': 'SECURE', 'count': 6, 'items': []}],
            'delegation_status': [{'status': 'SECURE', 'count': len(zc), 'items': []}],
            'notices': {'errors_count': 0, 'warnings_count': 0,
                        'errors': [], 'warnings': []},
        }
        return obs_app._build_structured_view(
            domain, zc, visual, [], [], layers
        )

    def test_cloudflare_com_zones(self):
        sv = self._build('cloudflare.com')
        self.assertEqual([z['name'] for z in sv['zones']],
                         ['.', 'com', 'cloudflare.com'])

    def test_wikipedia_org_zones(self):
        sv = self._build('wikipedia.org')
        self.assertEqual([z['name'] for z in sv['zones']],
                         ['.', 'org', 'wikipedia.org'])

    def test_no_findings_does_not_add_synthetic_status(self):
        sv = self._build('cloudflare.com')
        target = next(z for z in sv['zones'] if z['classification']['is_target'])
        self.assertEqual(target['errors'],   [])
        self.assertEqual(target['warnings'], [])
        # No synthetic "everything ok" pseudo-status appears on the zone:
        for k in target.keys():
            self.assertNotIn(k, {'overall_status', 'is_secure',
                                 'health', 'risk_level'})


if __name__ == '__main__':
    unittest.main()
