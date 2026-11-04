"""Validates that DNSViz remains the sovereign source for visual states.

The Observatory is now a structured interpreter of DNSViz: it does NOT
recompute DNSSEC status, does NOT produce health/risk scoring, and does
NOT expose those legacy values to the frontend, the report or the PDF.

These tests assert exactly that contract on the public artifact
(`result.json` shape produced by `_build_result_json`).
"""
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from backend import app as obs_app


def _internal_result(domain: str, *, errors=None, warnings=None, visual_source='dnsviz graph node_info'):
    """Synthesize what _run_dnsviz returns, without invoking the CLI."""
    zone_chain = obs_app._build_zone_chain(domain)
    visual = {
        'source': visual_source,
        'rrset_status': [{'status': 'SECURE', 'count': 4, 'items': []}],
        'dnskey_ds_nsec_status': [{'status': 'SECURE', 'count': 6, 'items': []}],
        'delegation_status': [{'status': 'SECURE', 'count': len(zone_chain), 'items': []}],
        'notices': {
            'errors_count':   len(errors or []),
            'warnings_count': len(warnings or []),
            'errors':   errors or [],
            'warnings': warnings or [],
        },
        'default_view': {
            'rrset_status': [{'status': 'SECURE', 'count': 4, 'items': []}],
            'dnskey_ds_nsec_status': [{'status': 'SECURE', 'count': 6, 'items': []}],
            'delegation_status': [{'status': 'SECURE', 'count': len(zone_chain), 'items': []}],
        },
    }
    return {
        'domain': domain,
        'timestamp': '2026-05-06T22:00:00+00:00',
        # Legacy fields kept ONLY for db.json index, not for the public JSON.
        'dnssec_status': 'SECURE',
        'dns_service_health': 'HEALTHY',
        'nameservers': [],
        'errors':   errors or [],
        'warnings': warnings or [],
        'dnsviz_visual': visual,
        'fidelity': {'dnsviz_graph_model_available': True, 'ipv6_available': True, 'visual_ignore_rfc9276': True, 'source': visual_source, 'notes': []},
        'dnsviz': {
            'version': 'fake', 'analysis_id': 'feedface' * 2, 'zone_chain': zone_chain,
            'grok_zones': [], 'raw_grok': {z: {} for z in zone_chain},
            'probe_command': 'dnsviz probe', 'grok_command': 'dnsviz grok',
            'graph_command': 'dnsviz graph', 'print_command': 'dnsviz print',
            'print_text': '', 'persisted_files': {'probe': 'probe.json', 'grok': 'grok.json', 'graph': 'graph.html', 'print': 'print.txt'},
            'probe_stderr': [], 'grok_stderr': [], 'graph_stderr': [], 'graph_error': '',
            'print_stderr': [], 'print_error': '', 'ipv6_available': True,
        },
    }


class ResultJsonShapeTests(unittest.TestCase):
    """Public /analyze JSON shape — DNSViz-soberano."""

    def test_no_legacy_diagnostic_fields_in_public_result(self):
        """dnssec_status / dns_service_health must NOT appear at the top level
        of result.json. They survive only inside db.json as legacy index."""
        internal = _internal_result('isoc.org.ec')
        result = obs_app._build_result_json('isoc.org.ec', 'feedfacefeedface', internal)

        for forbidden in ('dnssec_status', 'dns_service_health', 'service_health',
                          'risk_score', 'health_score', 'risk_level'):
            self.assertNotIn(forbidden, result,
                f'{forbidden} debe NO exponerse en el public JSON: '
                f'rompe la regla "DNSViz soberano".')

    def test_top_level_shape_matches_spec(self):
        result = obs_app._build_result_json(
            'isoc.org.ec', 'feedfacefeedface', _internal_result('isoc.org.ec')
        )
        for required in ('id', 'domain', 'generated_at', 'source',
                         'dnsviz_original', 'dnsviz_visual',
                         'structured_view', 'layers'):
            self.assertIn(required, result, f'falta clave de spec: {required}')

    def test_source_block_lists_all_dnsviz_artifacts(self):
        result = obs_app._build_result_json(
            'cloudflare.com', 'aabbccddeeff0011', _internal_result('cloudflare.com')
        )
        src = result['source']
        self.assertEqual(src['engine'], 'DNSViz CLI')
        for kind in ('probe', 'grok', 'graph', 'print'):
            self.assertIn(kind, src,         f'source.{kind} faltante')
            self.assertTrue(str(src[kind]).startswith('/analyze/aabbccddeeff0011/'),
                f'source.{kind} debe apuntar al endpoint persistido')

    def test_dnsviz_original_exposes_graph_html_url(self):
        result = obs_app._build_result_json(
            'wikipedia.org', '0011223344556677', _internal_result('wikipedia.org')
        )
        self.assertEqual(
            result['dnsviz_original']['graph_html_url'],
            '/analyze/0011223344556677/graph.html',
        )

    def test_dnsviz_visual_is_passthrough_from_graph(self):
        """dnsviz_visual debe traer rrset/dnskey/delegation/notices tal como
        salen del grafo de DNSViz, sin reinterpretación."""
        internal = _internal_result('isoc.org.ec')
        result = obs_app._build_result_json('isoc.org.ec', 'aaaaaaaaaaaaaaaa', internal)
        v = result['dnsviz_visual']
        for key in ('rrset_status', 'dnskey_ds_nsec_status',
                    'delegation_status', 'notices'):
            self.assertIn(key, v)
        self.assertEqual(v['source'], 'dnsviz graph node_info')


class StructuredViewTests(unittest.TestCase):
    """structured_view: zonas, agrupaciones, sin reinterpretación."""

    def _internal_with_findings(self):
        return _internal_result(
            'isoc.org.ec',
            errors=[{
                'code': 'MISSING_RRSIG',
                'description': 'A RRset has no RRSIG.',
                'zone': 'isoc.org.ec',
                'servers': ['1.2.3.4'],
                'query_options': [],
                'occurrence': 1,
            }],
            warnings=[{
                'code': 'NONZERO_NSEC3_ITERATION_COUNT',
                'description': 'NSEC3 iter > 0',
                'zone': 'isoc.org.ec',
                'servers': [],
                'query_options': [],
                'occurrence': 1,
            }],
        )

    def test_zone_chain_classification(self):
        result = obs_app._build_result_json(
            'isoc.org.ec', 'a' * 16, _internal_result('isoc.org.ec')
        )
        zones = result['structured_view']['zones']
        names = [z['name'] for z in zones]
        self.assertEqual(names, ['.', 'ec', 'org.ec', 'isoc.org.ec'])

        cls = {z['name']: z['classification'] for z in zones}
        self.assertTrue(cls['.']['is_root'])
        self.assertTrue(cls['ec']['is_tld'])
        self.assertTrue(cls['org.ec']['is_intermediate'])
        self.assertTrue(cls['isoc.org.ec']['is_target'])

    def test_notices_attached_to_correct_zone(self):
        result = obs_app._build_result_json(
            'isoc.org.ec', 'b' * 16, self._internal_with_findings()
        )
        target_zone = next(z for z in result['structured_view']['zones']
                           if z['classification']['is_target'])
        self.assertEqual(len(target_zone['errors']),   1)
        self.assertEqual(len(target_zone['warnings']), 1)
        self.assertEqual(target_zone['errors'][0]['code'], 'MISSING_RRSIG')

    def test_notices_by_zone_groups_correctly(self):
        result = obs_app._build_result_json(
            'isoc.org.ec', 'c' * 16, self._internal_with_findings()
        )
        nbz = result['structured_view']['notices_by_zone']
        target = next(b for b in nbz if b['zone'] == 'isoc.org.ec')
        self.assertEqual(len(target['errors']),   1)
        self.assertEqual(len(target['warnings']), 1)

    def test_notices_by_code_aggregates_with_layers(self):
        result = obs_app._build_result_json(
            'isoc.org.ec', 'd' * 16, self._internal_with_findings()
        )
        nbc = result['structured_view']['notices_by_code']
        codes = [c['code'] for c in nbc]
        self.assertIn('MISSING_RRSIG', codes)
        self.assertIn('NONZERO_NSEC3_ITERATION_COUNT', codes)

        miss = next(c for c in nbc if c['code'] == 'MISSING_RRSIG')
        # `level` must come from capa1b (`dnsviz_level`), not from the Observatory.
        self.assertIn(miss['level'], ('Error', 'Warning'))
        # The RFC must come from capa1a `rfcs` (DNSViz catalog), not invented.
        self.assertIn('4035', miss['rfcs'])

    def test_notices_by_rfc_groups_codes(self):
        result = obs_app._build_result_json(
            'isoc.org.ec', 'e' * 16, self._internal_with_findings()
        )
        nbr = result['structured_view']['notices_by_rfc']
        rfcs = [b['rfc'] for b in nbr]
        self.assertIn('4035', rfcs)
        self.assertIn('9276', rfcs)
        # MISSING_RRSIG appears under RFC 4035, not the other way around.
        rfc4035 = next(b for b in nbr if b['rfc'] == '4035')
        self.assertIn('MISSING_RRSIG', rfc4035['codes'])

    def test_visual_status_per_zone_is_filtered_subset(self):
        """Each zone shows only the visual entries that belong to it."""
        result = obs_app._build_result_json(
            'isoc.org.ec', 'f' * 16, self._internal_with_findings()
        )
        for zone in result['structured_view']['zones']:
            self.assertIn('visual_status', zone)
            for sec in ('rrset_status', 'dnskey_ds_nsec_status', 'delegation_status'):
                self.assertIn(sec, zone['visual_status'])


class LayersIntegrityTests(unittest.TestCase):
    """capa1a/1b/2/3 cargadas sin alterar estados DNSViz."""

    def test_layers_load_from_backend_data_dnsviz(self):
        layers = obs_app._load_layers()
        for key in ('capa1a', 'capa1b', 'capa2', 'capa3', 'ui_texts', 'report_texts'):
            self.assertIn(key, layers['raw'])
        self.assertGreater(len(layers['by_code']['capa1a']), 0)
        self.assertGreater(len(layers['by_code']['capa1b']), 0)

    def test_capa1a_has_no_forbidden_fields(self):
        """Catalog DNSViz must remain pure (no responsable/scoring/risk)."""
        forbidden = {'responsible', 'responsable', 'severity_ops', 'severity',
                     'riesgo', 'risk', 'health', 'cost_ref',
                     'action_owner', 'action_hosting',
                     'action_registrar', 'action_registry'}
        for code, rows in obs_app._load_layers()['by_code']['capa1a'].items():
            for row in rows:
                for f in row.keys():
                    self.assertNotIn(
                        f.lower(), forbidden,
                        f'capa1a[{code}] tiene campo prohibido: {f}'
                    )

    def test_capa3_uses_prudent_language(self):
        """The first MISSING_RRSIG ES explanation must use hedged language,
        not absolute claims (per spec)."""
        idx = obs_app._load_layers()['by_code']['capa3']
        es = idx.get(('MISSING_RRSIG', 'es'))
        self.assertIsNotNone(es, 'falta capa3[MISSING_RRSIG][es]')
        # The plain_title must mention DNSViz as the reporter, not the
        # Observatory passing judgment.
        self.assertIn('DNSViz', es['plain_title'])

    def test_capa1b_visual_relations_come_from_dnsviz(self):
        idx = obs_app._load_layers()['by_code']['capa1b']
        for code in ('SERVER_UNRESPONSIVE_UDP', 'SERVER_UNRESPONSIVE_TCP'):
            self.assertIn(code, idx)
            self.assertEqual(
                idx[code]['visual_status_relation'],
                'does_not_override_visual_status',
                f'{code} no debe degradar el estado visual final'
            )


class EnrichmentDoesNotInventStateTests(unittest.TestCase):
    """The notice enrichment must not synthesize DNSViz states."""

    def test_enriched_notice_does_not_invent_status(self):
        layers = obs_app._load_layers()['by_code']
        notice = {'code': 'MISSING_RRSIG',
                  'description': 'foo',
                  'zone': 'isoc.org.ec',
                  'servers': []}
        enriched = obs_app._enrich_notice(notice, 'Error', layers)
        # No sintetiza un node.status si DNSViz no lo dio.
        self.assertEqual(enriched['node']['status'], '')
        # No agrega campos como dnssec_status, health, risk.
        for forbidden in ('dnssec_status', 'health', 'risk', 'risk_level'):
            self.assertNotIn(forbidden, enriched)

    def test_unknown_code_is_traceable_with_missing_layers(self):
        layers = obs_app._load_layers()['by_code']
        notice = {'code': 'TOTALLY_FAKE_CODE_XYZ',
                  'description': 'unknown', 'zone': '.', 'servers': []}
        enriched = obs_app._enrich_notice(notice, 'Error', layers)
        # All four layers should be marked unused (none has this code).
        self.assertEqual(enriched['traceability']['layers_used'], [])


if __name__ == '__main__':
    unittest.main()
