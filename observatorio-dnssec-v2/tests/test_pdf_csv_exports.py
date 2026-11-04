"""Validates the report exports:
  - CSV  (works without WeasyPrint)
  - PDF  (returns 501 with explicit message if WeasyPrint is absent;
          when WeasyPrint is installed, validates the PDF magic bytes)
  - JSON (already covered by /analyze/<id>/result.json — checked here too)

Also asserts that none of the exports leak the legacy diagnostic fields
(dnssec_status / dns_service_health / risk_*).
"""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from backend import app as obs_app


def _fake_result(domain, aid):
    """Synthesize a result.json shaped like _build_result_json output."""
    return {
        'id': aid,
        'domain': domain,
        'generated_at': '2026-05-06T22:00:00+00:00',
        'source': {
            'engine': 'DNSViz CLI',
            'probe':  f'/analyze/{aid}/probe.json',
            'graph':  f'/analyze/{aid}/graph.html',
            'grok':   f'/analyze/{aid}/grok.json',
            'print':  f'/analyze/{aid}/print.txt',
            'version': 'fake', 'zone_chain': ['.', 'org.', f'{domain}.'],
        },
        'dnsviz_original': {
            'graph_html_url':       f'/analyze/{aid}/graph.html',
            'graph_png_url':        f'/analyze/{aid}/graph.png',
            'graph_png_available':  True,
            'raw_text': '', 'raw_grok': {},
        },
        'dnsviz_visual': {
            'rrset_status': [{'status': 'SECURE', 'count': 4, 'items': []}],
            'dnskey_ds_nsec_status': [{'status': 'SECURE', 'count': 6, 'items': []}],
            'delegation_status': [{'status': 'SECURE', 'count': 3, 'items': []}],
            'notices': {'errors_count': 1, 'warnings_count': 1,
                        'errors': [], 'warnings': []},
        },
        'structured_view': {
            'zones': [],
            'sections': {
                'rrset_status': [], 'dnskey_ds_nsec_status': [], 'delegation_status': [],
                'notices': {
                    'errors': [{
                        'type': 'Error', 'code': 'MISSING_RRSIG',
                        'original_message': 'A RRset has no RRSIG, and "anomalies" with quotes',
                        'zone': domain,
                        'node': {'key': 'rrset', 'label': f'{domain}/A', 'status': 'BOGUS'},
                        'servers': ['1.2.3.4'], 'query_options': [],
                        'rfcs': ['4035'], 'rfcs_text': ['RFC 4035'],
                        'semantica': {'dnsviz_section': 'Notices', 'dnsviz_level': 'Error',
                                      'dnsviz_group': 'RRSIG', 'applies_to': ['rrset'],
                                      'visual_status_relation': 'may_cause_bogus', 'notes': ''},
                        'contexto_normativo': None,
                        'explanations': {
                            'es': {'plain_title': 'DNSViz reporta un RRset sin firma RRSIG',
                                   'plain_description': 'Acentos: ñoño á é í ó ú',
                                   'what_it_means': '', 'possible_actions': [], 'suggested_review': ''},
                            'en': {'plain_title': 'DNSViz reports an RRset without an RRSIG',
                                   'plain_description': 'Plain English description',
                                   'what_it_means': '', 'possible_actions': [], 'suggested_review': ''},
                        },
                        'traceability': {'source': 'DNSViz CLI', 'zone': domain,
                                         'node_key': 'rrset',
                                         'layers_used': ['capa1a', 'capa1b']},
                    }],
                    'warnings': [],
                },
            },
            'notices_by_zone': [], 'notices_by_code': [], 'notices_by_rfc': [],
        },
        'layers': {'capa1a': {}, 'capa1b': {}, 'capa2': {}, 'capa3': {}},
        'nameservers': [],
    }


class _ExportsBase(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self._old_an = obs_app.ANALYSES_DIR
        self._old_db = obs_app.DB_FILE
        obs_app.ANALYSES_DIR = self._td.name
        obs_app.DB_FILE = os.path.join(self._td.name, 'db.json')
        with open(obs_app.DB_FILE, 'w', encoding='utf-8') as f:
            json.dump({
                'users': [{
                    'id': 'admin',
                    'email': 'admin@example.test',
                    'password': obs_app._hash('adminpass'),
                    'role': 'admin',
                    'active': True,
                }],
                'analyses': [],
                'tokens': {},
                'domains': [],
                'logs': [],
                'report_texts': {},
            }, f)
        self.token = obs_app._token_create('admin@example.test', 'admin')
        self.auth = {'Authorization': f'Bearer {self.token}'}
        self.aid = 'feedfacefeedface'
        os.makedirs(os.path.join(self._td.name, self.aid), exist_ok=True)
        with open(os.path.join(self._td.name, self.aid, 'result.json'), 'w', encoding='utf-8') as f:
            json.dump(_fake_result('isoc.org.ec', self.aid), f, ensure_ascii=False, indent=2)
        # Persist a fake graph.html so the iframe link smoke test can hit it.
        with open(os.path.join(self._td.name, self.aid, 'graph.html'), 'w', encoding='utf-8') as f:
            f.write('<html><body>fake DNSViz graph</body></html>')
        self.client = obs_app.app.test_client()

    def tearDown(self):
        obs_app.ANALYSES_DIR = self._old_an
        obs_app.DB_FILE = self._old_db
        self._td.cleanup()


class JSONExportTests(_ExportsBase):
    def test_result_json_endpoint_requires_auth(self):
        r = self.client.get(f'/analyze/{self.aid}/result.json')
        self.assertEqual(r.status_code, 401)

    def test_result_json_endpoint_serves_persisted_file_with_auth(self):
        r = self.client.get(f'/analyze/{self.aid}/result.json', headers=self.auth)
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body['domain'], 'isoc.org.ec')
        # Private JSON also avoids the legacy diagnostic fields.
        for f in ('dnssec_status', 'dns_service_health', 'risk_score', 'health_score'):
            self.assertNotIn(f, body)

    def test_public_json_endpoint_serves_phase1_payload(self):
        r = self.client.get(f'/analyze/{self.aid}/result.json')
        self.assertEqual(r.status_code, 401)
        r = self.client.get(f'/analyze/{self.aid}/public.json')
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body['domain'], 'isoc.org.ec')
        self.assertIn('dnsviz_visual', body)
        self.assertNotIn('structured_view', body)
        self.assertNotIn('layers', body)
        self.assertNotIn('raw_text', body.get('dnsviz_original') or {})
        self.assertNotIn('probe', body.get('source') or {})
        self.assertNotIn('grok', body.get('source') or {})
        self.assertNotIn('print', body.get('source') or {})
        self.assertIn('graph_html', body.get('source') or {})
        for f in ('dnssec_status', 'dns_service_health', 'risk_score', 'health_score'):
            self.assertNotIn(f, body)

    def test_result_json_404_for_unknown_id(self):
        r = self.client.get('/analyze/deadbeefdeadbeef/result.json', headers=self.auth)
        self.assertEqual(r.status_code, 404)

    def test_path_traversal_rejected(self):
        # Werkzeug normalizes URL paths, so '../' in the slug becomes a
        # non-matching route (404). Our _safe_analysis_path also defends in
        # depth: any literal '..' or path separator in the slug returns None.
        self.assertIsNone(obs_app._safe_analysis_path('../etc', 'result.json'))
        self.assertIsNone(obs_app._safe_analysis_path('a/b', 'result.json'))


class CSVExportTests(_ExportsBase):
    def test_csv_status_and_headers(self):
        r = self.client.get(f'/analyze/{self.aid}/report.csv', headers=self.auth)
        self.assertEqual(r.status_code, 200)
        self.assertIn('text/csv', r.headers.get('Content-Type', ''))
        self.assertIn('attachment', r.headers.get('Content-Disposition', ''))
        self.assertIn(b'isoc.org.ec', r.data)

    def test_csv_columns_and_one_row_per_notice(self):
        r = self.client.get(f'/analyze/{self.aid}/report.csv', headers=self.auth)
        body = r.data.decode('utf-8')
        lines = [l for l in body.split('\r\n') if l]
        self.assertEqual(lines[0],
            'zone,type,code,rfcs,original_message,explanation_es,explanation_en')
        # 1 error + 0 warnings = 1 data row in the fixture
        self.assertEqual(len(lines), 2)

    def test_csv_quotes_special_chars(self):
        r = self.client.get(f'/analyze/{self.aid}/report.csv', headers=self.auth)
        body = r.data.decode('utf-8')
        # The fixture's original_message contains a comma and quotes:
        # `A RRset has no RRSIG, and "anomalies" with quotes`
        self.assertIn('""anomalies""', body)

    def test_csv_includes_utf8_explanations(self):
        r = self.client.get(f'/analyze/{self.aid}/report.csv', headers=self.auth)
        body = r.data.decode('utf-8')
        self.assertIn('ñoño', body)

    def test_csv_does_not_leak_legacy_diagnostic_fields(self):
        r = self.client.get(f'/analyze/{self.aid}/report.csv', headers=self.auth)
        body = r.data.decode('utf-8').lower()
        for f in ('dnssec_status', 'dns_service_health',
                  'risk_score', 'health_score'):
            self.assertNotIn(f, body)


class PDFExportTests(_ExportsBase):
    def test_pdf_endpoint_responds_predictably(self):
        r = self.client.get(f'/analyze/{self.aid}/report.pdf?lang=es', headers=self.auth)
        try:
            import weasyprint  # noqa: F401
            has_weasy = True
        except Exception:
            has_weasy = False

        if has_weasy:
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.headers.get('Content-Type'), 'application/pdf')
            self.assertEqual(r.data[:4], b'%PDF',
                'PDF magic bytes faltan')
        else:
            self.assertEqual(r.status_code, 501)
            body = r.get_json()
            self.assertEqual(body['error'], 'pdf_unavailable')
            self.assertIn('WeasyPrint', body['message'])

    def test_pdf_404_for_unknown_id(self):
        r = self.client.get('/analyze/0000000000000000/report.pdf', headers=self.auth)
        self.assertEqual(r.status_code, 404)

    def test_pdf_lang_query_only_accepts_es_or_en(self):
        # Bogus lang falls back to 'es'. We only check the endpoint
        # doesn't crash on weird input.
        r = self.client.get(f'/analyze/{self.aid}/report.pdf?lang=fr', headers=self.auth)
        self.assertIn(r.status_code, (200, 501))


class TemplateRendersWithoutLegacyFieldsTests(unittest.TestCase):
    """Even before WeasyPrint, the Jinja template alone must not surface
    dnssec_status / health / risk language."""

    def test_render_template_only(self):
        from flask import render_template
        result = _fake_result('isoc.org.ec', 'aaaabbbbccccdddd')
        with obs_app.app.test_request_context():
            html = render_template(
                'pdf-report.html.j2',
                result=result,
                ui={'report': {}},
                rt={'cover': {}, 'intro': {}, 'sections': {},
                    'glossary': [], 'disclaimer': {}, 'methodology': {}},
                lang='es',
                counts=obs_app._summary_counts(result['dnsviz_visual']),
                graph_url=f'http://obs.local/analyze/{result["id"]}/graph.html',
                formatted_date='06/05/2026 22:00 UTC',
            )
        for forbidden in ('dnssec_status', 'dns_service_health',
                          'health_score', 'risk_score', 'risk_level'):
            self.assertNotIn(forbidden, html)
        # The graph link is present (and ONLY as a link, no embedded image).
        self.assertIn('graph.html', html)
        self.assertNotIn('<img', html)


if __name__ == '__main__':
    unittest.main()
