"""Validates the graph.png fallback that fixes the blank-iframe issue.

Background:
  `dnsviz graph -Thtml` emits HTML that references local files via
  `file:///usr/local/share/dnsviz/{css,js}/dnsviz.{css,js}`. Browsers refuse
  to load `file://` from an HTTP page, so the embedded iframe renders blank.

Fix:
  - Backend additionally runs `dnsviz graph -Tpng` and persists graph.png.
  - New endpoint `/analyze/<id>/graph.png`.
  - result.json exposes `dnsviz_original.graph_png_url` and
    `dnsviz_original.graph_png_available`.
  - Frontend prefers PNG; HTML stays as auditable evidence.
"""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from backend import app as obs_app


_FAKE_PNG = (
    b'\x89PNG\r\n\x1a\n'                      # magic
    b'\x00\x00\x00\rIHDR'                     # IHDR chunk header
    b'\x00\x00\x00\x01\x00\x00\x00\x01'       # 1x1
    b'\x08\x06\x00\x00\x00'                   # 8-bit, RGBA
    b'\x1f\x15\xc4\x89'                       # CRC
    b'\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01'
    b'\r\n-\xb4'                              # IDAT CRC
    b'\x00\x00\x00\x00IEND\xaeB`\x82'         # IEND
)


class GraphPngEndpointTests(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self._old_an = obs_app.ANALYSES_DIR
        obs_app.ANALYSES_DIR = self._td.name
        self.aid = 'graphpngtest0001'
        os.makedirs(os.path.join(self._td.name, self.aid), exist_ok=True)
        with open(os.path.join(self._td.name, self.aid, 'graph.png'), 'wb') as f:
            f.write(_FAKE_PNG)
        with open(os.path.join(self._td.name, self.aid, 'graph.html'), 'w', encoding='utf-8') as f:
            f.write('<html><body>fake</body></html>')
        self.client = obs_app.app.test_client()

    def tearDown(self):
        obs_app.ANALYSES_DIR = self._old_an
        self._td.cleanup()

    def test_graph_png_endpoint_serves_image(self):
        r = self.client.get(f'/analyze/{self.aid}/graph.png')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers.get('Content-Type'), 'image/png')
        self.assertEqual(r.data[:8], b'\x89PNG\r\n\x1a\n',
            'PNG magic bytes must round-trip through send_from_directory')

    def test_graph_html_endpoint_serves_interactive_phase1_view(self):
        """Interactive DNSViz HTML is public in FASE 1 for mouse-over."""
        r = self.client.get(f'/analyze/{self.aid}/graph.html')
        self.assertEqual(r.status_code, 200)
        self.assertIn('text/html', r.headers.get('Content-Type', ''))

    def test_graph_png_404_for_unknown_id(self):
        r = self.client.get('/analyze/deadbeefdeadbeef/graph.png')
        self.assertEqual(r.status_code, 404)

    def test_path_traversal_rejected_for_png(self):
        self.assertIsNone(obs_app._safe_analysis_path('../etc', 'graph.png'))


class ResultJsonExposesPngUrlTests(unittest.TestCase):
    def test_dnsviz_original_includes_png_url(self):
        zone_chain = obs_app._build_zone_chain('isoc.org.ec')
        internal = {
            'domain': 'isoc.org.ec',
            'timestamp': '2026-05-07T05:00:00+00:00',
            'nameservers': [],
            'errors': [], 'warnings': [],
            'dnsviz_visual': {
                'source': 'dnsviz graph node_info',
                'rrset_status': [], 'dnskey_ds_nsec_status': [],
                'delegation_status': [],
                'notices': {'errors_count': 0, 'warnings_count': 0,
                            'errors': [], 'warnings': []},
            },
            'fidelity': {},
            'dnsviz': {
                'version': 'fake', 'analysis_id': 'g' * 16,
                'zone_chain': zone_chain, 'grok_zones': [], 'raw_grok': {},
                'probe_command': '', 'grok_command': '',
                'graph_command': '', 'graph_png_command': '', 'print_command': '',
                'graph_png_available': True,
                'print_text': '', 'persisted_files': {},
            },
        }
        result = obs_app._build_result_json('isoc.org.ec', 'g' * 16, internal)
        self.assertEqual(
            result['dnsviz_original']['graph_png_url'],
            '/analyze/gggggggggggggggg/graph.png',
        )
        self.assertTrue(result['dnsviz_original']['graph_png_available'])
        # source.* also exposes graph_png so clients can construct it deterministically.
        self.assertEqual(
            result['source']['graph_png'],
            '/analyze/gggggggggggggggg/graph.png',
        )

    def test_graph_png_available_false_when_render_failed(self):
        zone_chain = obs_app._build_zone_chain('cloudflare.com')
        internal = {
            'domain': 'cloudflare.com',
            'timestamp': '2026-05-07T05:00:00+00:00',
            'nameservers': [],
            'errors': [], 'warnings': [],
            'dnsviz_visual': {
                'source': 'dnsviz graph node_info',
                'rrset_status': [], 'dnskey_ds_nsec_status': [],
                'delegation_status': [],
                'notices': {'errors_count': 0, 'warnings_count': 0,
                            'errors': [], 'warnings': []},
            },
            'fidelity': {},
            'dnsviz': {
                'version': 'fake', 'analysis_id': 'h' * 16,
                'zone_chain': zone_chain, 'grok_zones': [], 'raw_grok': {},
                'probe_command': '', 'grok_command': '',
                'graph_command': '', 'graph_png_command': '', 'print_command': '',
                'graph_png_available': False,           # render failed
                'graph_png_error': 'graphviz dot timeout',
                'print_text': '', 'persisted_files': {},
            },
        }
        result = obs_app._build_result_json('cloudflare.com', 'h' * 16, internal)
        self.assertFalse(result['dnsviz_original']['graph_png_available'])
        # The URL still appears so the frontend can probe it; the flag tells
        # the UI to show the textual fallback instead of breaking <img>.


if __name__ == '__main__':
    unittest.main()
