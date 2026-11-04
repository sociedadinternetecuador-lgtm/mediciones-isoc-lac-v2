"""Validates the new admin layer/text editor and verifies the legacy
report-texts shape from db.json is no longer the source of truth.

The new editable surface is:
  - capa1b (semántica visual)
  - capa2  (contexto normativo)
  - capa3  (explicaciones humanas, ES/EN)
  - ui-texts
  - report-texts

capa1a (DNSViz catalog) must remain locked.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from backend import app as obs_app


class _AdminClientBase(unittest.TestCase):
    """Spin up a temp DB + temp data dir so tests don't touch the real files."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        # Temp DB
        self.tmp_db = os.path.join(self._td.name, 'db.json')
        self._old_db = obs_app.DB_FILE
        obs_app.DB_FILE = self.tmp_db
        with open(self.tmp_db, 'w', encoding='utf-8') as f:
            json.dump({
                'users': [{
                    'id': 'admin',
                    'email': 'admin@example.test',
                    'password': obs_app._hash('adminpass'),
                    'role': 'admin',
                    'active': True,
                }, {
                    'id': 'analyst',
                    'email': 'analyst@example.test',
                    'password': obs_app._hash('analystpass'),
                    'role': 'analyst',
                    'active': True,
                }],
                'analyses': [], 'domains': [], 'logs': [],
                'tokens': {}, 'report_texts': {},
            }, f)

        # Temp DATA_DIR — copy the real seed files so we can write/restore freely.
        self._old_data_dir = obs_app.DATA_DIR
        self.tmp_data_dir = os.path.join(self._td.name, 'data')
        os.makedirs(self.tmp_data_dir, exist_ok=True)
        for fname in os.listdir(self._old_data_dir):
            src = os.path.join(self._old_data_dir, fname)
            if os.path.isfile(src):
                shutil.copyfile(src, os.path.join(self.tmp_data_dir, fname))
        obs_app.DATA_DIR = self.tmp_data_dir
        obs_app._invalidate_layer_cache()

        self.client = obs_app.app.test_client()
        self.admin_token   = obs_app._token_create('admin@example.test',   'admin')
        self.analyst_token = obs_app._token_create('analyst@example.test', 'analyst')

    def tearDown(self):
        obs_app.DB_FILE = self._old_db
        obs_app.DATA_DIR = self._old_data_dir
        obs_app._invalidate_layer_cache()
        self._td.cleanup()

    def _auth(self, token):
        return {'Authorization': f'Bearer {token}'}


class AdminDataIndexTests(_AdminClientBase):
    def test_index_lists_all_editable_layers(self):
        r = self.client.get('/admin/data', headers=self._auth(self.admin_token))
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        keys = {it['key'] for it in body['items']}
        self.assertEqual(keys, {'capa1b', 'capa2', 'capa3', 'ui_texts', 'report_texts'})
        self.assertTrue(body['capa1a_locked'])

    def test_capa1a_is_not_in_index(self):
        r = self.client.get('/admin/data', headers=self._auth(self.admin_token))
        keys = {it['key'] for it in r.get_json()['items']}
        self.assertNotIn('capa1a', keys, 'capa1a debe estar bloqueada en admin')

    def test_analyst_cannot_access_admin_data(self):
        r = self.client.get('/admin/data', headers=self._auth(self.analyst_token))
        self.assertEqual(r.status_code, 403)


class AdminDataGetPutTests(_AdminClientBase):
    def test_get_capa1b_returns_list(self):
        r = self.client.get('/admin/data/capa1b', headers=self._auth(self.admin_token))
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.get_json(), list)

    def test_get_ui_texts_returns_dict_with_languages(self):
        r = self.client.get('/admin/data/ui-texts', headers=self._auth(self.admin_token))
        body = r.get_json()
        self.assertIn('es', body)
        self.assertIn('en', body)

    def test_put_capa1a_is_forbidden(self):
        r = self.client.put('/admin/data/capa1a',
                            json=[],
                            headers=self._auth(self.admin_token))
        self.assertEqual(r.status_code, 403)

    def test_put_capa1b_validates_schema(self):
        # missing 'code' -> 400
        r = self.client.put('/admin/data/capa1b',
                            json=[{'description': 'no code'}],
                            headers=self._auth(self.admin_token))
        self.assertEqual(r.status_code, 400)
        self.assertIn('code', r.get_json()['message'].lower())

    def test_put_capa1b_rejects_duplicate_codes(self):
        r = self.client.put('/admin/data/capa1b',
                            json=[{'code': 'X'}, {'code': 'X'}],
                            headers=self._auth(self.admin_token))
        self.assertEqual(r.status_code, 400)
        self.assertIn('duplicado', r.get_json()['message'].lower())

    def test_put_capa3_requires_lang(self):
        r = self.client.put('/admin/data/capa3',
                            json=[{'code': 'X', 'language': 'fr', 'plain_title': 'x'}],
                            headers=self._auth(self.admin_token))
        self.assertEqual(r.status_code, 400)

    def test_put_capa3_round_trip(self):
        new_data = [
            {'code': 'TEST_X', 'language': 'es', 'plain_title': 'Título', 'audience_level': 'both'},
            {'code': 'TEST_X', 'language': 'en', 'plain_title': 'Title',  'audience_level': 'both'},
        ]
        r = self.client.put('/admin/data/capa3',
                            json=new_data,
                            headers=self._auth(self.admin_token))
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json().get('backup'),
                        'PUT debe crear un backup automatico')
        # GET returns the new data
        r2 = self.client.get('/admin/data/capa3',
                             headers=self._auth(self.admin_token))
        codes = {(row['code'], row['language']) for row in r2.get_json()}
        self.assertIn(('TEST_X', 'es'), codes)
        self.assertIn(('TEST_X', 'en'), codes)

    def test_put_writes_utf8_with_ensure_ascii_false(self):
        """Acentos y eñes no deben salir como \\u00f1."""
        data = [{'code': 'TEST_UTF8', 'plain_text': 'ñoño á é í ó ú'}]
        # ui-texts allows arbitrary dict shape, easier to test
        r = self.client.put('/admin/data/ui-texts',
                            json={'es': {'home': {'hero_title': 'Niñez'}}, 'en': {}},
                            headers=self._auth(self.admin_token))
        self.assertEqual(r.status_code, 200)
        path = obs_app._layer_path('ui_texts')
        with open(path, 'rb') as f:
            raw = f.read()
        self.assertIn('Niñez'.encode('utf-8'), raw)
        self.assertNotIn(b'\\u00f1', raw)


class AdminRestoreDefaultsTests(_AdminClientBase):
    def test_restore_creates_backup_and_replaces(self):
        # Mutate
        r = self.client.put('/admin/data/capa1b',
                            json=[{'code': 'ZZZ_ONLY', 'notes': 'mutated'}],
                            headers=self._auth(self.admin_token))
        self.assertEqual(r.status_code, 200)
        # Restore
        r = self.client.post('/admin/data/capa1b/restore-defaults',
                             headers=self._auth(self.admin_token))
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json().get('backup'))
        # The current file should match the .default copy
        with open(obs_app._layer_path('capa1b'), encoding='utf-8') as f:
            current = json.load(f)
        with open(obs_app._layer_path('capa1b', default=True), encoding='utf-8') as f:
            seed = json.load(f)
        self.assertEqual(current, seed)
        codes = {row['code'] for row in current}
        self.assertNotIn('ZZZ_ONLY', codes)
        self.assertIn('MISSING_RRSIG', codes)

    def test_backups_endpoint_lists_history(self):
        # Force at least 1 backup
        self.client.put('/admin/data/capa2',
                        json=[{'code': 'BK_TEST'}],
                        headers=self._auth(self.admin_token))
        r = self.client.get('/admin/data/capa2/backups',
                            headers=self._auth(self.admin_token))
        self.assertEqual(r.status_code, 200)
        items = r.get_json()['items']
        self.assertGreaterEqual(len(items), 1)
        for it in items:
            self.assertTrue(it['filename'].startswith('capa2.'))
            self.assertTrue(it['filename'].endswith('.json'))


class PublicReadEndpointsTests(_AdminClientBase):
    def test_public_ui_texts_no_auth(self):
        r = self.client.get('/api/ui-texts.json')
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.get_json(), dict)

    def test_public_report_texts_no_auth(self):
        r = self.client.get('/api/report-texts.json')
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertIn('es', body)

    def test_public_capa1a_read_only(self):
        """capa1a se puede LEER públicamente (catálogo abierto) pero no editar."""
        r = self.client.get('/api/layers/capa1a.json')
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.get_json(), list)


if __name__ == '__main__':
    unittest.main()
