"""
Observatorio DNSSEC v2 — backend/app.py
Flask sirve API + frontend estático desde el mismo puerto 8080.
Sin CORS. Sin sessionStorage. Token en localStorage via Bearer header.
"""

import os, sys, json, shutil, subprocess, tempfile, logging, hashlib, hmac, secrets, smtplib, threading, shlex, re
import html as html_lib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps
from urllib.parse import urlsplit
from flask import Flask, request, jsonify, send_from_directory, Response, render_template

try:
    import dns.resolver
except Exception:
    dns = None

try:
    from backend import phase2_db
except Exception:
    import phase2_db

# ─────────────────────────────────────────────
# APP — sirve frontend/ como estáticos
# ─────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, '..', 'frontend')

TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')
app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path='', template_folder=TEMPLATES_DIR)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['JSON_AS_ASCII'] = False
app.json.ensure_ascii = False

# Sin CORS — todo mismo origen
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# CONFIGURACIÓN
# ─────────────────────────────────────────────
DB_FILE    = os.environ.get('DB_FILE',    os.path.join(BASE_DIR, 'db.json'))

# Defaults are for local development only. Cloud Run must set these with
# environment variables; never put production credentials in source code.
ENV_SECRET_KEY = os.environ.get('SECRET_KEY')
ENV_ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL')
ENV_ADMIN_PASS = os.environ.get('ADMIN_PASS')
SECRET_KEY  = ENV_SECRET_KEY  or 'change-this-secret-in-production'
ADMIN_EMAIL = ENV_ADMIN_EMAIL or 'admin@corpece.org.ec'
ADMIN_PASS  = ENV_ADMIN_PASS  or 'changeme123'
APP_BASE_URL = os.environ.get('APP_BASE_URL', '').rstrip('/')
ANALYZE_ASYNC_DEFAULT = os.environ.get('ANALYZE_ASYNC_DEFAULT', '1').lower() not in {'0', 'false', 'no'}
ANALYZE_WORKERS = max(1, int(os.environ.get('ANALYZE_WORKERS', '2')))
ANALYZE_EXECUTOR = ThreadPoolExecutor(max_workers=ANALYZE_WORKERS)
_ANALYZE_JOBS = set()
_ANALYZE_JOBS_LOCK = threading.RLock()

SMTP_HOST = os.environ.get('SMTP_HOST', '')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASS = os.environ.get('SMTP_PASS', '')
SMTP_FROM = os.environ.get('SMTP_FROM') or SMTP_USER

DNSVIZ_REMOTE = os.environ.get('DNSVIZ_REMOTE', '0').lower() in {'1', 'true', 'yes'}
DNSVIZ_GCP_PROJECT = os.environ.get('DNSVIZ_GCP_PROJECT', 'observatorio-dnssec')
DNSVIZ_GCP_ZONE = os.environ.get('DNSVIZ_GCP_ZONE', 'us-central1-a')
DNSVIZ_GCP_VM = os.environ.get('DNSVIZ_GCP_VM', 'dnsviz-lab')
DNSVIZ_REMOTE_RUNNER = os.environ.get('DNSVIZ_REMOTE_RUNNER', '/opt/dnsviz-lab/run-check.sh')
DNSVIZ_REMOTE_BASE_DIR = os.environ.get('DNSVIZ_REMOTE_BASE_DIR', '/opt/dnsviz-lab/checks')
GCLOUD_CMD = os.environ.get('GCLOUD_CMD', '')

def get_dnsviz_command():
    env_cmd = os.environ.get("DNSVIZ_CMD")
    if env_cmd:
        return env_cmd.split()

    dnsviz_path = shutil.which("dnsviz")
    if dnsviz_path:
        return [dnsviz_path]

    scripts_path = os.path.join(os.path.dirname(sys.executable), "Scripts", "dnsviz")
    if os.path.exists(scripts_path):
        return [sys.executable, scripts_path]

    raise RuntimeError("dnsviz CLI not found")

@app.after_request
def no_cache(response):
    """Evita que el navegador cachee archivos estáticos durante desarrollo."""
    if response.mimetype in {'application/json', 'text/html', 'text/css', 'application/javascript', 'text/javascript'}:
        response.headers['Content-Type'] = f'{response.mimetype}; charset=utf-8'
    if request.path.startswith('/js/') or request.path.startswith('/css/') or request.path.endswith('.html'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

# ─────────────────────────────────────────────
# RUTAS FRONTEND — Flask sirve los HTML
# ─────────────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory(FRONTEND_DIR, 'index.html')

@app.route('/report')
def report():
    return send_from_directory(FRONTEND_DIR, 'report.html')

@app.route('/report-v2')
def report_v2():
    return send_from_directory(FRONTEND_DIR, 'report-v2.html')

@app.route('/about')
def about():
    return send_from_directory(FRONTEND_DIR, 'about.html')

@app.route('/lab')
def lab_page():
    return send_from_directory(FRONTEND_DIR, 'lab.html')

@app.route('/lab/prepare')
def lab_prepare_page():
    return send_from_directory(FRONTEND_DIR, 'lab-prepare.html')

@app.route('/admin/login')
def admin_login_page():
    return send_from_directory(os.path.join(FRONTEND_DIR, 'admin'), 'login.html')

@app.route('/admin/dashboard')
def admin_dashboard_page():
    return send_from_directory(os.path.join(FRONTEND_DIR, 'admin'), 'dashboard.html')

# Catch-all para archivos estáticos (css, js, data, etc.)
@app.route('/data/dnsviz/dnsviz-legend-taxonomy.json')
def dnsviz_legend_taxonomy():
    return send_from_directory(DATA_DIR, 'dnsviz-legend-taxonomy.json', mimetype='application/json')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory(FRONTEND_DIR, path)

# ─────────────────────────────────────────────
# BASE DE DATOS (JSON simple)
# ─────────────────────────────────────────────
_DB_SCHEMA = {
    'users':    [],
    'analyses': [],
    'domains':  [],
    'logs':     [],
    'tokens':   {},
    'report_texts': {}
}

def _db_load():
    if not os.path.exists(DB_FILE):
        return dict(_DB_SCHEMA)
    try:
        with open(DB_FILE, encoding='utf-8') as f:
            db = json.load(f)
        for k, v in _DB_SCHEMA.items():
            db.setdefault(k, v)
        return db
    except Exception as e:
        log.error(f'db_load error: {e}')
        return dict(_DB_SCHEMA)

def _db_save(db):
    try:
        with open(DB_FILE, 'w', encoding='utf-8') as f:
            json.dump(db, f, indent=2, default=str, ensure_ascii=False)
    except Exception as e:
        log.error(f'db_save error: {e}')

def _db_init():
    """Crea o actualiza el admin definido por variables de entorno."""
    db = _db_load()
    _sync_env_admin(db)
    _db_save(db)

def _sync_env_admin(db):
    """Keeps the environment admin as the authoritative admin login."""
    admin_email = ADMIN_EMAIL.strip().lower()
    if not admin_email or not ADMIN_PASS:
        log.warning('ADMIN_EMAIL/ADMIN_PASS no definidos; no se puede activar admin de entorno')
        return
    admin = next(
        (u for u in db['users'] if u.get('email', '').strip().lower() == admin_email),
        None
    )
    if admin:
        admin.update({
            'email':      admin_email,
            'password':   _hash(ADMIN_PASS),
            'role':       'admin',
            'active':     True,
        })
    else:
        db['users'].append({
            'id':         _uid(),
            'email':      admin_email,
            'password':   _hash(ADMIN_PASS),
            'role':       'admin',
            'active':     True,
            'last_login': None,
        })
    log.info(f'Admin de entorno activo: {admin_email}')

def _bootstrap_runtime():
    """Bootstrap required for imported app servers such as gunicorn/Cloud Run."""
    if not ENV_SECRET_KEY:
        log.warning('SECRET_KEY no definido por entorno; usando valor local de desarrollo')
    try:
        os.makedirs(ANALYSES_DIR, exist_ok=True)
    except Exception as e:
        log.warning(f'cannot create ANALYSES_DIR {ANALYSES_DIR}: {e}')
    if not (ENV_ADMIN_EMAIL and ENV_ADMIN_PASS):
        log.warning('ADMIN_EMAIL/ADMIN_PASS no definidos por entorno; bootstrap admin de entorno omitido')
        return
    _db_init()

# ─────────────────────────────────────────────
# UTILIDADES
# ─────────────────────────────────────────────
def _uid():
    return secrets.token_hex(8)

def _hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def _password_matches(password: str, stored_hash: str) -> bool:
    return hmac.compare_digest(stored_hash or '', _hash(password))

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _now_iso() -> str:
    return _now().isoformat()

def _log(msg: str):
    db = _db_load()
    db['logs'].append({'ts': _now_iso(), 'msg': msg})
    db['logs'] = db['logs'][-500:]
    _db_save(db)

def _dnsviz_version() -> str:
    try:
        cmd = get_dnsviz_command() + ['-v']
        log.info(f'Ejecutando DNSViz: {" ".join(cmd)}')
        return subprocess.check_output(
            cmd,
            stderr=subprocess.STDOUT, text=True, timeout=5
        ).strip()
    except Exception:
        return 'unknown'

def _smtp_configured() -> bool:
    return bool(SMTP_HOST and SMTP_FROM)

def _send_recovery_email(to_email: str, subject: str, body: str) -> bool:
    if not _smtp_configured():
        return False

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = SMTP_FROM
    msg['To'] = to_email
    msg.set_content(body)

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as smtp:
        smtp.starttls()
        if SMTP_USER and SMTP_PASS:
            smtp.login(SMTP_USER, SMTP_PASS)
        smtp.send_message(msg)
    return True

# ─────────────────────────────────────────────
# DATA LAYERS (capa1a/1b/2/3) y persistencia de analisis
# ─────────────────────────────────────────────
DATA_DIR     = os.path.join(BASE_DIR, 'data', 'dnsviz')
ANALYSES_DIR = os.environ.get('ANALYSES_DIR') or os.path.join(BASE_DIR, 'analyses')

LAYER_FILES = {
    'capa1a':       'capa1a-catalogo-dnsviz.json',
    'capa1b':       'capa1b-semantica-dnsviz.json',
    'capa2':        'capa2-contexto-normativo.json',
    'capa3':        'capa3-explicaciones.json',
    'ui_texts':     'ui-texts.json',
    'report_texts': 'report-texts.json',
}

# Capas tabulares (lista) vs documentos (dict).
TABULAR_LAYERS = {'capa1a', 'capa1b', 'capa2', 'capa3'}

_LAYER_CACHE = None

def _layer_path(key: str, default: bool = False) -> str:
    fname = LAYER_FILES[key]
    if default:
        fname = fname.replace('.json', '.default.json')
    return os.path.join(DATA_DIR, fname)

def _load_layer_file(key: str, default: bool = False):
    path = _layer_path(key, default)
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        log.warning(f'Layer {key} not found at {path}')
    except Exception as e:
        log.warning(f'Layer {key} ({path}) load error: {e}')
    return [] if key in TABULAR_LAYERS else {}

def _ensure_analyses_dir() -> str:
    try:
        os.makedirs(ANALYSES_DIR, exist_ok=True)
    except Exception as e:
        log.warning(f'cannot create ANALYSES_DIR {ANALYSES_DIR}: {e}')
    return ANALYSES_DIR

def _analysis_dir(aid: str) -> str:
    return os.path.join(ANALYSES_DIR, aid)

def _analysis_status_path(aid: str) -> str:
    return os.path.join(_analysis_dir(aid), 'status.json')

def _read_analysis_status(aid: str) -> dict | None:
    path = _analysis_status_path(aid)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        log.warning(f'cannot read status for {aid}: {e}')
        return None

def _write_analysis_status(aid: str, **updates) -> dict:
    os.makedirs(_analysis_dir(aid), exist_ok=True)
    status = _read_analysis_status(aid) or {'id': aid, 'created_at': _now_iso()}
    status.update(updates)
    status['updated_at'] = _now_iso()
    tmp = _analysis_status_path(aid) + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(status, f, ensure_ascii=False, indent=2)
    os.replace(tmp, _analysis_status_path(aid))
    return status

REPORT_TEXT_FIELDS = [
    'public_title',
    'executive_description',
    'technical_description',
    'dnssec_impact_text',
    'operational_impact_text',
    'recommended_action_owner',
    'recommended_action_hosting',
    'recommended_action_registrar',
    'recommended_action_registry',
]

REPORT_TEXT_META_FIELDS = [
    'code',
    'report_visibility',
    'audience_level',
]
REPORT_TEXT_LANGS = ('es', 'en')
REPORT_TEXT_ALL_FIELDS = REPORT_TEXT_META_FIELDS + REPORT_TEXT_FIELDS

REPORT_TEXT_AUDIENCE = {'executive', 'technical', 'both'}

def _load_layers() -> dict:
    """Carga las 6 fuentes de datos (capa1a, capa1b, capa2, capa3, ui-texts, report-texts).

    Las 4 capas tabulares se devuelven como `raw` (lista) y `by_code` (indice).
    Los documentos (`ui_texts`, `report_texts`) solo en `raw` como dict.
    """
    global _LAYER_CACHE
    if _LAYER_CACHE is not None:
        return _LAYER_CACHE

    raw = {key: _load_layer_file(key) for key in LAYER_FILES}

    by_code = {}

    # capa1a: lista de entradas del catalogo DNSViz; un mismo code puede mapear
    # a varias clases del catalogo, por eso lo guardamos como lista por code.
    c1a = {}
    for row in raw.get('capa1a', []) or []:
        if isinstance(row, dict) and row.get('code'):
            c1a.setdefault(row['code'], []).append(row)
    by_code['capa1a'] = c1a

    # capa1b: semantica visual DNSViz, un registro por code.
    c1b = {}
    for row in raw.get('capa1b', []) or []:
        if isinstance(row, dict) and row.get('code'):
            c1b[row['code']] = row
    by_code['capa1b'] = c1b

    # capa2: contexto normativo, un registro por code.
    c2 = {}
    for row in raw.get('capa2', []) or []:
        if isinstance(row, dict) and row.get('code'):
            c2[row['code']] = row
    by_code['capa2'] = c2

    # capa3: explicaciones humanas, indexadas por (code, language).
    c3 = {}
    for row in raw.get('capa3', []) or []:
        if isinstance(row, dict) and row.get('code'):
            lang = (row.get('language') or 'es').lower()
            c3[(row['code'], lang)] = row
    by_code['capa3'] = c3

    _LAYER_CACHE = {'raw': raw, 'by_code': by_code}
    return _LAYER_CACHE

def _invalidate_layer_cache() -> None:
    """Forzar recarga de capas (uso desde admin tras editar archivos)."""
    global _LAYER_CACHE
    _LAYER_CACHE = None

def _empty_report_text_lang() -> dict:
    return {field: '' for field in REPORT_TEXT_FIELDS}

def _coerce_lang_text(row: dict | None) -> dict:
    source = row if isinstance(row, dict) else {}
    return {
        field: '' if source.get(field) is None else str(source.get(field, ''))
        for field in REPORT_TEXT_FIELDS
    }

def _report_text_response(row: dict, source: str) -> dict:
    texts = row.get('texts') if isinstance(row.get('texts'), dict) else {}
    normalized_texts = {
        lang: _coerce_lang_text(texts.get(lang))
        for lang in REPORT_TEXT_LANGS
    }
    default_text = normalized_texts.get('es') or _empty_report_text_lang()
    return {
        'source': source,
        'texts': normalized_texts,
        'public_title': default_text.get('public_title', ''),
        'executive_description': default_text.get('executive_description', ''),
        'technical_description': default_text.get('technical_description', ''),
        'dnssec_impact_text': default_text.get('dnssec_impact_text', ''),
        'operational_impact_text': default_text.get('operational_impact_text', ''),
        'recommended_actions': {
            'owner': default_text.get('recommended_action_owner', ''),
            'hosting': default_text.get('recommended_action_hosting', ''),
            'registrar': default_text.get('recommended_action_registrar', ''),
            'registry': default_text.get('recommended_action_registry', ''),
        },
        'audience_level': row.get('audience_level') or 'both',
        'report_visibility': bool(row.get('report_visibility', True)),
    }

def _report_text_fallback(issue: dict, c3: dict | None) -> tuple[dict, str]:
    c3 = c3 or {}
    if c3:
        es_text = {
            'code': issue.get('code', ''),
            'public_title': c3.get('plain_title') or issue.get('description') or issue.get('code', ''),
            'executive_description': c3.get('plain_description') or issue.get('description', ''),
            'technical_description': issue.get('description', ''),
            'dnssec_impact_text': c3.get('impact') or '',
            'operational_impact_text': c3.get('impact') or '',
            'recommended_action_owner': c3.get('action_owner') or '',
            'recommended_action_hosting': c3.get('action_hosting') or '',
            'recommended_action_registrar': c3.get('action_registrar') or '',
            'recommended_action_registry': c3.get('action_registry') or '',
            'report_visibility': True,
            'audience_level': 'both',
        }
        return {
            'code': issue.get('code', ''),
            'texts': {'es': es_text, 'en': _empty_report_text_lang()},
            'report_visibility': True,
            'audience_level': 'both',
        }, 'capa3'
    es_text = {
        'code': issue.get('code', ''),
        'public_title': issue.get('description') or issue.get('code', ''),
        'executive_description': issue.get('description', ''),
        'technical_description': issue.get('description', ''),
        'dnssec_impact_text': '',
        'operational_impact_text': '',
        'recommended_action_owner': '',
        'recommended_action_hosting': '',
        'recommended_action_registrar': '',
        'recommended_action_registry': '',
        'report_visibility': True,
        'audience_level': 'both',
    }
    return {
        'code': issue.get('code', ''),
        'texts': {'es': es_text, 'en': _empty_report_text_lang()},
        'report_visibility': True,
        'audience_level': 'both',
    }, 'dnsviz'

def _normalize_report_text(row: dict, code: str | None = None) -> dict:
    source = row if isinstance(row, dict) else {}
    item = {field: (source.get(field) if isinstance(source, dict) else '') for field in REPORT_TEXT_META_FIELDS}
    item['code'] = (code or item.get('code') or '').strip().upper()
    item['audience_level'] = item.get('audience_level') or 'both'
    if item['audience_level'] not in REPORT_TEXT_AUDIENCE:
        item['audience_level'] = 'both'
    visibility = source.get('report_visibility', True)
    item['report_visibility'] = bool(visibility)
    texts = source.get('texts') if isinstance(source.get('texts'), dict) else None
    if texts:
        item['texts'] = {
            lang: _coerce_lang_text(texts.get(lang))
            for lang in REPORT_TEXT_LANGS
        }
    else:
        # Backward compatibility with the first flat report_texts model.
        flat = _coerce_lang_text(source)
        item['texts'] = {'es': flat, 'en': _empty_report_text_lang()}
    for field in REPORT_TEXT_META_FIELDS:
        if item.get(field) is None:
            item[field] = ''
    return item

def _report_text_admin_payload(row: dict) -> dict:
    item = _normalize_report_text(row)
    # Keep flat ES fields for older UI/tests and expose structured bilingual texts.
    item.update(item.get('texts', {}).get('es', {}))
    item['updated_at'] = row.get('updated_at', '') if isinstance(row, dict) else ''
    item['updated_by'] = row.get('updated_by', '') if isinstance(row, dict) else ''
    return item

def _report_text_changed_fields(before: dict | None, after: dict) -> list:
    before = before or {}
    changed = []
    for field in REPORT_TEXT_META_FIELDS + ['texts']:
        if field == 'code':
            continue
        if before.get(field) != after.get(field):
            changed.append(field)
    return changed

EXPLANATION_ALIAS = {
    # DNSViz puede emitir TIMEOUT mientras la explicacion humana curada vive
    # bajo SERVER_UNRESPONSIVE_UDP. El alias permite reusar capa3.
    'TIMEOUT': 'SERVER_UNRESPONSIVE_UDP',
}

def _enrich_issues_with_layers(issue_list: list, language: str = 'es') -> list:
    """Adjunta a cada issue su mapping a capa1a/1b/2/3.

    Mantenido para compatibilidad de codigo legacy; el nuevo `structured_view`
    construye su propia agrupacion sin depender de esta mutacion.
    """
    layers = _load_layers()['by_code']
    c1a = layers.get('capa1a', {})
    c1b = layers.get('capa1b', {})
    c2 = layers.get('capa2', {})
    c3 = layers.get('capa3', {})
    lang = (language or 'es').lower()

    for issue in issue_list:
        code = issue.get('code', '')
        c3_code = code if (code, lang) in c3 else EXPLANATION_ALIAS.get(code, code)
        c3_row = c3.get((c3_code, lang)) or c3.get((c3_code, 'es'))
        missing = []
        if code not in c1a: missing.append('capa1a')
        if code not in c1b: missing.append('capa1b')
        if code not in c2:  missing.append('capa2')
        if c3_row is None:  missing.append('capa3')
        issue['mapping'] = {
            'capa1a':         c1a.get(code, []),
            'capa1b':         c1b.get(code),
            'capa2':          c2.get(code),
            'capa3':          c3_row,
            'missing_layers': missing,
        }
    return issue_list

# ─────────────────────────────────────────────
# TOKENS
# ─────────────────────────────────────────────
def _tokens_clean(db) -> dict:
    """Devuelve solo tokens válidos (no expirados)."""
    now = _now_iso()
    return {k: v for k, v in db.get('tokens', {}).items() if v.get('expires', '') > now}

def _token_signature(token_id: str) -> str:
    return hmac.new(SECRET_KEY.encode(), token_id.encode(), hashlib.sha256).hexdigest()

def _token_pack(token_id: str) -> str:
    return f'{token_id}.{_token_signature(token_id)}'

def _token_unpack(token: str) -> str | None:
    try:
        token_id, signature = token.rsplit('.', 1)
    except ValueError:
        return None
    expected = _token_signature(token_id)
    if not hmac.compare_digest(signature, expected):
        return None
    return token_id

def _token_create(email: str, role: str) -> str:
    token_id = secrets.token_hex(32)
    db = _db_load()
    db['tokens'] = _tokens_clean(db)
    db['tokens'][token_id] = {
        'email':   email,
        'role':    role,
        'expires': (_now() + timedelta(hours=8)).isoformat()
    }
    _db_save(db)
    return _token_pack(token_id)

def _token_get(token: str) -> dict | None:
    if not token:
        return None
    token_id = _token_unpack(token)
    if not token_id:
        return None
    db  = _db_load()
    now = _now_iso()
    entry = db['tokens'].get(token_id)
    if entry and entry.get('expires', '') > now:
        return entry
    return None

def _token_from_request() -> str:
    return request.headers.get('Authorization', '').replace('Bearer ', '').strip()

def _current_user() -> str:
    entry = _token_get(_token_from_request())
    return entry['email'] if entry else ''

def _current_role() -> str:
    entry = _token_get(_token_from_request())
    return entry['role'] if entry else ''

# ─────────────────────────────────────────────
# DECORADORES DE AUTENTICACIÓN
# ─────────────────────────────────────────────
def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not _token_get(_token_from_request()):
            return jsonify({'error': 'unauthorized', 'message': 'Token inválido o expirado'}), 401
        return f(*args, **kwargs)
    return wrapper

def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        entry = _token_get(_token_from_request())
        if not entry:
            return jsonify({'error': 'unauthorized', 'message': 'Token inválido o expirado'}), 401
        if entry.get('role') != 'admin':
            return jsonify({'error': 'forbidden', 'message': 'Se requiere rol admin'}), 403
        return f(*args, **kwargs)
    return wrapper

# ─────────────────────────────────────────────
# AUTH ENDPOINTS
# ─────────────────────────────────────────────
@app.route('/auth/login', methods=['POST'])
def auth_login():
    data  = request.json or {}
    email = (data.get('email') or data.get('user') or '').strip().lower()
    pwd   = data.get('password', '')

    if not email or not pwd:
        return jsonify({'error': 'missing_fields', 'message': 'Email y contraseña requeridos'}), 400

    admin_email = ADMIN_EMAIL.strip().lower()
    if hmac.compare_digest(email, admin_email):
        if not hmac.compare_digest(pwd, ADMIN_PASS):
            _log(f'Login fallido: {email}')
            return jsonify({'error': 'invalid_credentials', 'message': 'Credenciales inválidas'}), 401
        db = _db_load()
        _sync_env_admin(db)
        user = next(u for u in db['users'] if u['email'].lower() == admin_email)
    else:
        db = _db_load()
        user = next(
            (u for u in db['users'] if u['email'].lower() == email and u.get('active', False)),
            None
        )
        if not user or user.get('role') == 'admin' or not _password_matches(pwd, user.get('password', '')):
            _log(f'Login fallido: {email}')
            return jsonify({'error': 'invalid_credentials', 'message': 'Credenciales inválidas'}), 401

    # Actualizar last_login PRIMERO, luego guardar, luego crear token
    # IMPORTANTE: _token_create() debe ir DESPUÉS de _db_save()
    # Si va antes, _db_save() sobreescribe db.json borrando el token recién creado
    for u in db['users']:
        if u['email'].lower() == email:
            u['last_login'] = _now_iso()
    _db_save(db)

    token = _token_create(email, user['role'])
    _log(f'Login exitoso: {email}')

    return jsonify({'token': token, 'role': user['role'], 'email': email})

@app.route('/auth/recover', methods=['POST'])
def auth_recover():
    email = (request.json or {}).get('email', '').strip().lower()
    if not email:
        return jsonify({'error': 'missing_fields', 'message': 'Email requerido'}), 400

    admin_email = ADMIN_EMAIL.strip().lower()
    db = _db_load()
    exists = hmac.compare_digest(email, admin_email) or any(
        u['email'].lower() == email and u.get('active', False) for u in db['users']
    )

    if exists:
        _log(f'Recovery solicitado: {email}')
        base_url = APP_BASE_URL or request.url_root.rstrip('/')
        if hmac.compare_digest(email, admin_email):
            body = (
                'Recuperacion de acceso admin - Observatorio DNSSEC\n\n'
                'La cuenta administradora principal usa la variable de entorno ADMIN_PASS.\n'
                'Por seguridad la aplicacion no guarda ni envia esa clave.\n\n'
                'Para definir una nueva clave, actualiza Cloud Run con ADMIN_PASS y SECRET_KEY:\n\n'
                'gcloud run services update observatorio-dnssec \\\n'
                '  --region=us-central1 \\\n'
                '  --update-env-vars "ADMIN_EMAIL=<admin-email>,ADMIN_PASS=<nueva-clave>,SECRET_KEY=<secret-key>"\n\n'
                f'Luego entra nuevamente en: {base_url}/admin/login\n'
            )
        else:
            body = (
                'Recuperacion de acceso - Observatorio DNSSEC\n\n'
                'Tu cuenta no administra su clave directamente desde este formulario.\n'
                'Pide a un administrador que cambie tu clave desde el panel de usuarios.\n\n'
                f'Panel: {base_url}/admin/login\n'
            )

        try:
            sent = _send_recovery_email(
                email,
                'Recuperacion de acceso - Observatorio DNSSEC',
                body
            )
            if sent:
                _log(f'Recovery enviado por email: {email}')
            else:
                _log('Recovery sin SMTP configurado; usar cambio de ADMIN_PASS en Cloud Run')
        except Exception as e:
            log.warning(f'recovery email error: {e}')
            _log(f'Recovery no enviado por error SMTP: {email}')

    # Siempre responder ok para no revelar si el email existe.
    message = (
        'Si el email existe y SMTP esta configurado, recibiras instrucciones. '
        'Para el admin principal en Cloud Run, la recuperacion se hace actualizando ADMIN_PASS.'
    )
    return jsonify({'ok': True, 'message': message})

# ─────────────────────────────────────────────
# API PUBLICA — capas y textos (read-only)
# ─────────────────────────────────────────────
@app.route('/api/ui-texts.json', methods=['GET'])
def api_ui_texts():
    return jsonify(_load_layers()['raw'].get('ui_texts') or {})

@app.route('/api/report-texts.json', methods=['GET'])
def api_report_texts():
    return jsonify(_load_layers()['raw'].get('report_texts') or {})

@app.route('/api/layers/capa1a.json', methods=['GET'])
def api_layer_capa1a():
    return jsonify(_load_layers()['raw'].get('capa1a') or [])

@app.route('/api/layers/capa1b.json', methods=['GET'])
def api_layer_capa1b():
    return jsonify(_load_layers()['raw'].get('capa1b') or [])

@app.route('/api/layers/capa2.json', methods=['GET'])
def api_layer_capa2():
    return jsonify(_load_layers()['raw'].get('capa2') or [])

@app.route('/api/layers/capa3.json', methods=['GET'])
def api_layer_capa3():
    return jsonify(_load_layers()['raw'].get('capa3') or [])

@app.route('/auth/me', methods=['GET'])
@require_auth
def auth_me():
    """Verifica token y devuelve info del usuario actual."""
    return jsonify({'email': _current_user(), 'role': _current_role()})

# ─────────────────────────────────────────────
# ANÁLISIS DNSSEC
# ─────────────────────────────────────────────
def _validate_analysis_domain(domain: str) -> tuple[str, tuple | None]:
    domain = (domain or '').strip().lower().rstrip('.')
    if not domain:
        return '', (jsonify({'error': 'domain_required', 'message': 'Dominio requerido'}), 400)
    parts = domain.split('.')
    if len(parts) < 2 or any(len(p) == 0 for p in parts):
        return '', (jsonify({'error': 'invalid_domain', 'message': 'Dominio invalido'}), 400)
    return domain, None

_DOMAIN_RE = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$')
_CCTLD_SECOND_LEVELS = {
    'com', 'net', 'org', 'edu', 'gov', 'gob', 'mil', 'fin', 'med', 'info', 'nom',
}
_KNOWN_GTLD = {
    'com', 'net', 'org', 'edu', 'gov', 'mil', 'int', 'info', 'biz', 'name', 'pro',
    'museum', 'coop', 'aero', 'app', 'dev', 'io', 'ai', 'cloud', 'online', 'site',
}
LAB_PREPARATION_LIMIT = 5000
LAB_ANALYSIS_BATCH_LIMIT = 100
LAB_DELEGATION_CHECK_LIMIT = 300

def _idna_domain(value: str) -> tuple[str, str | None]:
    labels = value.strip('.').split('.')
    encoded = []
    for label in labels:
        if not label:
            return '', 'empty_label'
        try:
            encoded.append(label.encode('idna').decode('ascii').lower())
        except Exception:
            return '', 'idna_failed'
    return '.'.join(encoded), None

def _extract_candidate_domain(raw: str) -> tuple[str, list[str]]:
    value = (raw or '').strip()
    rules = []
    if not value:
        return '', rules
    value = value.strip().strip('\'"<>[](){}')
    if '://' not in value and (value.startswith('www.') or '/' in value or '?' in value or '#' in value):
        parse_value = 'http://' + value
    else:
        parse_value = value
    parsed = urlsplit(parse_value)
    host = parsed.hostname if parsed.scheme and parsed.netloc else value.split('/')[0].split('?')[0].split('#')[0]
    host = (host or '').strip().lower().rstrip('.')
    if parsed.scheme or parsed.path not in ('', host):
        rules.append('url_to_hostname')
    if host.startswith('www.'):
        host = host[4:]
        rules.append('strip_www')
    host, idna_error = _idna_domain(host)
    if idna_error:
        rules.append(idna_error)
    return host, rules

def _classify_domain_name(domain: str) -> dict:
    labels = domain.split('.')
    tld = labels[-1] if labels else ''
    tld_type = 'unknown'
    if len(tld) == 2:
        tld_type = 'ccTLD'
    elif tld in _KNOWN_GTLD:
        tld_type = 'gTLD'
    elif tld == 'arpa':
        tld_type = 'arpa'
    registrable = domain
    public_suffix = tld
    cc_second_level = ''
    if len(labels) >= 3 and tld_type == 'ccTLD' and labels[-2] in _CCTLD_SECOND_LEVELS:
        public_suffix = '.'.join(labels[-2:])
        cc_second_level = labels[-2]
        registrable = '.'.join(labels[-3:])
    elif len(labels) >= 2:
        registrable = '.'.join(labels[-2:])
    report_family = 'generic' if tld_type == 'gTLD' else 'country_code' if tld_type == 'ccTLD' else tld_type
    report_group = public_suffix if report_family == 'country_code' else tld
    return {
        'tld': tld,
        'tld_type': tld_type,
        'registry_root': tld,
        'cc_second_level': cc_second_level,
        'public_suffix': public_suffix,
        'registrable_domain': registrable,
        'report_family': report_family,
        'report_group': report_group,
    }

def _has_ns_delegation(domain: str) -> tuple[bool | None, list[str], str]:
    if dns is None:
        return None, [], 'dnspython_unavailable'
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 2.0
        resolver.timeout = 1.0
        answers = resolver.resolve(domain, 'NS')
        nameservers = sorted(str(rr.target).rstrip('.') for rr in answers)
        return bool(nameservers), nameservers, 'checked'
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False, [], 'checked'
    except Exception:
        return None, [], 'check_failed'

def _apply_lab_analysis_recommendation(item: dict) -> None:
    if item.get('status') == 'invalid':
        item.update({
            'zone_kind': 'invalid',
            'analysis_domain': '',
            'analysis_mode': 'exclude',
            'analysis_recommendation': 'invalid_exclude',
            'delegation_status': 'not_applicable',
            'delegation_nameservers': [],
        })
        return

    domain = item.get('normalized_domain') or ''
    base = item.get('registrable_domain') or domain
    is_subdomain = bool(base and domain and domain != base)
    item['is_subdomain'] = is_subdomain

    if not is_subdomain:
        item.update({
            'zone_kind': 'base_domain',
            'analysis_domain': domain,
            'analysis_mode': 'analyze',
            'analysis_recommendation': 'analyze_base_domain',
            'delegation_status': 'not_applicable',
            'delegation_nameservers': [],
        })
        return

    item.update({
        'zone_kind': 'subdomain_needs_review',
        'analysis_domain': base,
        'analysis_mode': 'review_before_analysis',
        'analysis_recommendation': 'review_subdomain_in_shortlist',
        'delegation_status': 'not_checked_in_inventory',
        'delegation_nameservers': [],
    })

def _normalize_lab_domain_input(raw: str) -> dict:
    normalized, rules = _extract_candidate_domain(raw)
    item = {
        'original': raw,
        'normalized_domain': normalized,
        'status': 'accepted',
        'rules': rules,
        'warning': '',
    }
    if not normalized or not _DOMAIN_RE.match(normalized):
        item.update({
            'status': 'invalid',
            'warning': 'invalid_domain',
            'tld': '',
            'tld_type': 'unknown',
            'registry_root': '',
            'cc_second_level': '',
            'public_suffix': '',
            'registrable_domain': '',
            'report_family': 'invalid',
            'report_group': 'invalid',
        })
        return item
    item.update(_classify_domain_name(normalized))
    if normalized != (raw or '').strip().lower().rstrip('.'):
        item['status'] = 'changed'
    return item

def _split_lab_domain_lines(text: str) -> list[str]:
    raw_items = []
    for line in (text or '').replace(',', '\n').replace(';', '\n').splitlines():
        item = line.strip()
        if item:
            raw_items.append(item)
    return raw_items

def _persist_analysis_result(domain: str, aid: str, internal: dict, user: str = 'public') -> dict:
    result_json = _build_result_json(domain, aid, internal)
    out_dir = _analysis_dir(aid)
    result_path = os.path.join(out_dir, 'result.json')
    with open(result_path, 'w', encoding='utf-8') as f:
        json.dump(result_json, f, ensure_ascii=False, indent=2)

    db = _db_load()
    visual = result_json.get('dnsviz_visual') or {}
    notices = visual.get('notices') or {}
    rec = {
        'id': aid,
        'domain': domain,
        'created_at': result_json.get('generated_at') or _now_iso(),
        'timestamp': result_json.get('generated_at') or _now_iso(),
        'user': user or 'public',
        'result_path': f'analyses/{aid}/result.json',
        'graph_html_url': f'/analyze/{aid}/graph.html',
        'status': internal.get('dnssec_status', 'INDETERMINATE'),
        'service_health': internal.get('dns_service_health', 'UNKNOWN'),
        'error_count': len(internal.get('errors') or []),
        'summary': {
            'rrset_status_groups': len(visual.get('rrset_status') or []),
            'dnskey_ds_nsec_status_groups': len(visual.get('dnskey_ds_nsec_status') or []),
            'delegation_status_groups': len(visual.get('delegation_status') or []),
            'notices_errors_count': notices.get('errors_count', 0),
            'notices_warnings_count': notices.get('warnings_count', 0),
            'visual_source': visual.get('source'),
        },
    }
    db['analyses'] = [a for a in db['analyses'] if a.get('id') != aid]
    db['analyses'].insert(0, rec)
    db['analyses'] = db['analyses'][:1000]
    _db_save(db)
    return result_json

def _public_phase1_result_json(result_json: dict) -> dict:
    """Return the public FASE 1 payload.

    FASE 1 can render the DNSViz-like one-domain report and expose only the
    public graph downloads. Raw DNSViz artifacts and derived exports belong to
    the authenticated FASE 2 laboratory.
    """
    source = result_json.get('source') or {}
    original = result_json.get('dnsviz_original') or {}
    public_source = {
        'engine': source.get('engine'),
        'graph_html': source.get('graph') or original.get('graph_html_url'),
        'graph_png': source.get('graph_png') or original.get('graph_png_url'),
        'graph_svg': source.get('graph_svg') or original.get('graph_svg_url'),
        'version': source.get('version'),
        'zone_chain': source.get('zone_chain'),
        'fidelity': source.get('fidelity'),
    }
    return {
        'id': result_json.get('id'),
        'domain': result_json.get('domain'),
        'generated_at': result_json.get('generated_at'),
        'source': {k: v for k, v in public_source.items() if v not in (None, '', [])},
        'dnsviz_original': {
            'graph_html_url': original.get('graph_html_url') or source.get('graph'),
            'graph_png_url': original.get('graph_png_url') or source.get('graph_png'),
            'graph_svg_url': original.get('graph_svg_url') or source.get('graph_svg'),
            'graph_png_available': bool(original.get('graph_png_available')),
            'graph_svg_available': bool(original.get('graph_svg_available')),
        },
        'dnsviz_visual': result_json.get('dnsviz_visual') or {},
    }

def _run_analysis_job(domain: str, aid: str, user: str = 'public') -> None:
    with _ANALYZE_JOBS_LOCK:
        _ANALYZE_JOBS.add(aid)
    try:
        log.info(f'Analizando async: {domain} (id={aid})')
        _write_analysis_status(aid, domain=domain, status='running', progress=10,
                               message='Preparando DNSViz', started_at=_now_iso())
        def _job_status(progress: int, message: str) -> None:
            _write_analysis_status(aid, domain=domain, status='running',
                                   progress=progress, message=message)

        internal = _run_dnsviz(domain, aid, status_callback=_job_status)
        _write_analysis_status(aid, domain=domain, status='running', progress=85,
                               message='Construyendo reporte')
        _persist_analysis_result(domain, aid, internal, user=user)
        _write_analysis_status(aid, domain=domain, status='done', progress=100,
                               message='Reporte listo', finished_at=_now_iso(),
                               public_result_url=f'/analyze/{aid}/public.json',
                               report_url='/report')
        log.info(f'Analisis async listo: {domain} (id={aid})')
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode() if getattr(e, 'stderr', None) else str(e)
        log.error(f'dnsviz error async {aid}: {stderr}')
        _write_analysis_status(aid, domain=domain, status='error', progress=100,
                               error='analysis_failed', message=f'Error en dnsviz: {stderr[:200]}',
                               finished_at=_now_iso())
    except subprocess.TimeoutExpired:
        _write_analysis_status(aid, domain=domain, status='error', progress=100,
                               error='timeout',
                               message='El analisis tardo demasiado. Intenta nuevamente.',
                               finished_at=_now_iso())
    except Exception as e:
        log.error(f'analyze async exception {aid}: {e}')
        _write_analysis_status(aid, domain=domain, status='error', progress=100,
                               error='analysis_failed', message=str(e), finished_at=_now_iso())
    finally:
        with _ANALYZE_JOBS_LOCK:
            _ANALYZE_JOBS.discard(aid)

@app.route('/analyze', methods=['POST'])
def analyze():
    domain, error_response = _validate_analysis_domain((request.json or {}).get('domain', ''))
    if error_response:
        return error_response
    if ANALYZE_ASYNC_DEFAULT and request.args.get('sync') != '1':
        aid = _uid()
        user = _current_user() or 'public'
        log.info(f'Analisis solicitado: {domain} (id={aid})')
        _log(f'Analyze: {domain} id={aid}')
        _ensure_analyses_dir()
        _write_analysis_status(aid, domain=domain, status='queued', progress=0,
                               message='Analisis en cola')
        ANALYZE_EXECUTOR.submit(_run_analysis_job, domain, aid, user)
        return jsonify({
            'id': aid,
            'domain': domain,
            'status': 'queued',
            'progress': 0,
            'status_url': f'/analyze/{aid}/status',
            'public_result_url': f'/analyze/{aid}/public.json',
        }), 202

    domain = (request.json or {}).get('domain', '').strip().lower().rstrip('.')
    if not domain:
        return jsonify({'error': 'domain_required', 'message': 'Dominio requerido'}), 400

    parts = domain.split('.')
    if len(parts) < 2 or any(len(p) == 0 for p in parts):
        return jsonify({'error': 'invalid_domain', 'message': 'Dominio inválido'}), 400

    aid = _uid()
    log.info(f'Analizando: {domain} (id={aid})')
    _log(f'Analyze: {domain} id={aid}')
    _ensure_analyses_dir()

    try:
        internal = _run_dnsviz(domain, aid)
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode() if e.stderr else ''
        log.error(f'dnsviz error: {stderr}')
        return jsonify({'error': 'analysis_failed', 'message': f'Error en dnsviz: {stderr[:200]}'}), 500
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'timeout', 'message': 'El análisis tardó demasiado. Intenta nuevamente.'}), 504
    except Exception as e:
        log.error(f'analyze exception: {e}')
        return jsonify({'error': 'analysis_failed', 'message': str(e)}), 500

    # Construir y persistir el JSON final segun el nuevo spec.
    try:
        result_json = _build_result_json(domain, aid, internal)
    except Exception as e:
        log.error(f'build result_json failed: {e}')
        return jsonify({'error': 'analysis_failed', 'message': str(e)}), 500

    out_dir = _analysis_dir(aid)
    result_path = os.path.join(out_dir, 'result.json')
    try:
        with open(result_path, 'w', encoding='utf-8') as f:
            json.dump(result_json, f, ensure_ascii=False, indent=2)
    except Exception as e:
        log.error(f'persist result.json failed: {e}')
        return jsonify({'error': 'persist_failed', 'message': str(e)}), 500

    # Indice ligero en db.json — sin payloads pesados.
    db = _db_load()
    visual = result_json.get('dnsviz_visual') or {}
    notices = visual.get('notices') or {}
    rec = {
        'id':             aid,
        'domain':         domain,
        'created_at':     result_json.get('generated_at') or _now_iso(),
        'timestamp':      result_json.get('generated_at') or _now_iso(),  # alias retrocompat
        'user':           _current_user() or 'public',
        'result_path':    f'analyses/{aid}/result.json',
        'graph_html_url': f'/analyze/{aid}/graph.html',
        # Campos legados conservados solo como metadata interna; el frontend
        # nuevo no los usa y el reporte no los muestra.
        'status':           internal.get('dnssec_status', 'INDETERMINATE'),
        'service_health':   internal.get('dns_service_health', 'UNKNOWN'),
        'error_count':      len(internal.get('errors') or []),
        'summary': {
            'rrset_status_groups':         len(visual.get('rrset_status') or []),
            'dnskey_ds_nsec_status_groups': len(visual.get('dnskey_ds_nsec_status') or []),
            'delegation_status_groups':    len(visual.get('delegation_status') or []),
            'notices_errors_count':        notices.get('errors_count', 0),
            'notices_warnings_count':      notices.get('warnings_count', 0),
            'visual_source':               visual.get('source'),
        },
    }
    db['analyses'].insert(0, rec)
    db['analyses'] = db['analyses'][:1000]
    _db_save(db)
    return jsonify(_public_phase1_result_json(result_json))

# ─────────────────────────────────────────────
# /analyze/<id>/* — artefactos persistidos por DNSViz
# ─────────────────────────────────────────────
@app.route('/analyze/<aid>/status', methods=['GET'])
def analyze_status(aid):
    if not aid or '/' in aid or '\\' in aid or '..' in aid:
        return jsonify({'error': 'not_found'}), 404
    status = _read_analysis_status(aid)
    if not status:
        if _safe_analysis_path(aid, 'result.json'):
            return jsonify({
                'id': aid,
                'status': 'done',
                'progress': 100,
                'message': 'Reporte listo',
                'public_result_url': f'/analyze/{aid}/public.json',
                'report_url': '/report',
            })
        return jsonify({'error': 'not_found'}), 404
    return jsonify(status)

def _safe_analysis_path(aid: str, filename: str) -> str | None:
    if not aid or '/' in aid or '\\' in aid or '..' in aid:
        return None
    candidate = os.path.normpath(os.path.join(_analysis_dir(aid), filename))
    base = os.path.normpath(_analysis_dir(aid))
    if not candidate.startswith(base):
        return None
    if not os.path.isfile(candidate):
        return None
    return candidate

@app.route('/analyze/<aid>/result.json', methods=['GET'])
@require_auth
def analyze_result(aid):
    path = _safe_analysis_path(aid, 'result.json')
    if not path:
        return jsonify({'error': 'not_found'}), 404
    return send_from_directory(_analysis_dir(aid), 'result.json', mimetype='application/json')

@app.route('/analyze/<aid>/public.json', methods=['GET'])
def analyze_public_result(aid):
    result = _load_persisted_result(aid)
    if not result:
        return jsonify({'error': 'not_found'}), 404
    return jsonify(_public_phase1_result_json(result))

def _dnsviz_share_dir() -> str | None:
    candidates = [
        os.environ.get('DNSVIZ_SHARE_DIR'),
        os.path.join(sys.prefix, 'share', 'dnsviz'),
        os.path.join(sys.base_prefix, 'share', 'dnsviz'),
        '/usr/share/dnsviz',
        '/usr/local/share/dnsviz',
    ]
    for candidate in candidates:
        if candidate and os.path.isdir(candidate):
            return candidate
    return None

def _rewrite_dnsviz_graph_html(raw_html: str) -> str:
    """Make DNSViz graph HTML browser-loadable from our same-origin app."""
    replacements = {
        'file:///usr/share/javascript/jquery-ui-themes/redmond/jquery-ui.css':
            'https://code.jquery.com/ui/1.13.3/themes/base/jquery-ui.css',
        'file:///usr/share/javascript/jquery/jquery.min.js':
            'https://code.jquery.com/jquery-3.7.1.min.js',
        'file:///usr/share/javascript/jquery-ui/jquery-ui.min.js':
            'https://code.jquery.com/ui/1.13.3/jquery-ui.min.js',
        'file:///usr/share/javascript/raphael/raphael.min.js':
            'https://cdnjs.cloudflare.com/ajax/libs/raphael/2.3.0/raphael.min.js',
        'file:///usr/share/dnsviz/css/dnsviz.css':
            '/dnsviz-assets/dnsviz/css/dnsviz.css',
        'file:///usr/local/share/dnsviz/css/dnsviz.css':
            '/dnsviz-assets/dnsviz/css/dnsviz.css',
        'file:///usr/share/dnsviz/js/dnsviz.js':
            '/dnsviz-assets/dnsviz/js/dnsviz.js',
        'file:///usr/local/share/dnsviz/js/dnsviz.js':
            '/dnsviz-assets/dnsviz/js/dnsviz.js',
        '/usr/share/dnsviz/icons/':
            '/dnsviz-assets/dnsviz/icons/',
        '/usr/local/share/dnsviz/icons/':
            '/dnsviz-assets/dnsviz/icons/',
    }
    rewritten = raw_html
    for old, new in replacements.items():
        rewritten = rewritten.replace(old, new)
    return rewritten

@app.route('/dnsviz-assets/dnsviz/<path:filename>', methods=['GET'])
def dnsviz_asset(filename):
    share_dir = _dnsviz_share_dir()
    if not share_dir:
        return jsonify({'error': 'dnsviz_assets_not_found'}), 404
    safe = os.path.normpath(filename).replace('\\', '/')
    if safe.startswith('../') or safe.startswith('/'):
        return jsonify({'error': 'invalid_path'}), 400
    path = os.path.abspath(os.path.join(share_dir, safe))
    base = os.path.abspath(share_dir)
    if not path.startswith(base) or not os.path.isfile(path):
        return jsonify({'error': 'not_found'}), 404
    return send_from_directory(os.path.dirname(path), os.path.basename(path))

@app.route('/analyze/<aid>/graph.html', methods=['GET'])
def analyze_graph(aid):
    path = _safe_analysis_path(aid, 'graph.html')
    if not path:
        return jsonify({'error': 'not_found'}), 404
    with open(path, encoding='utf-8') as f:
        html = _rewrite_dnsviz_graph_html(f.read())
    return Response(html, mimetype='text/html; charset=utf-8')

@app.route('/analyze/<aid>/graph.png', methods=['GET'])
def analyze_graph_png(aid):
    path = _safe_analysis_path(aid, 'graph.png')
    if not path:
        return jsonify({'error': 'not_found'}), 404
    return send_from_directory(_analysis_dir(aid), 'graph.png', mimetype='image/png')

@app.route('/analyze/<aid>/graph.svg', methods=['GET'])
def analyze_graph_svg(aid):
    path = _safe_analysis_path(aid, 'graph.svg')
    if not path:
        return jsonify({'error': 'not_found'}), 404
    return send_from_directory(_analysis_dir(aid), 'graph.svg', mimetype='image/svg+xml')

@app.route('/analyze/<aid>/probe.json', methods=['GET'])
@require_auth
def analyze_probe(aid):
    path = _safe_analysis_path(aid, 'probe.json')
    if not path:
        return jsonify({'error': 'not_found'}), 404
    return send_from_directory(_analysis_dir(aid), 'probe.json', mimetype='application/json')

@app.route('/analyze/<aid>/grok.json', methods=['GET'])
@require_auth
def analyze_grok(aid):
    path = _safe_analysis_path(aid, 'grok.json')
    if not path:
        return jsonify({'error': 'not_found'}), 404
    return send_from_directory(_analysis_dir(aid), 'grok.json', mimetype='application/json')

@app.route('/analyze/<aid>/print.txt', methods=['GET'])
@require_auth
def analyze_print(aid):
    path = _safe_analysis_path(aid, 'print.txt')
    if not path:
        return jsonify({'error': 'not_found'}), 404
    return send_from_directory(_analysis_dir(aid), 'print.txt', mimetype='text/plain; charset=utf-8')

# ─────────────────────────────────────────────
# Exportaciones del reporte: PDF (WeasyPrint), CSV
#   El JSON ya se sirve desde /analyze/<id>/result.json
# ─────────────────────────────────────────────
def _csv_quote(s) -> str:
    s = '' if s is None else str(s)
    if any(ch in s for ch in (',', '"', '\n', '\r', ';')):
        return '"' + s.replace('"', '""') + '"'
    return s

def _safe_filename_part(s: str) -> str:
    out = ''.join(ch if ch.isalnum() or ch in '-_.' else '_' for ch in (s or 'report'))
    return out[:64] or 'report'

def _load_persisted_result(aid: str) -> dict | None:
    path = _safe_analysis_path(aid, 'result.json')
    if not path:
        return None
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        log.warning(f'load result.json {aid} failed: {e}')
        return None

def _format_iso_for_humans(iso: str, lang: str) -> str:
    if not iso:
        return ''
    try:
        d = datetime.fromisoformat(iso.replace('Z', '+00:00'))
    except Exception:
        return iso
    if lang == 'en':
        return d.strftime('%Y-%m-%d %H:%M %Z')
    return d.strftime('%d/%m/%Y %H:%M %Z')

def _summary_counts(visual: dict) -> dict:
    def _count_groups(groups):
        n = 0
        for g in groups or []:
            n += int(g.get('count') or len(g.get('items') or []))
        return n
    notices = visual.get('notices') or {}
    return {
        'rrset':      _count_groups(visual.get('rrset_status')),
        'dnskey':     _count_groups(visual.get('dnskey_ds_nsec_status')),
        'delegation': _count_groups(visual.get('delegation_status')),
        'errors':     int(notices.get('errors_count') or 0),
        'warnings':   int(notices.get('warnings_count') or 0),
    }

@app.route('/analyze/<aid>/report.pdf', methods=['GET'])
@require_auth
def analyze_report_pdf(aid):
    """Genera el PDF institucional con WeasyPrint a partir del result.json persistido."""
    result = _load_persisted_result(aid)
    if result is None:
        return jsonify({'error': 'not_found', 'message': 'result.json no encontrado'}), 404

    try:
        from weasyprint import HTML  # type: ignore
    except Exception as e:
        log.warning(f'WeasyPrint no disponible: {e}')
        return jsonify({
            'error':   'pdf_unavailable',
            'message': 'WeasyPrint no instalado en este entorno. Reconstruye la imagen con Dockerfile actualizado.',
        }), 501

    lang = (request.args.get('lang') or 'es').strip().lower()
    if lang not in ('es', 'en'):
        lang = 'es'

    raw_layers = _load_layers()['raw']
    ui_all = raw_layers.get('ui_texts') or {}
    rt_all = raw_layers.get('report_texts') or {}
    ui = ui_all.get(lang) or ui_all.get('es') or {}
    rt = rt_all.get(lang) or rt_all.get('es') or {}

    base_url = APP_BASE_URL or request.url_root.rstrip('/')
    graph_url = f'{base_url}/analyze/{aid}/graph.html'

    visual = result.get('dnsviz_visual') or {}
    counts = _summary_counts(visual)
    formatted_date = _format_iso_for_humans(result.get('generated_at') or '', lang)

    try:
        html = render_template(
            'pdf-report.html.j2',
            result=result,
            ui=ui,
            rt=rt,
            lang=lang,
            counts=counts,
            graph_url=graph_url,
            formatted_date=formatted_date,
        )
    except Exception as e:
        log.error(f'render pdf template failed: {e}')
        return jsonify({'error': 'render_failed', 'message': str(e)}), 500

    try:
        pdf_bytes = HTML(string=html, base_url=base_url).write_pdf()
    except Exception as e:
        log.error(f'WeasyPrint write_pdf failed: {e}')
        return jsonify({'error': 'pdf_failed', 'message': str(e)}), 500

    fname = f'{_safe_filename_part(result.get("domain") or "report")}-{aid[:8]}.pdf'
    return Response(
        pdf_bytes,
        mimetype='application/pdf',
        headers={
            'Content-Disposition': f'inline; filename="{fname}"',
            'Cache-Control': 'no-store',
        },
    )

@app.route('/analyze/<aid>/report.csv', methods=['GET'])
@require_auth
def analyze_report_csv(aid):
    """Una fila por notice: zone, type, code, rfcs, original_message, explanation_es, explanation_en."""
    result = _load_persisted_result(aid)
    if result is None:
        return jsonify({'error': 'not_found'}), 404

    sv = result.get('structured_view') or {}
    sections = (sv.get('sections') or {}).get('notices') or {}
    rows = []
    for n in (sections.get('errors') or []):
        rows.append((n, 'Error'))
    for n in (sections.get('warnings') or []):
        rows.append((n, 'Warning'))

    out = ['zone,type,code,rfcs,original_message,explanation_es,explanation_en']
    for n, kind in rows:
        expls = n.get('explanations') or {}
        es = expls.get('es') or {}
        en = expls.get('en') or {}
        out.append(','.join([
            _csv_quote(n.get('zone') or ''),
            _csv_quote(kind),
            _csv_quote(n.get('code') or ''),
            _csv_quote(' '.join(n.get('rfcs') or [])),
            _csv_quote(n.get('original_message') or ''),
            _csv_quote(es.get('plain_description') or es.get('plain_title') or ''),
            _csv_quote(en.get('plain_description') or en.get('plain_title') or ''),
        ]))

    fname = f'{_safe_filename_part(result.get("domain") or "report")}-{aid[:8]}.csv'
    body = '\r\n'.join(out) + '\r\n'
    return Response(
        body,
        mimetype='text/csv; charset=utf-8',
        headers={
            'Content-Disposition': f'attachment; filename="{fname}"',
            'Cache-Control': 'no-store',
        },
    )

def _resolve_ns(domain: str):
    """Resuelve nameservers de un dominio para pasarlos a dnsviz probe con -x."""
    try:
        out = subprocess.check_output(['dig', '+short', 'NS', domain], timeout=10, text=True)
        ns_list = []
        for ns in out.strip().splitlines():
            ns = ns.rstrip('.')
            if not ns:
                continue
            ip_out = subprocess.check_output(
                ['dig', '+short', 'A', ns], timeout=5, text=True
            ).strip().splitlines()
            if ip_out:
                ns_list.append(f'{ns}={ip_out[0]}')
        return ','.join(ns_list) if ns_list else None
    except Exception:
        return None

def _build_zone_chain(domain: str) -> list:
    """Construye lista de zonas desde raíz hasta dominio.
    Ejemplo: isoc.org.ec → ['.', 'ec.', 'org.ec.', 'isoc.org.ec.']
    """
    parts = domain.rstrip('.').split('.')
    zones = ['.']
    for i in range(len(parts) - 1, 0, -1):
        zones.append('.'.join(parts[i:]) + '.')
    zones.append(domain.rstrip('.') + '.')
    seen = set()
    result = []
    for z in zones:
        if z not in seen:
            seen.add(z)
            result.append(z)
    return result

DNSSEC_ALLOWED_STATUSES = {'SECURE', 'BOGUS', 'INSECURE', 'INDETERMINATE', 'UNKNOWN'}
DNS_SERVICE_ALLOWED_HEALTH = {'HEALTHY', 'DEGRADED', 'UNSTABLE', 'CRITICAL', 'UNKNOWN'}

OPERATIONAL_DNS_CODES = {
    'TIMEOUT',
    'SERVER_UNRESPONSIVE_UDP',
    'SERVER_UNRESPONSIVE_TCP',
    'PMTU_EXCEEDED',
    'ERROR_WITH_EDNS',
    'DNSSEC_DOWNGRADE_EDNS_DISABLED',
    'UNABLE_TO_RETRIEVE_DNSSEC_RECORDS',
    'SERVFAIL',
    'NETWORK_ERROR',
    'QUERY_TIMEOUT',
    'TCP_CONNECTION_FAILED',
    'UDP_TRUNCATED',
    'NO_RESPONSE',
    'RESPONSE_ERROR',
}

MINOR_SERVICE_WARNING_CODES = {
    'CDS_INCONSISTENT_WITH_DS',
    'CDNSKEY_INCONSISTENT_WITH_DS',
    'CDNSKEY_INCONSISTENT_WITH_CDS',
    'CDS_INCONSISTENT_WITH_CDNSKEY',
}

DNSSEC_POLICY_ONLY_CODES = {
    'NONZERO_NSEC3_ITERATION_COUNT',
    'NONEMPTY_NSEC3_SALT',
}

CRYPTO_DNSSEC_HINTS = (
    'RRSIG', 'DNSKEY', 'DS', 'NSEC', 'NSEC3', 'SIGNATURE', 'DIGEST',
    'ALGORITHM', 'SEP', 'KEY', 'CHAIN', 'BOGUS', 'VALIDATION'
)

def _issue_code(issue: dict) -> str:
    return (issue.get('code') or '').upper()

def _is_operational_issue(issue: dict) -> bool:
    code = _issue_code(issue)
    if code in OPERATIONAL_DNS_CODES:
        return True
    text = f"{code} {issue.get('description', '')}".upper()
    return any(token in text for token in (
        'TIMEOUT', 'UNRESPONSIVE', 'PMTU', 'TRANSPORT', 'TCP', 'UDP',
        'NO RESPONSE', 'EDNS', 'SERVFAIL', 'UNABLE TO RETRIEVE'
    ))

def _is_crypto_dnssec_issue(issue: dict) -> bool:
    code = _issue_code(issue)
    if code in DNSSEC_POLICY_ONLY_CODES or _is_operational_issue(issue):
        return False
    return any(token in code for token in CRYPTO_DNSSEC_HINTS)

def _is_final_domain_issue(issue: dict, domain: str) -> bool:
    return (issue.get('zone') or '').rstrip('.') == domain.rstrip('.')

def _dns_rcode(domain: str) -> str:
    try:
        out = subprocess.check_output(
            ['dig', '+time=2', '+tries=1', domain, 'A'],
            timeout=5,
            text=True,
            stderr=subprocess.STDOUT,
        )
    except Exception:
        return ''
    for line in out.splitlines():
        if 'status:' in line:
            return line.split('status:', 1)[1].split(',', 1)[0].strip().upper()
    return ''

def _visual_status_value(section) -> str:
    if isinstance(section, dict):
        return (section.get('status') or '').upper()
    if isinstance(section, list):
        statuses = {
            (group.get('status') or '').upper()
            for group in section
            if isinstance(group, dict)
        }
        if statuses == {'SECURE'}:
            return 'SECURE'
        if 'BOGUS' in statuses:
            return 'BOGUS'
        if 'ERROR' in statuses:
            return 'ERROR'
        if 'INSECURE' in statuses:
            return 'INSECURE'
        if 'SECURE' in statuses:
            return 'SECURE'
    return ''

def _visual_default_dnssec_status(dnsviz_visual: dict | None) -> str:
    if not isinstance(dnsviz_visual, dict):
        return ''
    view = dnsviz_visual.get('default_view') or {}
    required = (
        'rrset_status',
        'dnskey_ds_nsec_status',
        'delegation_status',
    )
    statuses = [_visual_status_value(view.get(key)) for key in required]
    if statuses and all(status == 'SECURE' for status in statuses):
        return 'SECURE'
    if statuses and 'INSECURE' in statuses and 'BOGUS' not in statuses and 'ERROR' not in statuses:
        return 'INSECURE'
    return ''

def _calculate_dnssec_status(grok: dict, domain: str, errors: list, dns_rcode: str = '', dnsviz_visual: dict | None = None) -> str:
    """Classify only DNSSEC cryptographic validity, not DNS service reachability."""
    if dns_rcode == 'NXDOMAIN':
        return 'UNKNOWN'

    visual_status = _visual_default_dnssec_status(dnsviz_visual)
    if visual_status:
        return visual_status

    status_map = {0: 'SECURE', 1: 'INSECURE', 2: 'BOGUS'}
    dk = domain.rstrip('.') + '.'
    domain_data = grok.get(dk)
    if domain_data is not None:
        deleg_status = domain_data.get('delegation', {}).get('status') if isinstance(domain_data, dict) else None
        dnssec_status = status_map.get(deleg_status)
        if dnssec_status:
            return dnssec_status

    final_crypto_errors = [
        e for e in errors
        if _is_final_domain_issue(e, domain) and _is_crypto_dnssec_issue(e)
    ]
    if final_crypto_errors:
        return 'BOGUS'
    final_operational_errors = [
        e for e in errors
        if _is_final_domain_issue(e, domain) and _is_operational_issue(e)
    ]
    if final_operational_errors:
        return 'INDETERMINATE'
    if grok:
        return 'SECURE'
    return 'UNKNOWN'

def _calculate_dns_service_health(errors: list, warnings: list, nameservers: list, domain: str) -> str:
    """Classify DNS availability/consistency separately from DNSSEC validation."""
    operational_errors = [e for e in errors if _is_operational_issue(e)]
    operational_warnings = [w for w in warnings if _is_operational_issue(w)]
    minor_service_warnings = [w for w in warnings if _issue_code(w) in MINOR_SERVICE_WARNING_CODES]

    if not operational_errors and not operational_warnings and not minor_service_warnings:
        return 'HEALTHY'

    final_operational = [e for e in operational_errors if _is_final_domain_issue(e, domain)]
    final_failed_servers = {
        server
        for issue in final_operational
        for server in (issue.get('servers') or [])
        if server
    }
    ns_count = len(nameservers or [])
    critical_threshold = max(2, (ns_count + 1) // 2) if ns_count else 3
    if final_failed_servers and len(final_failed_servers) >= critical_threshold:
        return 'CRITICAL'

    pmtu_count = sum(1 for issue in operational_errors + operational_warnings if _issue_code(issue) == 'PMTU_EXCEEDED')
    if pmtu_count >= 3 or len(operational_errors) >= 3:
        return 'UNSTABLE'

    return 'DEGRADED'

def _extract_graph_node_info(html_path: str) -> tuple[dict, str]:
    try:
        with open(html_path, encoding='utf-8') as f:
            html = f.read()
    except Exception as e:
        return {}, f'graph_html_read_failed: {e}'

    marker = 'var node_info = '
    start = html.find(marker)
    if start < 0:
        return {}, 'node_info_not_found'
    start += len(marker)

    depth = 0
    in_string = False
    escaped = False
    end = None
    for pos, ch in enumerate(html[start:], start):
        if in_string:
            if escaped:
                escaped = False
            elif ch == '\\':
                escaped = True
            elif ch == '"':
                in_string = False
        else:
            if ch == '"':
                in_string = True
            elif ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    end = pos + 1
                    break

    if end is None:
        return {}, 'node_info_json_not_closed'

    try:
        return json.loads(html[start:end]), ''
    except Exception as e:
        return {}, f'node_info_json_invalid: {e}'

def _clean_dns_name(name) -> str:
    if name is None:
        return ''
    value = str(name).strip()
    if value == '.':
        return '.'
    return value.rstrip('.')

def _visual_issue(issue: dict) -> dict:
    return {
        'code':          issue.get('code', ''),
        'description':   html_lib.unescape(issue.get('description', '') or ''),
        'servers':       issue.get('servers', []),
        'query_options': issue.get('query_options', []),
    }

def _merge_visual_notices(notices: list) -> list:
    merged = {}
    order = []
    for notice in notices or []:
        key = (
            notice.get('label') or '',
            notice.get('code') or '',
            notice.get('description') or '',
        )
        if key not in merged:
            merged[key] = {
                **notice,
                'servers': list(notice.get('servers') or []),
                'query_options': list(notice.get('query_options') or []),
                'count': notice.get('count') or 1,
            }
            order.append(key)
            continue
        current = merged[key]
        current['count'] = int(current.get('count') or 1) + int(notice.get('count') or 1)
        for field in ('servers', 'query_options'):
            values = current.setdefault(field, [])
            for value in notice.get(field) or []:
                if value not in values:
                    values.append(value)
    return [merged[key] for key in order]

def _visual_label(key: str, node: dict) -> str:
    desc = html_lib.unescape(node.get('description', '') or '')
    parts = key.split('|')

    if key.startswith('RRset-'):
        name = _clean_dns_name(node.get('name'))
        rtype = node.get('type')
        if not name and desc.startswith('Response errors for '):
            return desc.replace('Response errors for ', '', 1)
        label = f'{name}/{rtype}' if name and rtype else (desc or key)
        rdata = node.get('rdata') or []
        if rdata and rdata[0] in ('NODATA', 'NXDOMAIN'):
            label += f' ({rdata[0]})'
        return label

    if key.startswith('DNSKEY-') and len(parts) >= 4:
        zone = _clean_dns_name(parts[1])
        return f'{zone}/DNSKEY (alg {parts[2]}, id {parts[3]})'

    if key.startswith('DS-') and len(parts) >= 4:
        zone = _clean_dns_name(parts[1])
        return f'{zone}/DS (alg {parts[2]}, id {parts[3]})'

    if key.startswith('del-'):
        child = _clean_dns_name(parts[0].replace('del-', '', 1))
        parent = _clean_dns_name(parts[1]) if len(parts) > 1 else ''
        if parent:
            return f'{parent} to {child}'
        return desc or key

    if key.startswith('cluster_'):
        return desc or key

    return desc or key

def _visual_kind(key: str) -> str:
    if key.startswith('RRset-'):
        return 'rrset_status'
    if key.startswith(('DNSKEY-', 'DS-', 'NSEC-', 'NSEC3-', 'NSECC-', 'NSEC3C-')):
        return 'dnskey_ds_nsec_status'
    if key.startswith('del-'):
        return 'delegation_status'
    return 'other'

def _group_visual_status(entries: list) -> list:
    order = ['BOGUS', 'ERROR', 'INSECURE', 'WARNING', 'SECURE', 'VALID', 'UNKNOWN']
    grouped = {}
    for entry in entries:
        status = entry.get('status') or 'UNKNOWN'
        grouped.setdefault(status, []).append(entry)
    result = []
    for status in order:
        items = grouped.pop(status, [])
        if items:
            items.sort(key=lambda x: x.get('label', ''))
            result.append({'status': status, 'count': len(items), 'items': items})
    for status in sorted(grouped):
        items = grouped[status]
        items.sort(key=lambda x: x.get('label', ''))
        result.append({'status': status, 'count': len(items), 'items': items})
    return result

def _build_dnsviz_visual(node_info: dict) -> dict:
    sections = {
        'rrset_status': [],
        'dnskey_ds_nsec_status': [],
        'delegation_status': [],
        'other': [],
    }
    notices_errors = []
    notices_warnings = []

    for key, values in node_info.items():
        if not isinstance(values, list):
            values = [values]
        for idx, node in enumerate(values):
            if not isinstance(node, dict):
                continue
            label = _visual_label(key, node)
            errors = [_visual_issue(e) for e in (node.get('errors') or []) if isinstance(e, dict)]
            warnings = [_visual_issue(w) for w in (node.get('warnings') or []) if isinstance(w, dict)]
            entry = {
                'key':         key,
                'kind':        _visual_kind(key),
                'index':       idx,
                'label':       label,
                'status':      node.get('status') or 'UNKNOWN',
                'description': html_lib.unescape(node.get('description', '') or ''),
                'name':        _clean_dns_name(node.get('name')),
                'type':        node.get('type'),
                'rdata':       node.get('rdata', []),
                'errors':      errors,
                'warnings':    warnings,
            }
            sections[entry['kind']].append(entry)

            for issue in errors:
                notices_errors.append({**issue, 'label': label, 'node_key': key, 'node_status': entry['status']})
            for issue in warnings:
                notices_warnings.append({**issue, 'label': label, 'node_key': key, 'node_status': entry['status']})

    notices_errors = _merge_visual_notices(notices_errors)
    notices_warnings = _merge_visual_notices(notices_warnings)
    _enrich_issues_with_layers(notices_errors)
    _enrich_issues_with_layers(notices_warnings)

    return {
        'source': 'dnsviz graph node_info',
        'node_info_count': len(node_info),
        'rrset_status': _group_visual_status(sections['rrset_status']),
        'dnskey_ds_nsec_status': _group_visual_status(sections['dnskey_ds_nsec_status']),
        'delegation_status': _group_visual_status(sections['delegation_status']),
        'other_status': _group_visual_status(sections['other']),
        'notices': {
            'errors_count': len(notices_errors),
            'warnings_count': len(notices_warnings),
            'errors': notices_errors,
            'warnings': notices_warnings,
        },
        'raw_node_info': node_info,
    }

def _build_dnsviz_default_view(visual: dict, domain: str, zone_chain: list) -> dict:
    target = _clean_dns_name(domain)
    chain_names = {_clean_dns_name(z) for z in zone_chain}

    def _flat(groups):
        items = []
        for group in groups or []:
            items.extend(group.get('items') or [])
        return items

    rrsets = []
    for entry in _flat(visual.get('rrset_status')):
        if entry.get('name') != target or not entry.get('type'):
            continue
        rdata = entry.get('rdata') or []
        is_denial = bool(rdata and rdata[0] in ('NODATA', 'NXDOMAIN'))
        if is_denial and entry.get('status') not in ('BOGUS', 'ERROR'):
            continue
        rrsets.append(entry)

    dnskeys = []
    for entry in _flat(visual.get('dnskey_ds_nsec_status')):
        key = entry.get('key', '')
        if not key.startswith(('DNSKEY-', 'DS-')):
            continue
        zone = _clean_dns_name((key.split('|') + [''])[1])
        if zone in chain_names:
            dnskeys.append(entry)

    delegations = _flat(visual.get('delegation_status'))

    return {
        'rrset_status': _group_visual_status(rrsets),
        'dnskey_ds_nsec_status': _group_visual_status(dnskeys),
        'delegation_status': _group_visual_status(delegations),
    }

def _run_dnsviz(domain: str, analysis_id: str, status_callback=None) -> dict:
    """Corre dnsviz probe + grok + graph + print y persiste los artefactos.

    Los archivos crudos se escriben en backend/analyses/<id>/:
      probe.json, grok.json, graph.html, print.txt

    El grafo de DNSViz se considera fuente soberana para los estados visuales;
    este sistema no recalcula DNSSEC ni produce diagnosticos globales propios.
    """
    if DNSVIZ_REMOTE:
        return _run_dnsviz_remote_gcp(domain, analysis_id, status_callback=status_callback)

    def _status(progress: int, message: str) -> None:
        if status_callback:
            status_callback(progress, message)

    zone_chain = _build_zone_chain(domain)
    dnsviz_cmd = get_dnsviz_command()
    log.info(f'Zone chain: {zone_chain}')

    out_dir = _analysis_dir(analysis_id)
    os.makedirs(out_dir, exist_ok=True)

    pf  = os.path.join(out_dir, 'probe.json')
    gf  = os.path.join(out_dir, 'grok.json')
    hf  = os.path.join(out_dir, 'graph.html')
    pngf = os.path.join(out_dir, 'graph.png')
    svgf = os.path.join(out_dir, 'graph.svg')
    txf = os.path.join(out_dir, 'print.txt')

    if True:  # mantener bloque existente con minima refactorizacion

        # -a . fuerza a dnsviz a caminar la ancestria real desde la raiz.
        # No forzamos -4: dnsviz.net evalua IPv4 e IPv6 cuando hay conectividad.
        # No usamos -x aqui: reemplaza los autoritativos descubiertos y puede
        # alterar la delegacion que queremos diagnosticar.
        cmd = dnsviz_cmd + ['probe', '-A', '-a', '.', '-o', pf]
        cmd += zone_chain
        log.info(f'Ejecutando DNSViz: {" ".join(cmd)}')
        _status(25, 'DNSViz probe: consultando servidores autoritativos')

        probe_result = subprocess.run(cmd, check=True, timeout=120, capture_output=True)
        probe_stderr = []
        if probe_result.stderr:
            for line in probe_result.stderr.decode(errors='replace').splitlines():
                if line.strip():
                    probe_stderr.append(line.strip())
                    log.info(f'probe: {line}')

        # Pasar la cadena a grok hace que serialice errores de zonas padre.
        grok_cmd = dnsviz_cmd + ['grok', '-l', 'warning', '-r', pf, '-o', gf] + zone_chain
        log.info(f'Ejecutando DNSViz: {" ".join(grok_cmd)}')
        _status(50, 'DNSViz grok: clasificando estados y avisos')

        grok_result = subprocess.run(grok_cmd, check=True, timeout=30, capture_output=True)
        grok_stderr = []
        if grok_result.stderr:
            for line in grok_result.stderr.decode(errors='replace').splitlines():
                if line.strip():
                    grok_stderr.append(line.strip())
                    log.info(f'grok: {line}')

        with open(gf, encoding='utf-8') as f:
            grok = json.load(f)

        # DNSViz.net no muestra por defecto los hallazgos de politica NSEC3
        # de RFC 9276 en la lista principal de Notices. Los ignoramos solo
        # para la vista visual; raw_grok conserva la evidencia completa.
        graph_cmd = dnsviz_cmd + ['graph', '--ignore-rfc9276', '-Thtml', '-r', pf, '-o', hf] + zone_chain
        graph_stderr = []
        graph_error = ''
        dnsviz_visual = {
            'source': 'unavailable',
            'node_info_count': 0,
            'rrset_status': [],
            'dnskey_ds_nsec_status': [],
            'delegation_status': [],
            'other_status': [],
            'notices': {'errors_count': 0, 'warnings_count': 0, 'errors': [], 'warnings': []},
            'raw_node_info': {},
        }
        log.info(f'Ejecutando DNSViz: {" ".join(graph_cmd)}')
        _status(62, 'DNSViz graph: generando HTML interactivo')
        try:
            try:
                graph_result = subprocess.run(graph_cmd, check=True, timeout=60, capture_output=True)
            except subprocess.CalledProcessError as e:
                err = (e.stderr or b'').decode(errors='replace')
                if '--ignore-rfc9276' not in err and 'no such option' not in err.lower() and 'unrecognized' not in err.lower():
                    raise
                graph_cmd = dnsviz_cmd + ['graph', '-Thtml', '-r', pf, '-o', hf] + zone_chain
                log.info(f'Ejecutando DNSViz: {" ".join(graph_cmd)}')
                graph_result = subprocess.run(graph_cmd, check=True, timeout=60, capture_output=True)
            if graph_result.stderr:
                for line in graph_result.stderr.decode(errors='replace').splitlines():
                    if line.strip():
                        graph_stderr.append(line.strip())
                        log.info(f'graph: {line}')
            node_info, node_error = _extract_graph_node_info(hf)
            if node_error:
                graph_error = node_error
                dnsviz_visual['source'] = 'graph_html_parse_failed'
            else:
                dnsviz_visual = _build_dnsviz_visual(node_info)
                dnsviz_visual['default_view'] = _build_dnsviz_default_view(dnsviz_visual, domain, zone_chain)
        except Exception as e:
            graph_error = str(e)
            log.warning(f'dnsviz graph unavailable: {graph_error}')

        # dnsviz graph -Tpng: imagen estable para el frontend.
        # El HTML generado por dnsviz referencia file:///usr/local/share/dnsviz/{css,js}/dnsviz.{css,js}
        # que el navegador NO cargara desde HTTP (ni en iframe). El PNG queda
        # como fuente estable para visualizacion; graph.html se conserva
        # como evidencia descargable original.
        graph_png_cmd = dnsviz_cmd + ['graph', '--ignore-rfc9276', '-Tpng', '-r', pf, '-o', pngf] + zone_chain
        graph_png_stderr = []
        graph_png_error = ''
        graph_png_available = False
        log.info(f'Ejecutando DNSViz: {" ".join(graph_png_cmd)}')
        _status(72, 'DNSViz graph: generando PNG')
        try:
            try:
                pngres = subprocess.run(graph_png_cmd, check=True, timeout=60, capture_output=True)
            except subprocess.CalledProcessError as e:
                err = (e.stderr or b'').decode(errors='replace')
                if '--ignore-rfc9276' in err and ('no such option' in err.lower() or 'unrecognized' in err.lower()):
                    graph_png_cmd = dnsviz_cmd + ['graph', '-Tpng', '-r', pf, '-o', pngf] + zone_chain
                    log.info(f'Ejecutando DNSViz: {" ".join(graph_png_cmd)}')
                    pngres = subprocess.run(graph_png_cmd, check=True, timeout=60, capture_output=True)
                else:
                    raise
            if pngres.stderr:
                for line in pngres.stderr.decode(errors='replace').splitlines():
                    if line.strip():
                        graph_png_stderr.append(line.strip())
                        log.info(f'graph(png): {line}')
            graph_png_available = os.path.isfile(pngf) and os.path.getsize(pngf) > 0
        except Exception as e:
            graph_png_error = str(e)
            log.warning(f'dnsviz graph -Tpng unavailable: {graph_png_error}')

        graph_svg_cmd = dnsviz_cmd + ['graph', '--ignore-rfc9276', '-Tsvg', '-r', pf, '-o', svgf] + zone_chain
        graph_svg_stderr = []
        graph_svg_error = ''
        graph_svg_available = False
        log.info(f'Ejecutando DNSViz: {" ".join(graph_svg_cmd)}')
        _status(76, 'DNSViz graph: generando SVG')
        try:
            try:
                svgres = subprocess.run(graph_svg_cmd, check=True, timeout=60, capture_output=True)
            except subprocess.CalledProcessError as e:
                err = (e.stderr or b'').decode(errors='replace')
                if '--ignore-rfc9276' in err and ('no such option' in err.lower() or 'unrecognized' in err.lower()):
                    graph_svg_cmd = dnsviz_cmd + ['graph', '-Tsvg', '-r', pf, '-o', svgf] + zone_chain
                    log.info(f'Ejecutando DNSViz: {" ".join(graph_svg_cmd)}')
                    svgres = subprocess.run(graph_svg_cmd, check=True, timeout=60, capture_output=True)
                else:
                    raise
            if svgres.stderr:
                for line in svgres.stderr.decode(errors='replace').splitlines():
                    if line.strip():
                        graph_svg_stderr.append(line.strip())
                        log.info(f'graph(svg): {line}')
            graph_svg_available = os.path.isfile(svgf) and os.path.getsize(svgf) > 0
        except Exception as e:
            graph_svg_error = str(e)
            log.warning(f'dnsviz graph -Tsvg unavailable: {graph_svg_error}')

        # dnsviz print: salida en texto plano legible (text-print.txt)
        print_cmd = dnsviz_cmd + ['print', '-r', pf] + zone_chain
        print_stderr = []
        print_error = ''
        log.info(f'Ejecutando DNSViz: {" ".join(print_cmd)}')
        _status(80, 'DNSViz print: generando reporte de texto')
        try:
            print_result = subprocess.run(print_cmd, check=True, timeout=30, capture_output=True)
            with open(txf, 'w', encoding='utf-8') as f:
                f.write(print_result.stdout.decode(errors='replace'))
            if print_result.stderr:
                for line in print_result.stderr.decode(errors='replace').splitlines():
                    if line.strip():
                        print_stderr.append(line.strip())
                        log.info(f'print: {line}')
        except Exception as e:
            print_error = str(e)
            log.warning(f'dnsviz print unavailable: {print_error}')
            try:
                with open(txf, 'w', encoding='utf-8') as f:
                    f.write('')
            except Exception:
                pass

    log.info(f'grok zones found: {list(grok.keys())}')
    result = _parse_grok(grok, domain, dnsviz_visual)
    ipv6_available = not any('No global IPv6 connectivity detected' in line for line in probe_stderr)
    fidelity_notes = []
    if not ipv6_available:
        fidelity_notes.append('Local WSL has no global IPv6 connectivity; IPv6-only DNSViz.net notices can differ.')
    fidelity_notes.append('DNSViz visual notices use --ignore-rfc9276 to match dnsviz.net visual defaults; raw_grok keeps RFC 9276 findings.')
    if dnsviz_visual.get('source') != 'dnsviz graph node_info':
        fidelity_notes.append('DNSViz visual model could not be extracted; report uses raw grok fallback only.')
    else:
        fidelity_notes.append('DNSViz graph node_info was extracted locally; dnsviz.net can still differ by network perspective and UI options.')
    result['dnsviz_visual'] = dnsviz_visual
    result['fidelity'] = {
        'dnsviz_graph_model_available': dnsviz_visual.get('source') == 'dnsviz graph node_info',
        'ipv6_available': ipv6_available,
        'visual_ignore_rfc9276': True,
        'source': dnsviz_visual.get('source'),
        'notes': fidelity_notes,
    }
    result['dnsviz'] = {
        'version':       _dnsviz_version(),
        'analysis_id':   analysis_id,
        'zone_chain':    zone_chain,
        'grok_zones':    list(grok.keys()),
        'raw_grok':      grok,
        'probe_command': ' '.join(dnsviz_cmd + ['probe', '-A', '-a', '.', '-o', 'probe.json'] + zone_chain),
        'grok_command':  ' '.join(dnsviz_cmd + ['grok', '-l', 'warning', '-r', 'probe.json', '-o', 'grok.json'] + zone_chain),
        'graph_command':     ' '.join(dnsviz_cmd + ['graph', '--ignore-rfc9276', '-Thtml', '-r', 'probe.json', '-o', 'graph.html'] + zone_chain),
        'graph_png_command': ' '.join(dnsviz_cmd + ['graph', '--ignore-rfc9276', '-Tpng',  '-r', 'probe.json', '-o', 'graph.png']  + zone_chain),
        'graph_svg_command': ' '.join(dnsviz_cmd + ['graph', '--ignore-rfc9276', '-Tsvg',  '-r', 'probe.json', '-o', 'graph.svg']  + zone_chain),
        'print_command':     ' '.join(dnsviz_cmd + ['print', '-r', 'probe.json'] + zone_chain),
        'graph_command_effective': ' '.join([os.path.basename(part) if part in (pf, hf) else part for part in graph_cmd]),
        'probe_stderr':  probe_stderr,
        'grok_stderr':   grok_stderr,
        'graph_stderr':  graph_stderr,
        'graph_error':   graph_error,
        'graph_png_stderr':    graph_png_stderr,
        'graph_png_error':     graph_png_error,
        'graph_png_available': graph_png_available,
        'graph_svg_stderr':    graph_svg_stderr,
        'graph_svg_error':     graph_svg_error,
        'graph_svg_available': graph_svg_available,
        'print_stderr':  print_stderr,
        'print_error':   print_error,
        'ipv6_available': ipv6_available,
        'persisted_files': {
            'probe':     os.path.basename(pf),
            'grok':      os.path.basename(gf),
            'graph':     os.path.basename(hf),
            'graph_png': os.path.basename(pngf),
            'graph_svg': os.path.basename(svgf),
            'print':     os.path.basename(txf),
        },
    }
    try:
        with open(txf, encoding='utf-8') as f:
            result['dnsviz']['print_text'] = f.read()
    except Exception:
        result['dnsviz']['print_text'] = ''
    return result

def _get_gcloud_command() -> list:
    if GCLOUD_CMD:
        return GCLOUD_CMD.split()
    for candidate in ('gcloud.cmd', 'gcloud', 'gcloud.ps1'):
        path = shutil.which(candidate)
        if path:
            if path.lower().endswith('.ps1'):
                return ['powershell', '-ExecutionPolicy', 'Bypass', '-File', path]
            return [path]
    raise RuntimeError('gcloud CLI not found. Set GCLOUD_CMD or install Google Cloud SDK.')

def _gcloud_base_args() -> list:
    return _get_gcloud_command() + ['compute']

def _run_gcloud(args: list, timeout: int = 300) -> subprocess.CompletedProcess:
    cmd = _gcloud_base_args() + args
    log.info(f'Ejecutando GCP worker: {" ".join(cmd)}')
    return subprocess.run(cmd, check=True, timeout=timeout, capture_output=True)

def _remote_analysis_dir(analysis_id: str) -> str:
    return f'{DNSVIZ_REMOTE_BASE_DIR.rstrip("/")}/{analysis_id}'

def _run_dnsviz_remote_gcp(domain: str, analysis_id: str, status_callback=None) -> dict:
    """Runs DNSViz on the configured GCP dual-stack VM and imports artifacts.

    The remote VM is the authoritative DNSViz vantage point. This backend only
    orchestrates execution, downloads the raw artifacts, and builds the same
    report shape used by the local runner.
    """
    def _status(progress: int, message: str) -> None:
        if status_callback:
            status_callback(progress, message)

    zone_chain = _build_zone_chain(domain)
    out_dir = _analysis_dir(analysis_id)
    os.makedirs(out_dir, exist_ok=True)

    remote_dir = _remote_analysis_dir(analysis_id)
    remote_cmd = (
        f'{shlex.quote(DNSVIZ_REMOTE_RUNNER)} '
        f'{shlex.quote(domain)} '
        f'{shlex.quote(remote_dir)}'
    )
    ssh_args = [
        'ssh', DNSVIZ_GCP_VM,
        '--zone', DNSVIZ_GCP_ZONE,
        '--project', DNSVIZ_GCP_PROJECT,
        '--command', remote_cmd,
    ]
    _status(25, 'Worker GCP: ejecutando DNSViz probe/grok/graph/print')
    run_result = _run_gcloud(ssh_args, timeout=240)
    remote_stdout = run_result.stdout.decode(errors='replace').splitlines()
    remote_stderr = run_result.stderr.decode(errors='replace').splitlines()

    artifacts = ['probe.json', 'grok.json', 'graph.html', 'graph.png', 'graph.svg', 'print.txt']
    copy_errors = []
    for artifact in artifacts:
        artifact_progress = {
            'probe.json': 62,
            'grok.json': 68,
            'graph.html': 74,
            'graph.png': 80,
            'graph.svg': 82,
            'print.txt': 84,
        }.get(artifact, 80)
        _status(artifact_progress, f'Worker GCP: importando {artifact}')
        src = f'{DNSVIZ_GCP_VM}:{remote_dir}/{artifact}'
        dst = os.path.join(out_dir, artifact)
        scp_args = [
            'scp', src, dst,
            '--zone', DNSVIZ_GCP_ZONE,
            '--project', DNSVIZ_GCP_PROJECT,
        ]
        try:
            _run_gcloud(scp_args, timeout=120)
        except Exception as e:
            copy_errors.append(f'{artifact}: {e}')
            if artifact in {'probe.json', 'grok.json'}:
                raise

    pf  = os.path.join(out_dir, 'probe.json')
    gf  = os.path.join(out_dir, 'grok.json')
    hf  = os.path.join(out_dir, 'graph.html')
    pngf = os.path.join(out_dir, 'graph.png')
    svgf = os.path.join(out_dir, 'graph.svg')
    txf = os.path.join(out_dir, 'print.txt')

    with open(gf, encoding='utf-8') as f:
        raw = f.read().strip()
        grok = json.loads(raw) if raw else {}

    dnsviz_visual = {
        'source': 'unavailable',
        'node_info_count': 0,
        'rrset_status': [],
        'dnskey_ds_nsec_status': [],
        'delegation_status': [],
        'other_status': [],
        'notices': {'errors_count': 0, 'warnings_count': 0, 'errors': [], 'warnings': []},
        'raw_node_info': {},
    }
    graph_error = ''
    if os.path.isfile(hf) and os.path.getsize(hf) > 0:
        node_info, node_error = _extract_graph_node_info(hf)
        if node_error:
            graph_error = node_error
            dnsviz_visual['source'] = 'graph_html_parse_failed'
        else:
            dnsviz_visual = _build_dnsviz_visual(node_info)
            dnsviz_visual['default_view'] = _build_dnsviz_default_view(dnsviz_visual, domain, zone_chain)

    graph_png_available = os.path.isfile(pngf) and os.path.getsize(pngf) > 0
    graph_svg_available = os.path.isfile(svgf) and os.path.getsize(svgf) > 0
    result = _parse_grok(grok, domain, dnsviz_visual)
    result['dnsviz_visual'] = dnsviz_visual
    result['fidelity'] = {
        'dnsviz_graph_model_available': dnsviz_visual.get('source') == 'dnsviz graph node_info',
        'ipv6_available': True,
        'visual_ignore_rfc9276': None,
        'source': dnsviz_visual.get('source'),
        'notes': [
            'DNSViz was executed on the configured Google Cloud dual-stack worker.',
            'Raw artifacts were imported unchanged from the remote DNSViz run.',
            'DNSViz.net can still differ by network perspective and execution time.',
        ],
    }
    result['dnsviz'] = {
        'version':       'remote',
        'analysis_id':   analysis_id,
        'zone_chain':    zone_chain,
        'grok_zones':    list(grok.keys()),
        'raw_grok':      grok,
        'runner':        'gcp_ssh_worker',
        'worker': {
            'project': DNSVIZ_GCP_PROJECT,
            'zone': DNSVIZ_GCP_ZONE,
            'vm': DNSVIZ_GCP_VM,
            'remote_runner': DNSVIZ_REMOTE_RUNNER,
            'remote_dir': remote_dir,
        },
        'probe_command': 'remote worker: dnsviz probe -A -a . -o probe.json ' + ' '.join(zone_chain),
        'grok_command':  'remote worker: dnsviz grok -l warning -r probe.json -o grok.json ' + ' '.join(zone_chain),
        'graph_command': 'remote worker: dnsviz graph -Thtml -r probe.json -o graph.html ' + ' '.join(zone_chain),
        'graph_png_command': 'remote worker: dnsviz graph -Tpng -r probe.json -o graph.png ' + ' '.join(zone_chain),
        'graph_svg_command': 'remote worker: dnsviz graph -Tsvg -r probe.json -o graph.svg ' + ' '.join(zone_chain),
        'print_command': 'remote worker: dnsviz print -r probe.json ' + ' '.join(zone_chain),
        'graph_command_effective': 'remote worker',
        'probe_stderr':  [line for line in remote_stderr if line.strip()],
        'grok_stderr':   [],
        'graph_stderr':  [],
        'graph_error':   graph_error,
        'graph_png_stderr':    [],
        'graph_png_error':     '',
        'graph_png_available': graph_png_available,
        'graph_svg_stderr':    [],
        'graph_svg_error':     '',
        'graph_svg_available': graph_svg_available,
        'print_stderr':  [],
        'print_error':   '',
        'remote_stdout': [line for line in remote_stdout if line.strip()],
        'copy_errors':   copy_errors,
        'ipv6_available': True,
        'persisted_files': {
            'probe':     os.path.basename(pf),
            'grok':      os.path.basename(gf),
            'graph':     os.path.basename(hf),
            'graph_png': os.path.basename(pngf),
            'graph_svg': os.path.basename(svgf),
            'print':     os.path.basename(txf),
        },
    }
    try:
        with open(txf, encoding='utf-8') as f:
            result['dnsviz']['print_text'] = f.read()
    except Exception:
        result['dnsviz']['print_text'] = ''
    return result

def _parse_grok(grok: dict, domain: str, dnsviz_visual: dict | None = None) -> dict:
    """Convierte la salida JSON de dnsviz grok en el formato del Observatorio.
    
    Camina TODAS las zonas del grok (no solo el dominio analizado)
    para capturar errores en zonas padre (., ec., org.ec., etc.)
    que también afectan la validación DNSSEC del dominio.
    """
    dk = domain.rstrip('.') + '.'

    errors      = []
    warnings    = []
    all_servers = set()

    # Status DNSSEC: usar estados criptograficos de DNSViz, no transporte.
    status_map = {0: 'SECURE', 1: 'INSECURE', 2: 'BOGUS'}

    # Cadena de confianza — todas las zonas presentes en el grok, ordenadas
    trust_chain = []

    # Recopilar errores y warnings de TODAS las zonas
    # Cada error lleva su zona de origen para mejor diagnóstico
    def _walk(obj, zone_name, source_path=''):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == 'errors' and isinstance(v, list):
                    for e in v:
                        if isinstance(e, dict) and e.get('code'):
                            errors.append({
                                'code':          e.get('code', ''),
                                'description':   e.get('description', ''),
                                'servers':       e.get('servers', []),
                                'query_options': e.get('query_options', []),
                                'zone':          zone_name,
                                'source_path':   source_path
                            })
                            all_servers.update(e.get('servers', []))
                elif k == 'warnings' and isinstance(v, list):
                    for w in v:
                        if isinstance(w, dict) and w.get('code'):
                            warnings.append({
                                'code':        w.get('code', ''),
                                'description': w.get('description', ''),
                                'servers':     w.get('servers', []),
                                'zone':        zone_name,
                                'source_path': source_path
                            })
                else:
                    next_path = f'{source_path}/{k}' if source_path else k
                    _walk(v, zone_name, next_path)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item, zone_name, source_path)

    for zone_key, zone_data in grok.items():
        zone_name = zone_key.rstrip('.') or '.'
        _walk(zone_data, zone_name)

    visual_notices = (dnsviz_visual or {}).get('notices') if isinstance(dnsviz_visual, dict) else None
    if isinstance(visual_notices, dict):
        seen_error_keys = {
            (item.get('code'), item.get('description'), tuple(item.get('servers') or []))
            for item in errors
        }
        seen_warning_keys = {
            (item.get('code'), item.get('description'), tuple(item.get('servers') or []))
            for item in warnings
        }

        def _append_visual_operational(target, seen, items, source_path):
            for issue in items or []:
                if not isinstance(issue, dict) or not issue.get('code') or not _is_operational_issue(issue):
                    continue
                key = (issue.get('code'), issue.get('description', ''), tuple(issue.get('servers') or []))
                if key in seen:
                    continue
                target.append({
                    'code': issue.get('code', ''),
                    'description': issue.get('description', ''),
                    'servers': issue.get('servers', []),
                    'query_options': issue.get('query_options', []),
                    'zone': domain.rstrip('.'),
                    'source_path': source_path,
                    'dnsviz_node_status': issue.get('node_status', ''),
                    'dnsviz_label': issue.get('label', ''),
                })
                all_servers.update(issue.get('servers', []))
                seen.add(key)

        _append_visual_operational(errors, seen_error_keys, visual_notices.get('errors'), 'dnsviz_visual/notices/errors')
        _append_visual_operational(warnings, seen_warning_keys, visual_notices.get('warnings'), 'dnsviz_visual/notices/warnings')

    # Mantener cada ocurrencia: MISSING_RRSIG en 10 RRsets son 10 hallazgos.
    zone_order = {
        (z.rstrip('.') or '.'): i
        for i, z in enumerate(_build_zone_chain(domain))
    }
    for i, item in enumerate(errors, 1):
        item['count'] = 1
        item['occurrence'] = i
    for i, item in enumerate(warnings, 1):
        item['count'] = 1
        item['occurrence'] = i

    errors.sort(key=lambda x: (zone_order.get(x.get('zone'), 999), x.get('code', ''), x.get('occurrence', 0)))
    warnings.sort(key=lambda x: (zone_order.get(x.get('zone'), 999), x.get('code', ''), x.get('occurrence', 0)))
    _enrich_issues_with_layers(errors)
    _enrich_issues_with_layers(warnings)

    nameservers = []
    try:
        out = subprocess.check_output(['dig', '+short', 'NS', domain], timeout=5, text=True)
        nameservers = [n.rstrip('.') for n in out.strip().splitlines() if n]
    except Exception:
        pass

    dns_rcode = _dns_rcode(domain)
    dnssec_status = _calculate_dnssec_status(grok, domain, errors, dns_rcode, dnsviz_visual)
    dns_service_health = _calculate_dns_service_health(errors, warnings, nameservers, domain)

    for zone in _build_zone_chain(domain):
        zone_name = zone.rstrip('.') or '.'
        zone_key = '.' if zone_name == '.' else zone_name + '.'
        st = grok.get(zone_key, {}).get('delegation', {}).get('status')
        zone_status = status_map.get(st)
        if zone_status is None:
            has_crypto_delegation_error = any(
                e.get('zone') == zone_name
                and e.get('source_path') == 'delegation'
                and _is_crypto_dnssec_issue(e)
                for e in errors
            )
            zone_status = 'BOGUS' if has_crypto_delegation_error else 'UNKNOWN'
        trust_chain.append({
            'name':   zone_name,
            'secure': zone_status == 'SECURE',
            'status': zone_status
        })

    log.info(
        f'Grok zones: {list(grok.keys())} | errors: {len(errors)} | '
        f'warnings: {len(warnings)} | dnssec: {dnssec_status} | dns_service: {dns_service_health}'
    )

    return {
        'domain':        domain,
        'timestamp':     _now_iso(),
        'dnssec_status': dnssec_status,
        'dns_service_health': dns_service_health,
        'nameservers':   nameservers,
        'trust_chain':   trust_chain,
        'errors':        errors,
        'warnings':      warnings,
        'servers':       list(all_servers)
    }

# ─────────────────────────────────────────────
# VISTA ESTRUCTURADA (nueva arquitectura: interprete de DNSViz)
# ─────────────────────────────────────────────
def _classify_zone(name: str, target: str) -> dict:
    nm = (name or '').rstrip('.') or '.'
    tg = (target or '').rstrip('.')
    is_root = (nm == '.')
    is_target = bool(tg) and (nm == tg)
    is_tld = (not is_root and not is_target and '.' not in nm)
    is_intermediate = not (is_root or is_target or is_tld)
    return {
        'is_root':         is_root,
        'is_tld':          is_tld,
        'is_intermediate': is_intermediate,
        'is_target':       is_target,
    }

def _entry_zone(entry: dict) -> str:
    """Mejor esfuerzo para inferir la zona DNS de un entry visual."""
    key = entry.get('key', '')
    if key.startswith('RRset-'):
        return _clean_dns_name(entry.get('name'))
    if key.startswith(('DNSKEY-', 'DS-', 'NSEC-', 'NSEC3-', 'NSECC-', 'NSEC3C-')):
        parts = key.split('|')
        if len(parts) >= 2:
            return _clean_dns_name(parts[1])
    if key.startswith('del-'):
        head = key.split('|', 1)[0].replace('del-', '', 1)
        return _clean_dns_name(head)
    return ''

def _assign_zone_to_chain(entry_zone: str, zone_chain_clean: list) -> str:
    """Mapea la zona del entry a la zona mas especifica de la cadena que la cubre."""
    if not entry_zone:
        return ''
    matches = []
    for z in zone_chain_clean:
        if z == '.':
            matches.append(z)
            continue
        if entry_zone == z or entry_zone.endswith('.' + z):
            matches.append(z)
    if not matches:
        return ''
    return max(matches, key=lambda z: 0 if z == '.' else len(z))

def _filter_visual_to_zone(visual: dict, zone_clean: str, zone_chain_clean: list) -> dict:
    """Devuelve los rrset/dnskey/delegation visuales que pertenecen a la zona dada."""
    out = {'rrset_status': [], 'dnskey_ds_nsec_status': [], 'delegation_status': []}
    sections = ('rrset_status', 'dnskey_ds_nsec_status', 'delegation_status')
    for section in sections:
        flat = []
        for group in (visual or {}).get(section, []) or []:
            flat.extend(group.get('items') or [])
        for entry in flat:
            ez = _entry_zone(entry)
            assigned = _assign_zone_to_chain(ez, zone_chain_clean)
            if assigned == zone_clean:
                out[section].append(entry)
        out[section] = _group_visual_status(out[section])
    return out

def _enrich_notice(notice: dict, kind: str, layers_by_code: dict) -> dict:
    code = notice.get('code') or ''
    c1a_rows = layers_by_code['capa1a'].get(code, []) or []
    c1b_row  = layers_by_code['capa1b'].get(code)
    c2_row   = layers_by_code['capa2'].get(code)

    rfcs = []
    rfcs_text = []
    for row in c1a_rows:
        for rfc in row.get('rfcs') or []:
            if rfc and rfc not in rfcs:
                rfcs.append(rfc)
        for ref in row.get('references') or []:
            if ref and ref not in rfcs_text:
                rfcs_text.append(ref)

    c3_index = layers_by_code['capa3']
    c3_code = code
    if (code, 'es') not in c3_index and (code, 'en') not in c3_index:
        c3_code = EXPLANATION_ALIAS.get(code, code)
    explanations = {
        'es': c3_index.get((c3_code, 'es')),
        'en': c3_index.get((c3_code, 'en')),
    }

    layers_used = []
    if c1a_rows: layers_used.append('capa1a')
    if c1b_row:  layers_used.append('capa1b')
    if c2_row:   layers_used.append('capa2')
    if explanations['es'] or explanations['en']: layers_used.append('capa3')

    zone = (notice.get('zone') or '').rstrip('.') or '.'
    node_label = notice.get('dnsviz_label') or notice.get('label') or ''
    node_status = notice.get('dnsviz_node_status') or notice.get('node_status') or ''
    node_key = notice.get('node_key') or node_label

    return {
        'type':             kind,
        'code':             code,
        'original_message': notice.get('description') or '',
        'zone':             zone,
        'node': {
            'key':    node_key,
            'label':  node_label,
            'status': node_status,
        },
        'servers':       notice.get('servers') or [],
        'query_options': notice.get('query_options') or [],
        'occurrence':    notice.get('occurrence'),
        'rfcs':          rfcs,
        'rfcs_text':     rfcs_text,
        'semantica':     c1b_row,
        'contexto_normativo': c2_row,
        'explanations':  explanations,
        'traceability': {
            'source':       'DNSViz CLI',
            'zone':         zone,
            'node_key':     node_key,
            'layers_used':  layers_used,
        },
    }

def _build_structured_view(domain: str, zone_chain: list, dnsviz_visual: dict,
                           grok_errors: list, grok_warnings: list,
                           layers_by_code: dict) -> dict:
    target = domain.rstrip('.')
    zone_chain_clean = [_clean_dns_name(z) for z in zone_chain]

    enriched_errors = [_enrich_notice(e, 'Error', layers_by_code) for e in (grok_errors or [])]
    enriched_warnings = [_enrich_notice(w, 'Warning', layers_by_code) for w in (grok_warnings or [])]
    all_notices = enriched_errors + enriched_warnings

    zone_index = {z: i for i, z in enumerate(zone_chain_clean)}

    zones = []
    for raw in zone_chain:
        nm = _clean_dns_name(raw)
        cls = _classify_zone(nm, target)
        z_errors = [n for n in enriched_errors if n['zone'] == nm]
        z_warnings = [n for n in enriched_warnings if n['zone'] == nm]
        z_rfcs = sorted({rfc for n in (z_errors + z_warnings) for rfc in (n.get('rfcs') or [])})
        zone_visual = _filter_visual_to_zone(dnsviz_visual, nm, zone_chain_clean)
        zones.append({
            'name':           nm,
            'classification': cls,
            'visual_status':  zone_visual,
            'errors':         z_errors,
            'warnings':       z_warnings,
            'rfcs':           z_rfcs,
        })

    sections = {
        'rrset_status':          dnsviz_visual.get('rrset_status', []),
        'dnskey_ds_nsec_status': dnsviz_visual.get('dnskey_ds_nsec_status', []),
        'delegation_status':     dnsviz_visual.get('delegation_status', []),
        'notices': {
            'errors':   enriched_errors,
            'warnings': enriched_warnings,
        },
    }

    by_zone = {}
    for n in all_notices:
        z = n['zone']
        bucket = by_zone.setdefault(z, {'zone': z, 'errors': [], 'warnings': []})
        if n['type'] == 'Error':
            bucket['errors'].append(n)
        else:
            bucket['warnings'].append(n)
    notices_by_zone = sorted(by_zone.values(), key=lambda b: zone_index.get(b['zone'], 999))

    by_code = {}
    for n in all_notices:
        c = n['code']
        bucket = by_code.setdefault(c, {
            'code':  c,
            'level': (n.get('semantica') or {}).get('dnsviz_level') or n['type'],
            'group': (n.get('semantica') or {}).get('dnsviz_group') or '',
            'rfcs':  list(n.get('rfcs') or []),
            'occurrences': [],
        })
        for rfc in (n.get('rfcs') or []):
            if rfc not in bucket['rfcs']:
                bucket['rfcs'].append(rfc)
        bucket['occurrences'].append({
            'type':          n['type'],
            'zone':          n['zone'],
            'node':          n['node'],
            'message':       n['original_message'],
            'servers':       n['servers'],
            'query_options': n['query_options'],
        })
    notices_by_code = sorted(by_code.values(), key=lambda x: (-len(x['occurrences']), x['code']))

    by_rfc = {}
    for n in all_notices:
        for rfc in n.get('rfcs') or []:
            entry = by_rfc.setdefault(rfc, {'rfc': rfc, 'codes': set(), 'count': 0})
            entry['codes'].add(n['code'])
            entry['count'] += 1
    notices_by_rfc = []
    for rfc, info in sorted(by_rfc.items(), key=lambda x: (-x[1]['count'], x[0])):
        notices_by_rfc.append({
            'rfc':   rfc,
            'codes': sorted(info['codes']),
            'count': info['count'],
        })

    return {
        'zones':           zones,
        'sections':        sections,
        'notices_by_zone': notices_by_zone,
        'notices_by_code': notices_by_code,
        'notices_by_rfc':  notices_by_rfc,
    }

def _layers_subset_for_codes(layers_by_code: dict, codes: set) -> dict:
    """Subset de las 4 capas tabulares restringido a los codigos vistos."""
    out = {'capa1a': {}, 'capa1b': {}, 'capa2': {}, 'capa3': {}}
    for c in codes:
        rows = layers_by_code['capa1a'].get(c)
        if rows: out['capa1a'][c] = rows
        r = layers_by_code['capa1b'].get(c)
        if r: out['capa1b'][c] = r
        r = layers_by_code['capa2'].get(c)
        if r: out['capa2'][c] = r
        c3_code = c if (c, 'es') in layers_by_code['capa3'] or (c, 'en') in layers_by_code['capa3'] else EXPLANATION_ALIAS.get(c, c)
        es = layers_by_code['capa3'].get((c3_code, 'es'))
        en = layers_by_code['capa3'].get((c3_code, 'en'))
        if es or en:
            out['capa3'][c] = {'es': es, 'en': en}
    return out

def _build_result_json(domain: str, analysis_id: str, internal_result: dict) -> dict:
    """Ensambla el JSON final segun el spec del Observatorio.

    `internal_result` es lo que devuelve `_run_dnsviz`, que ya incluye
    `dnsviz_visual`, `errors`, `warnings`, `dnsviz`, `nameservers`, etc.
    El JSON final NO expone `dnssec_status` ni `dns_service_health`.
    """
    layers_by_code = _load_layers()['by_code']
    zone_chain = (internal_result.get('dnsviz') or {}).get('zone_chain') or _build_zone_chain(domain)

    grok_errors   = internal_result.get('errors')   or []
    grok_warnings = internal_result.get('warnings') or []
    dnsviz_visual = internal_result.get('dnsviz_visual') or {}

    structured = _build_structured_view(
        domain, zone_chain, dnsviz_visual,
        grok_errors, grok_warnings, layers_by_code,
    )

    codes_seen = {n.get('code') for n in (grok_errors + grok_warnings) if n.get('code')}
    layers_subset = _layers_subset_for_codes(layers_by_code, codes_seen)

    base_url = f'/analyze/{analysis_id}'
    raw_grok = (internal_result.get('dnsviz') or {}).get('raw_grok') or {}
    raw_text = (internal_result.get('dnsviz') or {}).get('print_text') or ''

    visual_clean = {
        'source':                 dnsviz_visual.get('source'),
        'rrset_status':           dnsviz_visual.get('rrset_status', []),
        'dnskey_ds_nsec_status':  dnsviz_visual.get('dnskey_ds_nsec_status', []),
        'delegation_status':      dnsviz_visual.get('delegation_status', []),
        'notices': {
            'errors_count':   (dnsviz_visual.get('notices') or {}).get('errors_count', 0),
            'warnings_count': (dnsviz_visual.get('notices') or {}).get('warnings_count', 0),
            'errors':         (dnsviz_visual.get('notices') or {}).get('errors', []),
            'warnings':       (dnsviz_visual.get('notices') or {}).get('warnings', []),
        },
        'default_view': dnsviz_visual.get('default_view'),
    }

    return {
        'id':           analysis_id,
        'domain':       domain,
        'generated_at': internal_result.get('timestamp') or _now_iso(),
        'source': {
            'engine':    'DNSViz CLI',
            'probe':     f'{base_url}/probe.json',
            'graph':     f'{base_url}/graph.html',
            'graph_png': f'{base_url}/graph.png',
            'graph_svg': f'{base_url}/graph.svg',
            'grok':      f'{base_url}/grok.json',
            'print':     f'{base_url}/print.txt',
            'commands': {
                'probe':     (internal_result.get('dnsviz') or {}).get('probe_command'),
                'grok':      (internal_result.get('dnsviz') or {}).get('grok_command'),
                'graph':     (internal_result.get('dnsviz') or {}).get('graph_command'),
                'graph_png': (internal_result.get('dnsviz') or {}).get('graph_png_command'),
                'graph_svg': (internal_result.get('dnsviz') or {}).get('graph_svg_command'),
                'print':     (internal_result.get('dnsviz') or {}).get('print_command'),
            },
            'version':    (internal_result.get('dnsviz') or {}).get('version'),
            'zone_chain': zone_chain,
            'fidelity':   internal_result.get('fidelity', {}),
        },
        'dnsviz_original': {
            'graph_html_url': f'{base_url}/graph.html',
            'graph_png_url':  f'{base_url}/graph.png',
            'graph_svg_url':  f'{base_url}/graph.svg',
            'graph_png_available': bool((internal_result.get('dnsviz') or {}).get('graph_png_available')),
            'graph_svg_available': bool((internal_result.get('dnsviz') or {}).get('graph_svg_available')),
            'raw_text':       raw_text,
            'raw_grok':       raw_grok,
        },
        'dnsviz_visual':   visual_clean,
        'structured_view': structured,
        'layers':          layers_subset,
        'nameservers':     internal_result.get('nameservers') or [],
    }

# ─────────────────────────────────────────────
# ADMIN — ESTADÍSTICAS
# ─────────────────────────────────────────────
@app.route('/admin/stats', methods=['GET'])
@require_auth
def admin_stats():
    db = _db_load()
    return jsonify({
        'total_analyses': len(db['analyses']),
        'unique_domains':  len(set(a['domain'] for a in db['analyses'])),
        'bogus_domains':   sum(1 for a in db['analyses'] if a.get('status') == 'BOGUS'),
        'secure_domains':  sum(1 for a in db['analyses'] if a.get('status') == 'SECURE'),
        'insecure_domains':sum(1 for a in db['analyses'] if a.get('status') == 'INSECURE'),
        'active_users':    sum(1 for u in db['users'] if u.get('active')),
        'current_user':    _current_user(),
        'current_role':    _current_role(),
        'recent': [
            {k: v for k, v in a.items() if k != 'data'}
            for a in db['analyses'][:10]
        ],
    })

# ─────────────────────────────────────────────
# ADMIN — HISTORIAL
# ─────────────────────────────────────────────
@app.route('/admin/history', methods=['GET'])
@require_auth
def admin_history():
    db   = _db_load()
    page = max(1, int(request.args.get('page', 1)))
    per  = 20
    q    = request.args.get('q', '').strip().lower()
    items = [a for a in db['analyses'] if not q or q in a['domain']]
    start = (page - 1) * per
    return jsonify({
        'items':    [{k: v for k, v in a.items() if k != 'data'} for a in items[start:start + per]],
        'total':    len(items),
        'per_page': per,
        'page':     page,
        'pages':    max(1, -(-len(items) // per))  # ceil division
    })

@app.route('/admin/history/<aid>', methods=['GET'])
@require_auth
def admin_history_get(aid):
    db = _db_load()
    a  = next((x for x in db['analyses'] if x['id'] == aid), None)
    if not a:
        return jsonify({'error': 'not_found'}), 404
    # Compat: registros antiguos guardaban el payload completo en a['data'].
    # Los nuevos guardan solo el indice y el JSON vive en backend/analyses/<id>/result.json.
    rpath = a.get('result_path')
    if rpath:
        candidate = os.path.normpath(os.path.join(BASE_DIR, rpath))
        if candidate.startswith(os.path.normpath(BASE_DIR)) and os.path.isfile(candidate):
            try:
                with open(candidate, encoding='utf-8') as f:
                    return jsonify(json.load(f))
            except Exception as e:
                log.warning(f'admin_history_get read result.json failed: {e}')
    if 'data' in a:
        return jsonify({**a['data'], 'id': a['id'], 'timestamp': a.get('timestamp'), 'domain': a['domain']})
    return jsonify({'error': 'result_unavailable', 'message': 'result.json no disponible para este analisis'}), 410

@app.route('/admin/history/<aid>', methods=['DELETE'])
@require_auth
def admin_history_delete(aid):
    db = _db_load()
    db['analyses'] = [a for a in db['analyses'] if a['id'] != aid]
    _db_save(db)
    return jsonify({'ok': True})

# ─────────────────────────────────────────────
# ADMIN — USUARIOS
# ─────────────────────────────────────────────
@app.route('/admin/users', methods=['GET'])
@require_admin
def admin_users_list():
    db = _db_load()
    return jsonify({
        'users': [{k: v for k, v in u.items() if k != 'password'} for u in db['users']]
    })

@app.route('/admin/users', methods=['POST'])
@require_admin
def admin_users_create():
    data  = request.json or {}
    email = data.get('email', '').strip().lower()
    pwd   = data.get('password', '')
    role  = data.get('role', 'analyst')

    if not email or not pwd:
        return jsonify({'error': 'missing_fields', 'message': 'Email y contraseña requeridos'}), 400
    if role not in ('admin', 'analyst'):
        return jsonify({'error': 'invalid_role', 'message': 'Rol debe ser admin o analyst'}), 400

    db = _db_load()
    if any(u['email'].lower() == email for u in db['users']):
        return jsonify({'error': 'user_exists', 'message': 'El usuario ya existe'}), 409

    db['users'].append({
        'id':         _uid(),
        'email':      email,
        'password':   _hash(pwd),
        'role':       role,
        'active':     True,
        'last_login': None,
    })
    _db_save(db)
    _log(f'Usuario creado: {email} ({role})')
    return jsonify({'ok': True})

@app.route('/admin/users/<uid>/toggle', methods=['POST'])
@require_admin
def admin_users_toggle(uid):
    active = bool((request.json or {}).get('active', True))
    db = _db_load()
    found = False
    for u in db['users']:
        if u['id'] == uid:
            # No permitir desactivar el único admin
            if not active and u['role'] == 'admin':
                admins = sum(1 for x in db['users'] if x['role'] == 'admin' and x.get('active'))
                if admins <= 1:
                    return jsonify({'error': 'cannot_disable_last_admin',
                                    'message': 'No puedes desactivar el único admin'}), 400
            u['active'] = active
            found = True
    if not found:
        return jsonify({'error': 'not_found'}), 404
    _db_save(db)
    return jsonify({'ok': True})

@app.route('/admin/users/<uid>', methods=['DELETE'])
@require_admin
def admin_users_delete(uid):
    db = _db_load()
    user = next((u for u in db['users'] if u['id'] == uid), None)
    if not user:
        return jsonify({'error': 'not_found'}), 404
    # No eliminar el único admin
    if user['role'] == 'admin':
        admins = sum(1 for u in db['users'] if u['role'] == 'admin')
        if admins <= 1:
            return jsonify({'error': 'cannot_delete_last_admin',
                            'message': 'No puedes eliminar el único admin'}), 400
    db['users'] = [u for u in db['users'] if u['id'] != uid]
    _db_save(db)
    _log(f'Usuario eliminado: {user["email"]}')
    return jsonify({'ok': True})

@app.route('/admin/users/<uid>/password', methods=['POST'])
@require_admin
def admin_users_change_password(uid):
    new_pwd = (request.json or {}).get('password', '')
    if len(new_pwd) < 8:
        return jsonify({'error': 'password_too_short', 'message': 'Mínimo 8 caracteres'}), 400
    db = _db_load()
    for u in db['users']:
        if u['id'] == uid:
            u['password'] = _hash(new_pwd)
            _db_save(db)
            _log(f'Contraseña cambiada: {u["email"]}')
            return jsonify({'ok': True})
    return jsonify({'error': 'not_found'}), 404

# ─────────────────────────────────────────────
# ADMIN — DOMINIOS MONITOREADOS
# ─────────────────────────────────────────────
@app.route('/admin/domains', methods=['GET'])
@require_auth
def admin_domains_list():
    db = _db_load()
    result = []
    for d in db.get('domains', []):
        last = next((a for a in db['analyses'] if a['domain'] == d['domain']), None)
        result.append({
            **d,
            'last_status':   last['status'] if last else None,
            'last_analyzed': last['timestamp'] if last else None
        })
    return jsonify({'domains': result})

@app.route('/admin/domains', methods=['POST'])
@require_auth
def admin_domains_add():
    domain = (request.json or {}).get('domain', '').strip().lower().rstrip('.')
    if not domain:
        return jsonify({'error': 'missing_domain'}), 400
    db = _db_load()
    if not any(d['domain'] == domain for d in db.get('domains', [])):
        db.setdefault('domains', []).append({'id': _uid(), 'domain': domain, 'added': _now_iso()})
        _db_save(db)
        _log(f'Dominio agregado: {domain}')
    return jsonify({'ok': True})

@app.route('/admin/domains/<did>', methods=['DELETE'])
@require_auth
def admin_domains_delete(did):
    db = _db_load()
    db['domains'] = [d for d in db.get('domains', []) if d['id'] != did]
    _db_save(db)
    return jsonify({'ok': True})

# ─────────────────────────────────────────────
# ADMIN — CAPAS / INFO
# ─────────────────────────────────────────────
@app.route('/admin/report-texts', methods=['GET'])
@require_auth
def admin_report_texts_list():
    db = _db_load()
    items = [
        _report_text_admin_payload(v)
        for v in (db.get('report_texts') or {}).values()
        if isinstance(v, dict)
    ]
    items.sort(key=lambda x: x.get('code', ''))
    return jsonify({'items': items})

@app.route('/admin/report-texts/<code>', methods=['GET'])
@require_auth
def admin_report_texts_get(code):
    normalized_code = (code or '').strip().upper()
    row = (_db_load().get('report_texts') or {}).get(normalized_code)
    if not row:
        return jsonify({'error': 'not_found', 'message': 'Texto no encontrado'}), 404
    return jsonify(_report_text_admin_payload(row))

@app.route('/admin/report-texts', methods=['POST'])
@require_admin
def admin_report_texts_create():
    data = request.json or {}
    code = (data.get('code') or '').strip().upper()
    if not code:
        return jsonify({'error': 'missing_code', 'message': 'Codigo requerido'}), 400

    db = _db_load()
    db.setdefault('report_texts', {})
    if code in db['report_texts']:
        return jsonify({'error': 'already_exists', 'message': 'El codigo ya existe'}), 409

    item = _normalize_report_text(data, code)
    item['updated_at'] = _now_iso()
    item['updated_by'] = _current_user()
    db['report_texts'][code] = item
    _db_save(db)
    _log(f'Report text creado por {_current_user()}: {code}')
    return jsonify(_report_text_admin_payload(item)), 201

@app.route('/admin/report-texts/<code>', methods=['PUT'])
@require_admin
def admin_report_texts_update(code):
    normalized_code = (code or '').strip().upper()
    if not normalized_code:
        return jsonify({'error': 'missing_code', 'message': 'Codigo requerido'}), 400

    data = request.json or {}
    db = _db_load()
    db.setdefault('report_texts', {})
    before = db['report_texts'].get(normalized_code)
    item = _normalize_report_text(data, normalized_code)
    item['updated_at'] = _now_iso()
    item['updated_by'] = _current_user()
    db['report_texts'][normalized_code] = item
    _db_save(db)

    changed = _report_text_changed_fields(before, item)
    _log(f'Report text editado por {_current_user()}: {normalized_code}; campos={",".join(changed) or "sin_cambios"}')
    return jsonify(_report_text_admin_payload(item))

@app.route('/admin/report-texts/<code>', methods=['DELETE'])
@require_admin
def admin_report_texts_delete(code):
    normalized_code = (code or '').strip().upper()
    db = _db_load()
    db.setdefault('report_texts', {})
    if normalized_code not in db['report_texts']:
        return jsonify({'error': 'not_found', 'message': 'Texto no encontrado'}), 404
    del db['report_texts'][normalized_code]
    _db_save(db)
    _log(f'Report text eliminado por {_current_user()}: {normalized_code}')
    return jsonify({'ok': True})

# ─────────────────────────────────────────────
# ADMIN — EDICIÓN DE CAPAS Y TEXTOS (capa1b/capa2/capa3/ui-texts/report-texts)
#   capa1a NO se expone para edición (catálogo soberano DNSViz).
# ─────────────────────────────────────────────
EDITABLE_LAYERS    = ('capa1b', 'capa2', 'capa3', 'ui_texts', 'report_texts')
TABULAR_EDITABLE   = {'capa1b', 'capa2', 'capa3'}
DOCUMENT_EDITABLE  = {'ui_texts', 'report_texts'}
BACKUP_KEEP        = 10

def _normalize_layer_key(slug: str) -> str | None:
    """Permite tanto 'ui-texts' como 'ui_texts' en la URL."""
    if not slug:
        return None
    norm = slug.replace('-', '_').strip().lower()
    return norm if norm in EDITABLE_LAYERS else None

def _layer_backup_dir(key: str) -> str:
    return os.path.join(DATA_DIR, '_backups', key)

def _make_layer_backup(key: str) -> str:
    """Copia el archivo actual a _backups/<key>/<key>.YYYYMMDDTHHMMSSZ.json."""
    src = _layer_path(key)
    if not os.path.isfile(src):
        return ''
    bdir = _layer_backup_dir(key)
    try:
        os.makedirs(bdir, exist_ok=True)
    except Exception as e:
        log.warning(f'cannot create backup dir {bdir}: {e}')
        return ''
    ts = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    dst = os.path.join(bdir, f'{key}.{ts}.json')
    try:
        shutil.copyfile(src, dst)
    except Exception as e:
        log.warning(f'backup copy failed {src} -> {dst}: {e}')
        return ''
    # Recorta a los ultimos BACKUP_KEEP backups
    try:
        existing = sorted(f for f in os.listdir(bdir) if f.startswith(f'{key}.') and f.endswith('.json'))
        while len(existing) > BACKUP_KEEP:
            old = existing.pop(0)
            try:
                os.remove(os.path.join(bdir, old))
            except Exception:
                pass
    except Exception:
        pass
    return os.path.basename(dst)

def _validate_layer_data(key: str, data) -> str | None:
    """Validacion ligera por tipo. NO impone esquema estricto: el admin puede
    extender campos. Solo bloquea estructuras claramente erroneas y duplicados."""
    if key in TABULAR_EDITABLE:
        if not isinstance(data, list):
            return 'Se esperaba un arreglo JSON'
        for i, row in enumerate(data):
            if not isinstance(row, dict):
                return f'Item {i} no es un objeto'
            code = row.get('code')
            if not isinstance(code, str) or not code.strip():
                return f'Item {i} tiene "code" vacío o inválido'
        if key in ('capa1b', 'capa2'):
            seen = set()
            for i, row in enumerate(data):
                if row['code'] in seen:
                    return f'code duplicado en item {i}: {row["code"]}'
                seen.add(row['code'])
        if key == 'capa3':
            seen = set()
            for i, row in enumerate(data):
                lang = (row.get('language') or '').lower()
                if lang not in ('es', 'en'):
                    return f'Item {i} ({row["code"]}): "language" debe ser "es" o "en"'
                k = (row['code'], lang)
                if k in seen:
                    return f'Par (code, language) duplicado en item {i}: {row["code"]}/{lang}'
                seen.add(k)
    elif key in DOCUMENT_EDITABLE:
        if not isinstance(data, dict):
            return 'Se esperaba un objeto JSON'
    return None

@app.route('/admin/data', methods=['GET'])
@require_admin
def admin_data_index():
    """Lista las capas/textos editables con metadata."""
    out = []
    for key in EDITABLE_LAYERS:
        path = _layer_path(key)
        item = {
            'key':       key,
            'slug':      key.replace('_', '-'),
            'filename':  LAYER_FILES[key],
            'kind':      'tabular' if key in TABULAR_EDITABLE else 'document',
            'editable':  True,
        }
        try:
            st = os.stat(path)
            item['size_bytes'] = st.st_size
            item['modified']   = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
        except Exception:
            item['size_bytes'] = 0
            item['modified']   = None
        try:
            data = _load_layer_file(key)
            if isinstance(data, list):
                item['count'] = len(data)
            elif isinstance(data, dict):
                item['languages'] = sorted(list(data.keys()))
                item['count']     = sum(1 for _ in data.keys())
        except Exception:
            item['count'] = 0
        out.append(item)
    return jsonify({
        'items': out,
        'data_dir': DATA_DIR,
        'capa1a_locked': True,
        'capa1a_filename': LAYER_FILES['capa1a'],
    })

@app.route('/admin/data/<slug>', methods=['GET'])
@require_admin
def admin_data_get(slug):
    key = _normalize_layer_key(slug)
    if not key:
        return jsonify({'error': 'forbidden', 'message': 'No editable'}), 403
    return jsonify(_load_layer_file(key))

@app.route('/admin/data/<slug>', methods=['PUT'])
@require_admin
def admin_data_put(slug):
    key = _normalize_layer_key(slug)
    if not key:
        return jsonify({'error': 'forbidden', 'message': 'No editable'}), 403
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({'error': 'invalid_json', 'message': 'Cuerpo JSON requerido'}), 400
    err = _validate_layer_data(key, data)
    if err:
        return jsonify({'error': 'validation_failed', 'message': err}), 400
    backup = _make_layer_backup(key)
    path = _layer_path(key)
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        return jsonify({'error': 'persist_failed', 'message': str(e)}), 500
    _invalidate_layer_cache()
    _log(f'admin_data_put {key} by {_current_user()} backup={backup or "-"}')
    return jsonify({'ok': True, 'backup': backup or None})

@app.route('/admin/data/<slug>/restore-defaults', methods=['POST'])
@require_admin
def admin_data_restore(slug):
    key = _normalize_layer_key(slug)
    if not key:
        return jsonify({'error': 'forbidden', 'message': 'No editable'}), 403
    default_path = _layer_path(key, default=True)
    if not os.path.isfile(default_path):
        return jsonify({'error': 'default_not_found', 'message': 'No hay archivo .default.json para esta capa'}), 404
    backup = _make_layer_backup(key)
    try:
        shutil.copyfile(default_path, _layer_path(key))
    except Exception as e:
        return jsonify({'error': 'restore_failed', 'message': str(e)}), 500
    _invalidate_layer_cache()
    _log(f'admin_data_restore {key} by {_current_user()} backup={backup or "-"}')
    return jsonify({'ok': True, 'backup': backup or None})

@app.route('/admin/data/<slug>/backups', methods=['GET'])
@require_admin
def admin_data_backups(slug):
    key = _normalize_layer_key(slug)
    if not key:
        return jsonify({'error': 'forbidden', 'message': 'No editable'}), 403
    bdir = _layer_backup_dir(key)
    if not os.path.isdir(bdir):
        return jsonify({'items': []})
    items = []
    try:
        for fname in sorted(os.listdir(bdir), reverse=True):
            if not (fname.startswith(f'{key}.') and fname.endswith('.json')):
                continue
            full = os.path.join(bdir, fname)
            try:
                st = os.stat(full)
                items.append({
                    'filename':   fname,
                    'size_bytes': st.st_size,
                    'modified':   datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
                })
            except Exception:
                pass
    except Exception as e:
        log.warning(f'list backups failed: {e}')
    return jsonify({'items': items})

# Pagina HTML del editor
@app.route('/admin/data-editor', methods=['GET'])
def admin_data_editor_page():
    return send_from_directory(os.path.join(FRONTEND_DIR, 'admin'), 'data-editor.html')

@app.route('/admin/layers/info', methods=['GET'])
@require_auth
def admin_layers_info():
    ver = _dnsviz_version()
    raw = _load_layers()['raw']
    layer_counts = {}
    for key in ('capa1a', 'capa1b', 'capa2', 'capa3'):
        layer_counts[key] = len(raw.get(key) or [])
    docs = {}
    for key in ('ui_texts', 'report_texts'):
        d = raw.get(key) or {}
        if isinstance(d, dict):
            docs[key] = {'languages': sorted(list(d.keys()))}

    return jsonify({
        'dnsviz_version': ver,
        'last_updated':   _now_iso(),
        'data_dir':       DATA_DIR,
        'analyses_dir':   ANALYSES_DIR,
        'layer_counts':   layer_counts,
        'docs':           docs,
    })

# ─────────────────────────────────────────────
# ADMIN — LOGS
# ─────────────────────────────────────────────
@app.route('/admin/logs', methods=['GET'])
@require_admin
def admin_logs():
    db    = _db_load()
    limit = int(request.args.get('limit', 200))
    lines = [f"[{e['ts']}] {e['msg']}" for e in reversed(db.get('logs', []))]
    return jsonify({'lines': lines[:limit]})

# ─────────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────────
@app.route('/health', methods=['GET'])
def health():
    db = _db_load()
    return jsonify({
        'status':   'ok',
        'ts':       _now_iso(),
        'analyses': len(db['analyses']),
        'users':    len(db['users']),
        'dnsviz_runner': 'gcp_ssh_worker' if DNSVIZ_REMOTE else 'local',
        'dnsviz_worker': {
            'project': DNSVIZ_GCP_PROJECT,
            'zone': DNSVIZ_GCP_ZONE,
            'vm': DNSVIZ_GCP_VM,
        } if DNSVIZ_REMOTE else None,
        'phase2_database': {
            'configured': phase2_db.is_configured(),
            'status': 'configured' if phase2_db.is_configured() else 'not_configured',
        },
    })

@app.route('/admin/phase2/db/health', methods=['GET'])
@require_admin
def admin_phase2_db_health():
    return jsonify(phase2_db.check_schema())

@app.route('/lab/status', methods=['GET'])
@require_auth
def lab_status():
    db = _db_load()
    phase2 = phase2_db.check_schema()
    if _current_role() != 'admin':
        phase2 = {
            'configured': phase2.get('configured', False),
            'status': phase2.get('status', 'unknown'),
        }
    return jsonify({
        'status': 'ok',
        'ts': _now_iso(),
        'user': {
            'email': _current_user(),
            'role': _current_role(),
        },
        'phase1': {
            'public_graph_html': True,
            'public_downloads': ['graph.png', 'graph.svg'],
            'private_artifacts': ['result.json', 'probe.json', 'grok.json', 'print.txt', 'report.pdf', 'report.csv'],
        },
        'phase2_database': phase2,
        'dnsviz_worker': {
            'runner': 'gcp_ssh_worker' if DNSVIZ_REMOTE else 'local',
            'project': DNSVIZ_GCP_PROJECT if DNSVIZ_REMOTE else None,
            'zone': DNSVIZ_GCP_ZONE if DNSVIZ_REMOTE else None,
            'vm': DNSVIZ_GCP_VM if DNSVIZ_REMOTE else None,
        },
        'prototype': {
            'analyses_indexed': len(db.get('analyses', [])),
            'users_indexed': len(db.get('users', [])),
        },
        'modules': [
            {'code': 'bulk_100', 'status': 'planned', 'label': 'Bulk hasta 100 dominios'},
            {'code': 'normalization', 'status': 'available', 'label': 'Normalizacion y clasificacion de dominios'},
            {'code': 'structured_reports', 'status': 'planned', 'label': 'Reportes tecnicos y ejecutivos'},
            {'code': 'publications', 'status': 'planned', 'label': 'Publicacion controlada de informes'},
            {'code': 'abuse_controls', 'status': 'planned', 'label': 'Cuotas, auditoria y controles antiabuso'},
        ],
    })

@app.route('/lab/domains/normalize', methods=['POST'])
@require_auth
def lab_domains_normalize():
    data = request.json or {}
    raw_items = data.get('domains')
    if isinstance(raw_items, list):
        raw_items = [str(item).strip() for item in raw_items if str(item).strip()]
    else:
        raw_items = _split_lab_domain_lines(str(data.get('text') or ''))

    if not raw_items:
        return jsonify({'error': 'empty_input', 'message': 'No hay dominios para preparar'}), 400
    if len(raw_items) > LAB_PREPARATION_LIMIT:
        return jsonify({
            'error': 'too_many_domains',
            'message': f'La preparacion acepta hasta {LAB_PREPARATION_LIMIT} entradas por archivo o lote',
            'limit': LAB_PREPARATION_LIMIT,
            'received': len(raw_items),
        }), 400

    seen = {}
    items = []
    for index, raw in enumerate(raw_items, start=1):
        item = _normalize_lab_domain_input(raw)
        item['index'] = index
        _apply_lab_analysis_recommendation(item)
        key = item.get('normalized_domain') or ''
        if key and item['status'] != 'invalid':
            if key in seen:
                item['status'] = 'duplicate'
                item['warning'] = 'duplicate_domain'
                item['duplicate_of'] = seen[key]
                item['analysis_mode'] = 'exclude'
                item['analysis_recommendation'] = 'duplicate_exclude'
            else:
                seen[key] = index
        item['eligible_position'] = None
        item['analysis_candidate'] = False
        item['batch_number'] = None
        item['batch_position'] = None
        items.append(item)

    valid_items = [i for i in items if i['status'] in {'accepted', 'changed'}]
    analysis_domains = []
    analysis_seen = {}
    for item in valid_items:
        analysis_domain = item.get('analysis_domain') or item.get('normalized_domain')
        if not analysis_domain or item.get('analysis_mode') == 'exclude':
            continue
        if analysis_domain not in analysis_seen:
            analysis_seen[analysis_domain] = len(analysis_domains) + 1
            analysis_domains.append(analysis_domain)
        position = analysis_seen[analysis_domain]
        item['eligible_position'] = position
        item['analysis_candidate'] = position <= LAB_ANALYSIS_BATCH_LIMIT
        item['batch_number'] = ((position - 1) // LAB_ANALYSIS_BATCH_LIMIT) + 1
        item['batch_position'] = ((position - 1) % LAB_ANALYSIS_BATCH_LIMIT) + 1

    batch_count = ((len(analysis_domains) - 1) // LAB_ANALYSIS_BATCH_LIMIT) + 1 if analysis_domains else 0
    summary = {
        'received': len(raw_items),
        'valid': len(valid_items),
        'analysis_batch_limit': LAB_ANALYSIS_BATCH_LIMIT,
        'analysis_unique_domains': len(analysis_domains),
        'analysis_selected': min(len(analysis_domains), LAB_ANALYSIS_BATCH_LIMIT),
        'analysis_remaining': max(0, len(analysis_domains) - LAB_ANALYSIS_BATCH_LIMIT),
        'delegation_checks_used': 0,
        'delegation_check_limit': LAB_DELEGATION_CHECK_LIMIT,
        'batch_count': batch_count,
        'changed': sum(1 for i in items if i['status'] == 'changed'),
        'duplicates': sum(1 for i in items if i['status'] == 'duplicate'),
        'invalid': sum(1 for i in items if i['status'] == 'invalid'),
        'subdomains': sum(1 for i in valid_items if i.get('is_subdomain')),
        'delegated_subdomains': 0,
        'grouped_subdomains': 0,
        'subdomains_pending_review': sum(1 for i in valid_items if i.get('zone_kind') == 'subdomain_needs_review'),
        'by_tld_type': {},
        'by_public_suffix': {},
        'by_report_family': {},
        'by_generic_tld': {},
        'by_country_code_root': {},
        'by_country_code_group': {},
        'by_zone_kind': {},
        'by_analysis_recommendation': {},
        'batches': [
            {
                'number': number,
                'start': ((number - 1) * LAB_ANALYSIS_BATCH_LIMIT) + 1,
                'end': min(number * LAB_ANALYSIS_BATCH_LIMIT, len(analysis_domains)),
                'count': min(
                    LAB_ANALYSIS_BATCH_LIMIT,
                    max(0, len(analysis_domains) - ((number - 1) * LAB_ANALYSIS_BATCH_LIMIT)),
                ),
            }
            for number in range(1, batch_count + 1)
        ],
    }
    for item in valid_items:
        tld_type = item.get('tld_type') or 'unknown'
        public_suffix = item.get('public_suffix') or item.get('tld') or 'unknown'
        family = item.get('report_family') or 'unknown'
        report_group = item.get('report_group') or public_suffix
        zone_kind = item.get('zone_kind') or 'unknown'
        recommendation = item.get('analysis_recommendation') or 'unknown'
        summary['by_tld_type'][tld_type] = summary['by_tld_type'].get(tld_type, 0) + 1
        summary['by_public_suffix'][public_suffix] = summary['by_public_suffix'].get(public_suffix, 0) + 1
        summary['by_report_family'][family] = summary['by_report_family'].get(family, 0) + 1
        summary['by_zone_kind'][zone_kind] = summary['by_zone_kind'].get(zone_kind, 0) + 1
        summary['by_analysis_recommendation'][recommendation] = summary['by_analysis_recommendation'].get(recommendation, 0) + 1
        if family == 'generic':
            summary['by_generic_tld'][report_group] = summary['by_generic_tld'].get(report_group, 0) + 1
        elif family == 'country_code':
            root = item.get('registry_root') or item.get('tld') or 'unknown'
            summary['by_country_code_root'][root] = summary['by_country_code_root'].get(root, 0) + 1
            summary['by_country_code_group'][report_group] = summary['by_country_code_group'].get(report_group, 0) + 1

    return jsonify({
        'status': 'ok',
        'preparation_limit': LAB_PREPARATION_LIMIT,
        'analysis_batch_limit': LAB_ANALYSIS_BATCH_LIMIT,
        'limit': LAB_ANALYSIS_BATCH_LIMIT,
        'summary': summary,
        'items': items,
    })

# ─────────────────────────────────────────────
# ARRANQUE
# ─────────────────────────────────────────────
_bootstrap_runtime()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    log.info(f'Observatorio DNSSEC v2 — http://localhost:{port}')
    log.info(f'Frontend: {os.path.abspath(FRONTEND_DIR)}')
    app.run(host='0.0.0.0', port=port, debug=False)
