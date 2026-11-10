"""Local management API and a separate mTLS-only agent surface."""
import base64
from collections import defaultdict
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from cryptography.hazmat.primitives import serialization
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, StrictInt
import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from control.render import NODES, POLICY_PARAMETERS, render, validate_site
from control.rules import MAX_RULE_EXCLUSIONS, rule_catalog, rules_by_id, validate_rule_exclusions
from control.workflow import deployment_status, node_ready, snapshot_digest

app = FastAPI(title='WAF Control', docs_url=None, redoc_url=None, openapi_url=None)
agent_app = FastAPI(title='WAF Agents', docs_url=None, redoc_url=None, openapi_url=None)
passwords = PasswordHasher()
attempts = defaultdict(list)
login_lock = threading.Lock()
STATIC = Path(__file__).parent / 'static'
FIELDS = 'id,hostname,backend_ip,backend_port,mode,paranoia,enabled,excluded_rules,exception_reason,crs_settings'


def db():
    return psycopg.connect(os.environ['DATABASE_URL'], row_factory=dict_row, connect_timeout=5)


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def audit(conn, actor, action, detail):
    conn.execute('INSERT INTO audit_events(actor,action,detail) VALUES(%s,%s,%s)',
                 (actor, action, Jsonb(detail)))


def origin_check(request):
    origin = request.headers.get('origin')
    if origin:
        parsed = urlsplit(origin)
        if parsed.netloc != request.headers.get('host') or parsed.scheme not in {'http', 'https'}:
            raise HTTPException(403, 'Origin không hợp lệ')


def current_user(request: Request):
    origin_check(request)
    token = request.cookies.get('waf_session', '')
    if not token:
        raise HTTPException(401, 'Cần đăng nhập')
    with db() as conn:
        row = conn.execute('SELECT u.id,u.username,u.role,s.csrf FROM sessions s JOIN users u ON u.id=s.user_id '
                           'WHERE s.token_hash=%s AND s.expires_at>now() AND u.enabled', (sha(token),)).fetchone()
    if not row:
        raise HTTPException(401, 'Phiên đăng nhập hết hạn')
    if request.method not in {'GET', 'HEAD'} and not hmac.compare_digest(request.headers.get('x-csrf-token', ''), row['csrf']):
        raise HTTPException(403, 'CSRF token không hợp lệ')
    return row


def engineer(user=Depends(current_user)):
    if user['role'] not in {'admin', 'engineer'}:
        raise HTTPException(403, 'Cần quyền chỉnh sửa')
    return user


def admin(user=Depends(current_user)):
    if user['role'] != 'admin':
        raise HTTPException(403, 'Cần quyền quản trị')
    return user


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=200)


class Site(BaseModel):
    model_config = ConfigDict(extra='forbid')
    hostname: str = Field(max_length=253)
    backend_ip: str = Field(max_length=45)
    backend_port: int = Field(ge=1, le=65535)
    mode: str = 'DetectionOnly'
    paranoia: int = Field(default=1, ge=1, le=4)
    crs_settings: dict[str, StrictInt] = Field(default_factory=dict)
    enabled: bool = True
    excluded_rules: list[StrictInt] = Field(default_factory=list, max_length=MAX_RULE_EXCLUSIONS)
    exception_reason: str = Field(default='', max_length=500)


class Note(BaseModel):
    note: str = Field(min_length=3, max_length=500)
    draft_digest: str | None = Field(default=None, pattern=r'^[a-f0-9]{64}$')


class RuleSelection(BaseModel):
    model_config = ConfigDict(extra='forbid')
    excluded_rules: list[StrictInt] = Field(max_length=MAX_RULE_EXCLUSIONS)
    exception_reason: str = Field(max_length=500)
    expected_excluded_rules: list[StrictInt] = Field(max_length=MAX_RULE_EXCLUSIONS)
    expected_exception_reason: str = Field(max_length=500)


class UserInput(BaseModel):
    username: str = Field(pattern=r'^[a-zA-Z0-9_.-]{3,50}$')
    password: str = Field(min_length=12, max_length=200)
    role: str = Field(pattern=r'^(admin|engineer|viewer)$')


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=12, max_length=200)


class UserState(BaseModel):
    enabled: bool


@app.post('/api/login')
def login(data: Login, request: Request, response: Response):
    origin_check(request)
    key = request.client.host
    now = time.monotonic()
    with login_lock:
        attempts[key] = [x for x in attempts[key] if now - x < 300]
        if len(attempts[key]) >= 10:
            raise HTTPException(429, 'Thử lại sau vài phút')
        attempts[key].append(now)
    with db() as conn:
        user = conn.execute('SELECT * FROM users WHERE username=%s AND enabled', (data.username,)).fetchone()
        valid = False
        try:
            valid = user is not None and passwords.verify(user['password_hash'], data.password)
        except VerificationError:
            pass
        if not valid:
            raise HTTPException(401, 'Tài khoản hoặc mật khẩu không đúng')
        token, csrf = secrets.token_urlsafe(40), secrets.token_urlsafe(32)
        conn.execute('DELETE FROM sessions WHERE expires_at<now()')
        conn.execute("INSERT INTO sessions VALUES(%s,%s,%s,now()+interval '8 hours')", (sha(token), user['id'], csrf))
        audit(conn, user['username'], 'login', {})
    with login_lock:
        attempts.pop(key, None)
    response.set_cookie('waf_session', token, httponly=True, samesite='strict', max_age=28800,
                        secure=os.environ.get('COOKIE_SECURE') == 'true', path='/')
    return {'id': user['id'], 'username': user['username'], 'role': user['role'], 'csrf': csrf}


@app.get('/api/me')
def me(user=Depends(current_user)):
    return user


@app.post('/api/logout')
def logout(request: Request, response: Response, user=Depends(current_user)):
    with db() as conn:
        conn.execute('DELETE FROM sessions WHERE token_hash=%s', (sha(request.cookies.get('waf_session', '')),))
    response.delete_cookie('waf_session')
    return {'ok': True}


@app.get('/healthz')
def health():
    try:
        with db() as conn:
            conn.execute('SELECT 1')
        return {'status': 'ok'}
    except psycopg.Error:
        raise HTTPException(503, 'Database unavailable')


@app.get('/api/overview')
def overview(user=Depends(current_user)):
    with db() as conn:
        sites = conn.execute('SELECT ' + FIELDS + ' FROM sites ORDER BY id').fetchall()
        nodes = conn.execute("SELECT id,address,desired_revision,actual_revision,actual_digest,health,detail,last_seen,"
                             "(last_seen>now()-interval '30 seconds') AS online FROM nodes ORDER BY id").fetchall()
        revisions = conn.execute('SELECT id,note,created_at,validated,approved_at,digest,snapshot,configs '
                                 'FROM revisions ORDER BY id DESC LIMIT 30').fetchall()
        node_revisions = conn.execute('SELECT id,note,created_at,validated,approved_at,digest,snapshot,configs FROM revisions WHERE id=ANY(%s)',
                                      ([n['actual_revision'] for n in nodes if n['actual_revision']],)).fetchall()
        deployments = conn.execute('SELECT * FROM deployments ORDER BY id DESC LIMIT 20').fetchall()
        events = conn.execute('SELECT * FROM waf_events ORDER BY id DESC LIMIT 50').fetchall()
        audits = conn.execute('SELECT * FROM audit_events ORDER BY id DESC LIMIT 50').fetchall()
    known = {r['id']: r for r in node_revisions}
    known.update({r['id']: r for r in revisions})
    workflow = deployment_status(sites, nodes, list(known.values()), deployments)
    public_revisions = [{k: v for k, v in r.items() if k not in ('snapshot', 'configs')} for r in revisions]
    return {'sites': sites, 'nodes': nodes, 'revisions': public_revisions, 'deployments': deployments,
            'workflow': workflow,
            'events': events, 'audit': audits, 'server': os.environ.get('NODE_ID', 'controller'),
            'policy_parameters': POLICY_PARAMETERS}


@app.get('/api/history/{kind}')
def history(kind: str, q: str = Query(default='', max_length=200),
            outcome: str = Query(default='', pattern=r'^(|blocked|detected)$'),
            start: dt.datetime | None = None, end: dt.datetime | None = None,
            page: int = Query(default=1, ge=1), size: int = Query(default=25, ge=1, le=100),
            user=Depends(current_user)):
    if kind not in {'waf', 'audit'}:
        raise HTTPException(404, 'Loại nhật ký không hợp lệ')
    if any(value and value.utcoffset() is None for value in (start, end)):
        raise HTTPException(422, 'Thời gian cần có múi giờ')
    if start and end and start > end:
        raise HTTPException(422, 'Thời gian bắt đầu phải trước thời gian kết thúc')
    clauses, params = [], []
    if q.strip():
        # Literal substring search: %, _ and backslash are not wildcards.
        pattern = '%' + q.strip().replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
        fields = (['e.id::text', 'e.event_key', 'e.node_id', 'e.site_id::text', 's.hostname',
                   'e.client_ip', 'e.rule_ids::text', 'e.request_method', 'e.request_uri',
                   'e.request_host', 'e.request_protocol'] if kind == 'waf' else
                  ['e.id::text', 'e.actor', 'e.action', 'e.detail::text'])
        clauses.append('(' + ' OR '.join(field + ' ILIKE %s' for field in fields) + ')')
        params.extend([pattern] * len(fields))
    if outcome and kind == 'waf':
        clauses.append('e.interrupted=%s')
        params.append(outcome == 'blocked')
    for value, operator in ((start, '>='), (end, '<=')):
        if value:
            clauses.append('e.created_at' + operator + '%s')
            params.append(value)
    source = ('waf_events e LEFT JOIN sites s ON s.id=e.site_id' if kind == 'waf' else 'audit_events e')
    where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
    with db() as conn:
        # Keep count and page consistent when agents insert new events.
        conn.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        total = conn.execute('SELECT count(*) AS total FROM ' + source + where, params).fetchone()['total']
        pages = max(1, (total + size - 1) // size)
        page = min(page, pages)
        columns = 'e.*,s.hostname' if kind == 'waf' else 'e.*'
        items = conn.execute('SELECT ' + columns + ' FROM ' + source + where +
                             ' ORDER BY e.id DESC LIMIT %s OFFSET %s',
                             [*params, size, (page - 1) * size]).fetchall()
    return {'items': items, 'total': total, 'page': page, 'pages': pages, 'size': size}


def site_values(data):
    try:
        values = validate_site(data.model_dump(), os.environ['BACKEND_ALLOWLIST'].split(','))
    except ValueError as e:
        raise HTTPException(422, str(e))
    return values


@app.get('/api/rules')
def list_rules(user=Depends(current_user)):
    catalog = rule_catalog()
    return {'version': catalog['version'], 'source_sha256': catalog['source_sha256'],
            'rules': [{key: value for key, value in rule.items() if key != 'source'}
                      for rule in catalog['rules']]}


@app.get('/api/rules/{rule_id}')
def get_rule(rule_id: int, user=Depends(current_user)):
    rule = rules_by_id().get(rule_id)
    if rule is None:
        raise HTTPException(404, 'Không có rule trong danh mục CRS hiện tại')
    return {'version': rule_catalog()['version'], **rule}


@app.patch('/api/sites/{site_id}/rules')
def update_rules(site_id: int, data: RuleSelection, user=Depends(engineer)):
    try:
        excluded = validate_rule_exclusions(data.excluded_rules, data.exception_reason)
    except ValueError as error:
        raise HTTPException(422, str(error))
    with db() as conn:
        site = conn.execute('SELECT excluded_rules,exception_reason FROM sites WHERE id=%s FOR UPDATE',
                            (site_id,)).fetchone()
        if not site:
            raise HTTPException(404, 'Không có site')
        if (sorted(set(site['excluded_rules'])) != sorted(set(data.expected_excluded_rules)) or
                site['exception_reason'] != data.expected_exception_reason):
            raise HTTPException(409, 'Rule của website đã thay đổi. Tải lại danh sách trước khi lưu.')
        conn.execute('UPDATE sites SET excluded_rules=%s,exception_reason=%s,updated_at=now() WHERE id=%s',
                     (Jsonb(excluded), data.exception_reason, site_id))
        audit(conn, user['username'], 'site.update_rules_draft',
              {'id': site_id, 'before': site['excluded_rules'], 'excluded_rules': excluded,
               'exception_reason': data.exception_reason, 'crs_version': rule_catalog()['version']})
    return {'ok': True, 'excluded_rules': excluded, 'exception_reason': data.exception_reason,
            'message': 'Đã lưu rule vào bản nháp; tạo phiên bản để triển khai.'}


@app.post('/api/sites')
def create_site(data: Site, user=Depends(engineer)):
    s = site_values(data)
    with db() as conn:
        try:
            row = conn.execute('INSERT INTO sites(hostname,backend_ip,backend_port,mode,paranoia,enabled,excluded_rules,exception_reason,crs_settings) '
                               'VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id',
                               (s['hostname'], s['backend_ip'], s['backend_port'], s['mode'], s['paranoia'],
                                s['enabled'], Jsonb(s['excluded_rules']), s['exception_reason'], Jsonb(s['crs_settings']))).fetchone()
        except psycopg.errors.UniqueViolation:
            raise HTTPException(409, 'Tên miền đã tồn tại')
        audit(conn, user['username'], 'site.create', {'id': row['id'], 'hostname': s['hostname'],
                                                   'paranoia': s['paranoia'], 'crs_settings': s['crs_settings']})
    return row


@app.put('/api/sites/{site_id}')
def update_site(site_id: int, data: Site, user=Depends(engineer)):
    s = site_values(data)
    with db() as conn:
        try:
            row = conn.execute('UPDATE sites SET hostname=%s,backend_ip=%s,backend_port=%s,mode=%s,paranoia=%s,enabled=%s,'
                               'excluded_rules=%s,exception_reason=%s,crs_settings=%s,updated_at=now() WHERE id=%s RETURNING id',
                               (s['hostname'], s['backend_ip'], s['backend_port'], s['mode'], s['paranoia'], s['enabled'],
                                Jsonb(s['excluded_rules']), s['exception_reason'], Jsonb(s['crs_settings']), site_id)).fetchone()
        except psycopg.errors.UniqueViolation:
            raise HTTPException(409, 'Tên miền đã tồn tại')
        if not row:
            raise HTTPException(404, 'Không có site')
        audit(conn, user['username'], 'site.update_draft', {'id': site_id, 'mode': s['mode'], 'hostname': s['hostname'],
                                                        'paranoia': s['paranoia'], 'crs_settings': s['crs_settings']})
    return {'ok': True, 'message': 'Đã lưu nháp; chưa thay đổi WAF'}


def validate_configs(configs):
    with tempfile.TemporaryDirectory(prefix='validate-') as tmp:
        for node, config in configs.items():
            # Validate syntax and CRS without needing production private keys.
            import re
            candidate = re.sub(r'    tls /etc/caddy/tls/[^\n]+', '    tls internal', config)
            candidate = candidate.replace('/var/log/caddy/', tmp + '/').replace('/var/log/coraza/', tmp + '/')
            path = Path(tmp) / 'Caddyfile'
            path.write_text(candidate)
            result = subprocess.run(['/usr/local/bin/caddy', 'validate', '--config', str(path), '--adapter', 'caddyfile'],
                                    cwd=tmp, capture_output=True, text=True, timeout=45)
            if result.returncode:
                raise HTTPException(422, 'Caddy/Coraza validation failed for ' + node + ': ' + result.stderr[-1500:])


@app.post('/api/revisions')
def revision(data: Note, user=Depends(engineer)):
    with db() as conn:
        sites = conn.execute('SELECT ' + FIELDS + ' FROM sites ORDER BY id').fetchall()
        if data.draft_digest and data.draft_digest != snapshot_digest(sites):
            raise HTTPException(409, 'Bản nháp đã thay đổi. Đóng hộp thoại và kiểm tra lại cấu hình mới nhất.')
        if not any(s['enabled'] for s in sites):
            raise HTTPException(422, 'Cần ít nhất một site hoạt động')
        for s in sites:
            validate_site(s, os.environ['BACKEND_ALLOWLIST'].split(','))
        # Reserve ID in this transaction; failed validation leaves no publishable revision.
        rid = conn.execute("SELECT nextval(pg_get_serial_sequence('revisions','id')) AS id").fetchone()['id']
        configs = {node: render(node, sites, str(rid)) for node in NODES}
        validate_configs(configs)
        digest = hashlib.sha256(canonical(configs)).hexdigest()
        conn.execute('INSERT INTO revisions(id,snapshot,configs,note,created_by,validated,digest) VALUES(%s,%s,%s,%s,%s,true,%s)',
                     (rid, Jsonb(sites), Jsonb(configs), data.note, user['id'], digest))
        audit(conn, user['username'], 'revision.validate', {'id': rid, 'digest': digest})
    return {'id': rid, 'validated': True, 'digest': digest}


@app.get('/api/revisions/{rid}')
def get_revision(rid: int, user=Depends(current_user)):
    with db() as conn:
        row = conn.execute('SELECT id,snapshot,configs,note,digest FROM revisions WHERE id=%s', (rid,)).fetchone()
    if not row:
        raise HTTPException(404, 'Không có revision')
    return row


@app.post('/api/revisions/{rid}/approve')
def approve(rid: int, user=Depends(admin)):
    with db() as conn:
        row = conn.execute('UPDATE revisions SET approved_by=%s,approved_at=now() WHERE id=%s AND validated RETURNING id',
                           (user['id'], rid)).fetchone()
        if not row:
            raise HTTPException(404, 'Phiên bản chưa được kiểm tra hoặc không tồn tại')
        audit(conn, user['username'], 'revision.approve', {'id': rid})
    return {'ok': True}


def begin_deployment(conn, rid, user, kind):
    conn.execute('SELECT pg_advisory_xact_lock(11810778209)')
    r = conn.execute('SELECT id FROM revisions WHERE id=%s AND approved_at IS NOT NULL AND validated', (rid,)).fetchone()
    if not r:
        raise HTTPException(409, 'Cần kiểm tra và phê duyệt phiên bản trước')
    if conn.execute("SELECT 1 FROM deployments WHERE state IN ('canary','rollout')").fetchone():
        raise HTTPException(409, 'Có deployment đang chạy; hoàn tất hoặc hủy trước')
    row = conn.execute('INSERT INTO deployments(revision_id,created_by,kind) VALUES(%s,%s,%s) RETURNING id',
                       (rid, user['id'], kind)).fetchone()
    conn.execute("UPDATE nodes SET desired_revision=%s,generation=generation+1 WHERE id='waf-cluster-1'", (rid,))
    audit(conn, user['username'], 'deployment.' + kind, {'id': row['id'], 'revision': rid})
    return row


@app.post('/api/revisions/{rid}/deploy')
def deploy(rid: int, user=Depends(admin)):
    with db() as conn:
        return begin_deployment(conn, rid, user, 'deploy')


@app.post('/api/revisions/{rid}/rollback')
def rollback(rid: int, user=Depends(admin)):
    with db() as conn:
        return begin_deployment(conn, rid, user, 'rollback')


@app.post('/api/deployments/{did}/promote')
def promote(did: int, user=Depends(admin)):
    with db() as conn:
        conn.execute('SELECT pg_advisory_xact_lock(11810778209)')
        d = conn.execute("SELECT * FROM deployments WHERE id=%s AND state='canary' FOR UPDATE", (did,)).fetchone()
        if not d:
            raise HTTPException(409, 'Không có lần triển khai thăm dò đang chờ')
        revision = conn.execute('SELECT id,configs FROM revisions WHERE id=%s', (d['revision_id'],)).fetchone()
        node = conn.execute("SELECT *, (last_seen>now()-interval '30 seconds') AS online "
                            "FROM nodes WHERE id='waf-cluster-1'").fetchone()
        if not node or not node_ready(node, revision):
            raise HTTPException(409, 'Node 1 chưa hoạt động ổn định với đúng phiên bản thăm dò')
        conn.execute("UPDATE nodes SET desired_revision=%s,generation=generation+1 WHERE id='waf-cluster-2'", (d['revision_id'],))
        conn.execute("UPDATE deployments SET state='rollout' WHERE id=%s", (did,))
        audit(conn, user['username'], 'deployment.promote', {'id': did})
    return {'ok': True}


@app.post('/api/deployments/{did}/abort')
def abort(did: int, user=Depends(admin)):
    with db() as conn:
        conn.execute('SELECT pg_advisory_xact_lock(11810778209)')
        conn.execute("UPDATE deployments SET state='aborted' WHERE id=%s AND state IN ('canary','rollout')", (did,))
        conn.execute('UPDATE nodes SET desired_revision=actual_revision,generation=generation+1 WHERE desired_revision IS DISTINCT FROM actual_revision')
        audit(conn, user['username'], 'deployment.abort', {'id': did})
    return {'ok': True, 'message': 'Đã dừng triển khai. Chọn phiên bản cũ để khôi phục các node đã áp dụng.'}


@app.get('/api/users')
def list_users(user=Depends(admin)):
    with db() as conn:
        return conn.execute('SELECT id,username,role,enabled FROM users ORDER BY id').fetchall()


@app.post('/api/users')
def add_user(data: UserInput, user=Depends(admin)):
    with db() as conn:
        try:
            row = conn.execute('INSERT INTO users(username,password_hash,role) VALUES(%s,%s,%s) RETURNING id',
                               (data.username, passwords.hash(data.password), data.role)).fetchone()
        except psycopg.errors.UniqueViolation:
            raise HTTPException(409, 'Tài khoản đã tồn tại')
        audit(conn, user['username'], 'user.create', {'username': data.username, 'role': data.role})
    return row


@app.patch('/api/users/{uid}')
def user_state(uid: int, data: UserState, user=Depends(admin)):
    if uid == user['id'] and not data.enabled:
        raise HTTPException(409, 'Không thể tự vô hiệu hóa tài khoản đang dùng')
    with db() as conn:
        row = conn.execute('UPDATE users SET enabled=%s WHERE id=%s RETURNING id', (data.enabled, uid)).fetchone()
        if not row:
            raise HTTPException(404, 'Không có tài khoản')
        if not data.enabled:
            conn.execute('DELETE FROM sessions WHERE user_id=%s', (uid,))
        audit(conn, user['username'], 'user.enable' if data.enabled else 'user.disable', {'id': uid})
    return {'ok': True}


@app.post('/api/password')
def change_password(data: PasswordChange, user=Depends(current_user)):
    with db() as conn:
        old = conn.execute('SELECT password_hash FROM users WHERE id=%s', (user['id'],)).fetchone()
        try:
            passwords.verify(old['password_hash'], data.current_password)
        except VerificationError:
            raise HTTPException(403, 'Mật khẩu hiện tại không đúng')
        conn.execute('UPDATE users SET password_hash=%s WHERE id=%s', (passwords.hash(data.password), user['id']))
        conn.execute('DELETE FROM sessions WHERE user_id=%s', (user['id'],))
        audit(conn, user['username'], 'password.change', {})
    return {'ok': True}


def node_identity(request: Request):
    supplied = request.headers.get('authorization', '')
    if not supplied.startswith('Bearer '):
        raise HTTPException(401, 'Agent identity required')
    with db() as conn:
        node = conn.execute('SELECT * FROM nodes WHERE token_hash=%s', (sha(supplied[7:]),)).fetchone()
    if not node:
        raise HTTPException(401, 'Unknown agent')
    return node


@agent_app.get('/agent/desired')
def desired(node=Depends(node_identity)):
    if not node['desired_revision']:
        return {'manifest': None}
    with db() as conn:
        row = conn.execute('SELECT id,configs FROM revisions WHERE id=%s AND approved_at IS NOT NULL', (node['desired_revision'],)).fetchone()
    if not row:
        raise HTTPException(409, 'No approved desired revision')
    config = row['configs'][node['id']]
    payload = {'node_id': node['id'], 'revision': row['id'], 'generation': node['generation'],
               'config': config, 'sha256': sha(config)}
    key = serialization.load_pem_private_key(Path(os.environ['SIGNING_KEY']).read_bytes(), None)
    return {'manifest': payload, 'signature': base64.b64encode(key.sign(canonical(payload))).decode()}


class WafEvent(BaseModel):
    event_key: str = Field(max_length=180)
    site_id: int
    client_ip: str = Field(max_length=45)
    rule_ids: list[int] = Field(max_length=100)
    interrupted: bool
    request_method: str = Field(default='', max_length=32)
    request_uri: str = Field(default='', max_length=16384)
    request_host: str = Field(default='', max_length=512)
    request_protocol: str = Field(default='', max_length=32)


class Heartbeat(BaseModel):
    revision: int | None = None
    digest: str = Field(default='', max_length=64)
    health: str = Field(pattern=r'^(healthy|error|drift|starting)$')
    detail: str = Field(default='', max_length=600)
    events: list[WafEvent] = Field(default_factory=list, max_length=100)


@agent_app.post('/agent/heartbeat')
def heartbeat(data: Heartbeat, node=Depends(node_identity)):
    with db() as conn:
        # Serialize lifecycle transitions with deploy/promote/abort and other agents.
        conn.execute('SELECT pg_advisory_xact_lock(11810778209)')
        conn.execute('UPDATE nodes SET actual_revision=%s,actual_digest=%s,health=%s,detail=%s,last_seen=now() WHERE id=%s',
                     (data.revision, data.digest, data.health, data.detail, node['id']))
        for event in data.events:
            try:
                client_ip = str(ipaddress.ip_address(event.client_ip))
            except ValueError:
                client_ip = ''
            conn.execute('INSERT INTO waf_events(event_key,node_id,site_id,client_ip,rule_ids,interrupted,'
                         'request_method,request_uri,request_host,request_protocol) '
                         'VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(event_key) DO NOTHING',
                         (node['id'] + ':' + event.event_key, node['id'], event.site_id, client_ip,
                          Jsonb(event.rule_ids), event.interrupted, event.request_method,
                          event.request_uri, event.request_host, event.request_protocol))
        advance_deployment(conn)
    return {'ok': True}


def advance_deployment(conn):
    active = conn.execute("SELECT * FROM deployments WHERE state IN ('canary','rollout') FOR UPDATE").fetchone()
    if not active:
        return
    revision = conn.execute('SELECT id,configs FROM revisions WHERE id=%s', (active['revision_id'],)).fetchone()
    nodes = conn.execute("SELECT *, (last_seen>now()-interval '30 seconds') AS online FROM nodes ORDER BY id").fetchall()
    by_id = {n['id']: n for n in nodes}
    if active['state'] == 'canary':
        node = by_id.get('waf-cluster-1')
        if not node or not node_ready(node, revision):
            return
        conn.execute("UPDATE nodes SET desired_revision=%s,generation=generation+1 WHERE id='waf-cluster-2'", (revision['id'],))
        conn.execute("UPDATE deployments SET state='rollout' WHERE id=%s", (active['id'],))
        audit(conn, 'controller', 'deployment.auto_promote', {'id': active['id'], 'revision': revision['id']})
        # Wait for a new heartbeat from node 2 after its desired revision changes.
        return
    if all(node_id in by_id and node_ready(by_id[node_id], revision) for node_id in NODES):
        conn.execute("UPDATE deployments SET state='complete',completed_at=now() WHERE id=%s", (active['id'],))
        audit(conn, 'controller', 'deployment.complete', {'id': active['id']})


@app.middleware('http')
async def headers(request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'"
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.get('/')
def index():
    return FileResponse(STATIC / 'index.html')


app.mount('/static', StaticFiles(directory=str(STATIC)), name='static')


async def database_unavailable(request, exc):
    return JSONResponse(status_code=503, content={'detail': 'PostgreSQL chưa sẵn sàng; WAF tiếp tục dùng cấu hình hiện tại'})


app.add_exception_handler(psycopg.Error, database_unavailable)
agent_app.add_exception_handler(psycopg.Error, database_unavailable)
