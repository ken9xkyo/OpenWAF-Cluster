#!/usr/bin/env python3
"""Initial POC control-plane secrets, internal PKI, database and seed revision.

Run with the control venv on node 1. Prints no passwords or private keys.
"""
import datetime as dt
import grp
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import secrets
import subprocess
import sys

from argon2 import PasswordHasher
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from control.render import NODES, render


def command(argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, text=True, **kwargs)


def file(path, content, mode=0o600, owner='root', group=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content.encode() if isinstance(content, str) else content)
    uid = pwd.getpwnam(owner).pw_uid
    gid = grp.getgrnam(group or owner).gr_gid
    os.chown(path, uid, gid)
    path.chmod(mode)


ROOT = Path('/etc/waf-control')
ROOT.mkdir(mode=0o750, exist_ok=True)
if subprocess.run(['getent', 'passwd', 'waf-control'], stdout=subprocess.DEVNULL).returncode != 0:
    command(['useradd', '--system', '--user-group', '--home-dir', '/var/lib/waf-control', '--shell', '/usr/sbin/nologin', 'waf-control'])
os.chown(ROOT, 0, grp.getgrnam('waf-control').gr_gid)
ROOT.chmod(0o750)
for directory in ['/var/lib/waf-control', '/var/lib/waf-agent']:
    command(['install', '-d', '-m', '0750', '-o', 'waf-control' if 'control' in directory else 'caddy',
             '-g', 'waf-control' if 'control' in directory else 'caddy', directory])
secrets_path = ROOT / 'bootstrap.json'
if secrets_path.exists():
    values = json.loads(secrets_path.read_text())
else:
    values = {'database_password': secrets.token_urlsafe(36), 'admin_password': secrets.token_urlsafe(24),
              'agent_tokens': {node: secrets.token_urlsafe(40) for node in NODES}}
    file(secrets_path, json.dumps(values))
PKI = ROOT / 'pki'
PKI.mkdir(mode=0o750, exist_ok=True)
os.chown(PKI, 0, grp.getgrnam('waf-control').gr_gid)
now = dt.datetime.now(dt.timezone.utc)
if (PKI / 'ca.key').exists():
    ca_key = serialization.load_pem_private_key((PKI / 'ca.key').read_bytes(), None)
    ca_cert = x509.load_pem_x509_certificate((PKI / 'ca.crt').read_bytes())
else:
    ca_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'OpenWAF POC Internal CA')])
    ca_cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(minutes=5))
               .not_valid_after(now+dt.timedelta(days=1825)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
               .sign(ca_key, hashes.SHA256()))
    file(PKI / 'ca.key', ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    file(PKI / 'ca.crt', ca_cert.public_bytes(serialization.Encoding.PEM), 0o644)


def certificate(name, ip, client=False):
    cert_path, key_path = PKI / (name+'.crt'), PKI / (name+'.key')
    if cert_path.exists():
        return
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(now+dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name), x509.IPAddress(ipaddress.ip_address(ip))]), False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .sign(ca_key, hashes.SHA256()))
    file(cert_path, cert.public_bytes(serialization.Encoding.PEM), 0o644)
    file(key_path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


for node, ip in NODES.items():
    certificate(node+'-api', ip)
    certificate(node+'-agent', ip, client=True)
certificate('waf-postgresql', '192.168.11.100')
signing = ROOT / 'release-signing.key'
if not signing.exists():
    key = ed25519.Ed25519PrivateKey.generate()
    file(signing, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), 0o400, 'waf-control')
    file(ROOT/'release-signing.pub', key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo), 0o644)

postgres_dir = Path('/etc/postgresql/16/main')
file(postgres_dir/'server.crt', (PKI/'waf-postgresql.crt').read_bytes(), 0o644, 'postgres')
file(postgres_dir/'server.key', (PKI/'waf-postgresql.key').read_bytes(), 0o600, 'postgres')
file(postgres_dir/'conf.d/waf-poc.conf', "listen_addresses='127.0.0.1,192.168.11.100'\nssl=on\nssl_cert_file='/etc/postgresql/16/main/server.crt'\nssl_key_file='/etc/postgresql/16/main/server.key'\npassword_encryption='scram-sha-256'\nmax_connections=60\nshared_buffers='128MB'\n", 0o644)
file(postgres_dir/'pg_hba.conf', 'local all postgres peer\nlocal all all peer\nhostssl wafcontrol wafapp 192.168.11.100/32 scram-sha-256\nhostssl wafcontrol wafapp 192.168.11.202/32 scram-sha-256\n', 0o640, 'postgres')
command(['systemctl', 'restart', 'postgresql@16-main'])
role_exists = command(['runuser', '-u', 'postgres', '--', 'psql', '-tAc', "SELECT 1 FROM pg_roles WHERE rolname='wafapp'"]).stdout.strip()
if not role_exists:
    statement = sql.SQL('CREATE ROLE wafapp LOGIN PASSWORD {} CONNECTION LIMIT 40').format(sql.Literal(values['database_password'])).as_string()
    command(['runuser', '-u', 'postgres', '--', 'psql', '-v', 'ON_ERROR_STOP=1'], input=statement)
db_exists = command(['runuser', '-u', 'postgres', '--', 'psql', '-tAc', "SELECT 1 FROM pg_database WHERE datname='wafcontrol'"]).stdout.strip()
if not db_exists:
    command(['runuser', '-u', 'postgres', '--', 'createdb', 'wafcontrol'])
schema = (Path(__file__).resolve().parents[1]/'control/schema.sql').read_text()
schema += '\nGRANT CONNECT ON DATABASE wafcontrol TO wafapp; GRANT USAGE ON SCHEMA public TO wafapp;\n'
schema += 'GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO wafapp;\n'
schema += 'GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO wafapp;\n'
schema += 'REVOKE UPDATE,DELETE,TRUNCATE ON audit_events FROM wafapp;\n'
schema += 'REVOKE CREATE ON SCHEMA public FROM PUBLIC;\n'
command(['runuser', '-u', 'postgres', '--', 'psql', '-d', 'wafcontrol', '-v', 'ON_ERROR_STOP=1'], input=schema)
dsn = f"host=192.168.11.100 port=5432 dbname=wafcontrol user=wafapp password={values['database_password']} sslmode=verify-full sslrootcert=/etc/waf-control/pki/ca.crt"
with psycopg.connect(dsn) as conn:
    if not conn.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
        conn.execute("INSERT INTO users(username,password_hash,role) VALUES('admin',%s,'admin')", (PasswordHasher().hash(values['admin_password']),))
        file('/root/waf-poc-admin.txt', 'URL qua SSH tunnel: http://127.0.0.1:9000\nUsername: admin\nPassword: '+values['admin_password']+'\n')
    if not conn.execute('SELECT 1 FROM sites LIMIT 1').fetchone():
        conn.execute("INSERT INTO sites(hostname,backend_ip,backend_port) VALUES('test-waf.vtccloud.vn','118.107.78.220',3000)")
    for node, ip in NODES.items():
        token_hash = hashlib.sha256(values['agent_tokens'][node].encode()).hexdigest()
        conn.execute('INSERT INTO nodes(id,address,token_hash) VALUES(%s,%s,%s) ON CONFLICT(id) DO UPDATE SET token_hash=excluded.token_hash', (node, ip, token_hash))
    if not conn.execute('SELECT 1 FROM revisions LIMIT 1').fetchone():
        from psycopg.rows import dict_row
        conn.row_factory = dict_row
        sites = conn.execute('SELECT id,hostname,backend_ip,backend_port,mode,paranoia,enabled,excluded_rules,exception_reason FROM sites ORDER BY id').fetchall()
        rid = conn.execute("SELECT nextval(pg_get_serial_sequence('revisions','id')) AS id").fetchone()['id']
        configs = {node: render(node, sites, str(rid)) for node in NODES}
        digest = hashlib.sha256(json.dumps(configs, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        conn.execute("INSERT INTO revisions(id,snapshot,configs,note,created_by,validated,approved_by,approved_at,digest) "
                     "VALUES(%s,%s,%s,'Initial two-node POC',1,true,1,now(),%s)", (rid, Jsonb(sites), Jsonb(configs), digest))
        conn.execute('UPDATE nodes SET desired_revision=%s,generation=1', (rid,))
        conn.execute("INSERT INTO audit_events(actor,action,detail) VALUES('bootstrap','initialize',%s)", (Jsonb({'revision':rid}),))

for node, ip in NODES.items():
    directory = ROOT/'deploy'/node
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    env = 'DATABASE_URL="'+dsn+'"\nSIGNING_KEY=/etc/waf-control/release-signing.key\nBACKEND_ALLOWLIST=118.107.78.220/32\nNODE_ID='+node+'\nXDG_DATA_HOME=/var/lib/waf-control\nXDG_CONFIG_HOME=/var/lib/waf-control\n'
    file(directory/'control.env', env)
    agent = {'node_id':node, 'address':ip, 'hostname':'test-waf.vtccloud.vn',
             'controllers':['https://192.168.11.100:9443','https://192.168.11.202:9443'],
             'token':values['agent_tokens'][node], 'ca':'/etc/waf-agent/pki/ca.crt',
             'certificate':'/etc/waf-agent/pki/agent.crt','key':'/etc/waf-agent/pki/agent.key',
             'signing_public_key':'/etc/waf-agent/signing.pub'}
    file(directory/'agent.json', json.dumps(agent, indent=2))
    for src,dest in [(PKI/'ca.crt','ca.crt'),(PKI/(node+'-api.crt'),'server.crt'),(PKI/(node+'-api.key'),'server.key'),
                     (PKI/(node+'-agent.crt'),'agent.crt'),(PKI/(node+'-agent.key'),'agent.key'),
                     (ROOT/'release-signing.key','signing.key'),(ROOT/'release-signing.pub','signing.pub')]:
        file(directory/dest, src.read_bytes())
print('Control database, internal PKI and seed revision ready; credentials stored in /root/waf-poc-admin.txt')
