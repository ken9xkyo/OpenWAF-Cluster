#!/usr/bin/env python3
"""Remove the explicitly retired BunkerWeb stack, preserving HAProxy/VRRP.

Destructive: deletes BunkerWeb configuration, database volumes and logs.
No backups are created. Intended only for the two authorized POC nodes.
"""
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess


def run(args, required=True):
    print('+', shlex.join(args), flush=True)
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if required and result.returncode:
        print(result.stdout, flush=True)
        result.check_returncode()
    return result


def remove(path):
    p = Path(path)
    if p.is_symlink() or p.is_file():
        p.unlink()
    elif p.is_dir():
        shutil.rmtree(p)


def main():
    assert os.geteuid() == 0
    host = subprocess.check_output(['hostname'], text=True).strip()
    assert host in {'waf-cluster-1', 'waf-cluster-2'}, host
    node = '192.168.11.100' if host == 'waf-cluster-1' else '192.168.11.202'

    # Decouple live VRRP and its firewall from the retired stack first.
    check = Path('/usr/local/sbin/bw-check-haproxy')
    target = Path('/usr/local/sbin/waf-check-haproxy')
    if check.exists():
        target.write_text(check.read_text())
        target.chmod(0o755)
    firewall = Path('/usr/local/sbin/bw-lb-firewall')
    target = Path('/usr/local/sbin/waf-poc-firewall')
    if firewall.exists():
        target.write_text(firewall.read_text().replace('BW-', 'WAF-'))
        target.chmod(0o755)
    for binary in ['iptables', 'ip6tables']:
        for old in ['BW-LB-PRIVATE', 'BW-LB-RUNTIME', 'BW-VRRP']:
            exists = subprocess.run([binary, '-w', '-S', old], capture_output=True).returncode == 0
            if exists:
                run([binary, '-w', '-E', old, old.replace('BW-', 'WAF-')])
    unit = Path('/etc/systemd/system/waf-poc-firewall.service')
    unit.write_text('[Unit]\nDescription=WAF POC private listener and VRRP firewall\n'
                    'Wants=network-online.target\nAfter=network-online.target docker.service\n'
                    'Before=haproxy.service keepalived.service\n[Service]\nType=oneshot\n'
                    'RemainAfterExit=yes\nExecStart=/usr/local/sbin/waf-poc-firewall ' + node +
                    '\n[Install]\nWantedBy=multi-user.target\n')
    dropin = Path('/etc/systemd/system/keepalived.service.d')
    dropin.mkdir(exist_ok=True)
    (dropin/'waf.conf').write_text('[Unit]\nWants=haproxy.service waf-poc-firewall.service\n'
                                 'After=haproxy.service waf-poc-firewall.service\n')
    remove(dropin/'bunkerweb.conf')
    config = Path('/etc/keepalived/keepalived.conf')
    content = (config.read_text().replace('/usr/local/sbin/bw-check-haproxy',
                                                '/usr/local/sbin/waf-check-haproxy')
                      .replace('BW_LB_', 'WAF_LB_').replace('BW_PUBLIC_VIP', 'WAF_PUBLIC_VIP')
                      .replace('ens3:bwvip', 'ens3:wafvip'))
    # ens8 is already tracked as the VRRP interface; listing it again causes
    # Keepalived's config check to report a warning (exit code 5).
    content = re.sub(r'(track_interface\s*\{)([^}]*)(\})',
                     lambda m: m[1] + re.sub(r'^\s*ens8\s*$', '', m[2], flags=re.M) + m[3], content)
    config.write_text(content)
    run(['keepalived', '-t', '-f', str(config)])
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', 'waf-poc-firewall.service'])
    run(['systemctl', 'reload', 'keepalived'])

    units = ['bw-haproxy-manager', 'bw-inspection-sidecars', 'bw-admin-ports-firewall',
             'bw-control-firewall', 'bw-lb-firewall', 'bunkerweb-api',
             'bunkerweb-scheduler', 'bunkerweb-ui', 'bunkerweb']
    for name in units:
        run(['systemctl', 'disable', '--now', name + '.service'], required=False)

    projects = {'bunkerweb-inspection', 'bunkerweb-manager', 'bw-haproxy-manager'}
    for project in sorted(projects):
        ids = subprocess.check_output(['docker', 'ps', '-aq', '--filter',
                                       'label=com.docker.compose.project=' + project], text=True).split()
        if ids:
            run(['docker', 'rm', '-f', *ids])
        for kind in ['network', 'volume']:
            names = subprocess.check_output(['docker', kind, 'ls', '-q', '--filter',
                                             'label=com.docker.compose.project=' + project], text=True).split()
            if names:
                run(['docker', kind, 'rm', *names])
    images = subprocess.check_output(['docker', 'image', 'ls', '--format', '{{.Repository}}\t{{.ID}}'], text=True).splitlines()
    for image in images:
        repository, image_id = image.split('\t')
        if repository.startswith('bunkerity/') or repository in {'bunkerweb-coraza-local', 'bw-haproxy-manager', 'clamav/clamav'}:
            run(['docker', 'image', 'rm', image_id], required=False)

    # Explicit packages only; no autoremove of potentially shared dependencies.
    result = run(['apt-get', '-y', '--allow-change-held-packages', 'purge', 'bunkerweb', 'nginx'])
    print(result.stdout, flush=True)
    for binary in ['iptables', 'ip6tables']:
        for chain in ['BW-CONTROL', 'BW-ADMIN-PORTS']:
            rows = subprocess.check_output([binary, '-w', '-S'], text=True).splitlines()
            for line in rows:
                args = shlex.split(line)
                if args[:1] == ['-A'] and '-j' in args and args[args.index('-j')+1] == chain:
                    run([binary, '-w', '-D', *args[1:]])
            run([binary, '-w', '-F', chain], required=False)
            run([binary, '-w', '-X', chain], required=False)
    for name in units:
        remove('/etc/systemd/system/' + name + '.service')
    for p in Path('/usr/local/sbin').glob('bw-*'):
        remove(p)
    for path in ['/opt/bunkerweb-manager', '/etc/bunkerweb', '/usr/share/bunkerweb',
                 '/var/lib/bunkerweb', '/var/cache/bunkerweb', '/var/log/bunkerweb',
                 '/var/backups/bunkerweb', '/var/tmp/bunkerweb', '/var/tmp/bunkerweb_upgrade',
                 '/run/bunkerweb', '/etc/nginx', '/var/log/nginx', '/var/cache/nginx',
                 '/etc/logrotate.d/bunkerweb', '/etc/apt/sources.list.d/bunkerity_bunkerweb.list',
                 '/etc/apt/keyrings/bunkerity_bunkerweb-archive-keyring.gpg',
                 '/etc/apt/sources.list.d/nginx.list', '/usr/share/keyrings/nginx-archive-keyring.gpg',
                 '/etc/haproxy/haproxy.cfg.next']:
        remove(path)
    for binary, path in [('iptables-save', '/etc/iptables/rules.v4'),
                         ('ip6tables-save', '/etc/iptables/rules.v6')]:
        if Path(path).parent.exists():
            Path(path).write_text(subprocess.check_output([binary], text=True))
            Path(path).chmod(0o600)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'is-active', 'haproxy', 'keepalived', 'waf-poc-firewall'])
    print('BunkerWeb removal completed on ' + host, flush=True)


if __name__ == '__main__':
    main()
