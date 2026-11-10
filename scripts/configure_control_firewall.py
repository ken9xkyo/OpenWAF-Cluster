#!/usr/bin/env python3
from pathlib import Path
import socket
import subprocess

node = {'waf-cluster-1': '192.168.11.100', 'waf-cluster-2': '192.168.11.202'}[socket.gethostname()]
script = '''#!/bin/sh
set -eu
iptables -w -N WAF-CONTROL 2>/dev/null || true
iptables -w -F WAF-CONTROL
iptables -w -A WAF-CONTROL -i lo -j ACCEPT
'''
for source in ['192.168.11.100/32', '192.168.11.202/32']:
    script += f'iptables -w -A WAF-CONTROL -i ens8 -s {source} -d {node} -p tcp -m multiport --dports 5432,9443 -j ACCEPT\n'
script += '''iptables -w -A WAF-CONTROL -j DROP
iptables -w -C INPUT -p tcp -m multiport --dports 5432,9000,9443 -j WAF-CONTROL 2>/dev/null || iptables -w -I INPUT 1 -p tcp -m multiport --dports 5432,9000,9443 -j WAF-CONTROL
ip6tables -w -N WAF-CONTROL 2>/dev/null || true
ip6tables -w -F WAF-CONTROL
ip6tables -w -A WAF-CONTROL -i lo -j ACCEPT
ip6tables -w -A WAF-CONTROL -j DROP
ip6tables -w -C INPUT -p tcp -m multiport --dports 5432,9000,9443 -j WAF-CONTROL 2>/dev/null || ip6tables -w -I INPUT 1 -p tcp -m multiport --dports 5432,9000,9443 -j WAF-CONTROL
'''
path = Path('/usr/local/sbin/waf-control-firewall')
path.write_text(script)
path.chmod(0o755)
Path('/etc/systemd/system/waf-control-firewall.service').write_text('''[Unit]
Description=Restrict WAF database and agent endpoints to the two LAN peers
After=network-online.target
Wants=network-online.target
Before=waf-control.service waf-agent-api.service postgresql@16-main.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/waf-control-firewall
[Install]
WantedBy=multi-user.target
''')
subprocess.run(['systemctl', 'daemon-reload'], check=True)
subprocess.run(['systemctl', 'enable', '--now', 'waf-control-firewall'], check=True)
for binary, path in [('iptables-save', '/etc/iptables/rules.v4'), ('ip6tables-save', '/etc/iptables/rules.v6')]:
    Path(path).write_text(subprocess.check_output([binary], text=True))
    Path(path).chmod(0o600)
print('Management firewall configured for ' + node)
