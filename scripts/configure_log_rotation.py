#!/usr/bin/env python3
from pathlib import Path
import subprocess

Path('/etc/waf-control/logrotate-coraza.conf').write_text('''/var/log/coraza/site-*.json {
    size 10M
    rotate 5
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    su caddy caddy
}
''')
Path('/etc/systemd/system/waf-logrotate.service').write_text('''[Unit]
Description=Rotate local Coraza audit logs for the WAF POC
[Service]
Type=oneshot
ExecStart=/usr/sbin/logrotate --state /var/lib/logrotate/waf-poc.status /etc/waf-control/logrotate-coraza.conf
''')
Path('/etc/systemd/system/waf-logrotate.timer').write_text('''[Unit]
Description=Check Coraza audit log size every 15 minutes
[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
[Install]
WantedBy=timers.target
''')
subprocess.run(['logrotate','--debug','/etc/waf-control/logrotate-coraza.conf'],check=True,capture_output=True)
subprocess.run(['systemctl','daemon-reload'],check=True)
subprocess.run(['systemctl','enable','--now','waf-logrotate.timer'],check=True)
print('Coraza log rotation configured.')
