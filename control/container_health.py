"""Local liveness probes; agents keep serving their last config during API outages."""
import os
from pathlib import Path
import socket
import sys
import time


def main():
    if sys.argv[1] == 'agent-api':
        from control.app import db
        from control.render import NODES
        with socket.create_connection((NODES[os.environ['NODE_ID']], 9443), timeout=3):
            pass
        with db() as conn:
            conn.execute('SELECT 1')
    elif sys.argv[1] == 'agent':
        # Written after each reconcile/heartbeat attempt, even during API outages.
        if time.time() - Path('/var/lib/waf-agent/state.json').stat().st_mtime > 120:
            raise RuntimeError('Agent reconciliation stopped')
    else:
        raise ValueError('Unknown health probe')


if __name__ == '__main__':
    main()
