FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    XDG_DATA_HOME=/var/lib/waf-control \
    XDG_CONFIG_HOME=/var/lib/waf-control
WORKDIR /app
COPY control/requirements.lock.txt /app/requirements.lock.txt
RUN pip install --no-cache-dir -r /app/requirements.lock.txt
# Staged by install_control_compose.py from the node's validated Coraza build.
COPY docker/caddy /usr/local/bin/caddy
RUN caddy list-modules | grep -qx 'http.handlers.waf'
COPY control /app/control
USER 65534:65534
CMD ["uvicorn", "control.app:app", "--host", "127.0.0.1", "--port", "9000", "--no-proxy-headers", "--no-access-log"]
