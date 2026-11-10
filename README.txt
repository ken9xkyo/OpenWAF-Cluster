OPENWAF CLUSTER — POC HAI VM
Triển khai ngày 10/11/2026. Nguồn ứng dụng quản trị nằm trong control/.

Truy cập ứng dụng được bảo vệ:
  https://test-waf.vtccloud.vn
  VIP 118.107.78.209 → HAProxy TCP/PROXY v2 → Caddy TLS + Coraza
  → http://118.107.78.220:3000

Mở WebGUI từ máy cá nhân:
  ssh -N -L 9000:127.0.0.1:9000 root@118.107.78.206
  Sau đó mở http://127.0.0.1:9000
  Username: admin
  Mật khẩu khởi tạo: đọc /root/waf-poc-admin.txt trên VM .206.
  Mật khẩu không được ghi trong repository hoặc báo cáo. Có thể đổi ở WebGUI.
  Nếu port local 9000 đang bận, dùng -L 19000:127.0.0.1:9000 và mở port 19000.

Bố trí:
  waf-cluster-1: 118.107.78.206 / 192.168.11.100
    HAProxy, Keepalived, Caddy/Coraza, WebGUI/API, agent API mTLS, agent,
    PostgreSQL 16, cấp/gia hạn Let's Encrypt, đồng bộ chứng thư mỗi phút.
  waf-cluster-2: 118.107.78.18 / 192.168.11.202
    HAProxy, Keepalived, Caddy/Coraza, WebGUI/API, agent API mTLS, agent.
  VIP được đưa về node 1 sau diễn tập. Keepalived có nopreempt.
  Không còn BunkerWeb/Nginx, sidecar ClamAV hoặc manager cũ.

Cổng:
  Public TCP 80/443: HAProxy; HTTPS kết thúc tại Caddy.
  LAN TCP 8080/8443: Caddy, chỉ cho hai IP LAN của LB.
  Loopback 2019: Caddy Admin API; không public.
  Loopback 9000: WebGUI/API, truy cập qua SSH tunnel.
  LAN 9443: agent API; yêu cầu mTLS và token riêng từng node.
  LAN 5432 tại .100: PostgreSQL, TLS verify-full + SCRAM, chỉ hai node.
  Loopback 8085: HAProxy stats.

Workflow quản trị:
  1. Website & policy: tạo/sửa domain, IPv4 backend, port, mode, PL và rule exception.
     Thao tác này chỉ lưu nháp. Rule exception trong MVP áp dụng theo site, có lý do.
  2. Phiên bản & triển khai: tạo phiên bản và validate Caddy/Coraza cho cả hai node.
  3. Admin approve phiên bản đã validate.
  4. Canary: áp dụng trên node 1; kiểm tra ứng dụng, agent health và lỗi WAF.
  5. Triển khai node 2 sau khi canary healthy; trạng thái complete khi cả hai đồng bộ.
  6. Rollback: chọn revision cũ, canary node 1 rồi triển khai node 2.
  7. Dừng rollout chỉ dừng tiến trình, không tự đổi các node đã apply về policy cũ.

Role local:
  Viewer: chỉ đọc. Engineer: sửa nháp, tạo/validate revision.
  Admin: quản lý tài khoản, approve, deploy, promote, rollback.
  Admin được phép approve revision của chính mình trong POC; chưa bắt buộc review 2 người.
  Vô hiệu hóa tài khoản thu hồi session. Đổi mật khẩu cũng thu hồi các session.

Thêm backend/domain:
  Backend hiện được giới hạn 118.107.78.220/32 để ngăn cấu hình tới dịch vụ quản trị.
  Nếu cần backend khác, chỉnh BACKEND_ALLOWLIST trong /etc/waf-control/control.env
  trên cả hai VM, rồi restart waf-control và waf-agent-api; WAF không cần dừng.
  Domain mới phải có DNS về VIP trước khi cấp chứng thư. Kiểm tra HTTPS của domain
  mới trước khi promote. Việc cấp/gia hạn ACME được thực hiện trên node 1.
  HTTP port 80 ưu tiên node 1 (node 2 backup); HTTPS port 443 cân bằng cả hai WAF.
  Chứng thư được đồng bộ qua SSH đã pin host key; reload --force để đọc cert mới.
  Nếu node 1 mất, node 2 dùng cert đã đồng bộ nhưng không tự tiếp quản việc gia hạn.

Service thường dùng:
  systemctl status caddy haproxy keepalived waf-control waf-agent-api waf-agent
  systemctl status postgresql@16-main             # chỉ node 1
  systemctl list-timers waf-cert-sync.timer waf-logrotate.timer
  journalctl -u waf-agent -n 50 --no-pager
  journalctl -u caddy -n 50 --no-pager
  curl -fsS https://test-waf.vtccloud.vn/ -o /dev/null
  curl -fsS http://127.0.0.1:9000/healthz

Nguồn và cấu hình:
  Repository: /root/OpenWAF-Cluster
  Runtime code: /opt/waf-control/app/control (root-owned, read-only cho service).
  Python venv: /opt/waf-control/venv
  Caddy binary: /usr/local/bin/caddy
  Caddyfile: /etc/caddy/Caddyfile → /var/lib/caddy/active/Caddyfile
  Agent staging/state/LKG: /var/lib/waf-agent (chỉ phục vụ reconcile/rollback).
  Control env/PKI: /etc/waf-control; agent identity: /etc/waf-agent.
  Không chỉnh Caddyfile trực tiếp: agent sẽ reconcile về revision mong muốn.
  Agent verify Ed25519, SHA256, node identity và generation chống replay;
  rollback revision cũ được cấp generation mới. Private keys/token không vào Git.

Log và dữ liệu:
  Caddy access log: /var/log/caddy/access.json, rotation 10 MiB × 5;
  loại bỏ headers và URI khỏi access log.
  Coraza audit: /var/log/coraza/site-*.json, parts AHZ, không ghi body/header đầy đủ.
  Kiểm tra size 15 phút/lần; rotate khi trên 10 MiB, giữ 5 bản.
  Audit có thể chứa matched data trong thông báo rule; chỉ caddy/root đọc log gốc.
  WebGUI chỉ nhận IP, rule IDs và hành động, không nhận payload/cookie/token.
  Event queue tại agent giới hạn 1.000; log gốc là nguồn khi delivery gián đoạn.
  PostgreSQL chưa cấu hình xóa lịch sử WAF/audit theo thời gian; cần chốt retention
  và tích hợp SIEM trước production. Không cấu hình backup theo yêu cầu POC.

Kết quả kiểm thử:
  reports/2026-11-10/control-verification.json
    Auth/CSRF/RBAC, revoke session, allowlist backend, mTLS, chữ ký chống tamper,
    validate/approve/canary/rollout, SQLi 403, XFF giả, rollback, config drift,
    data plane tiếp tục HTTP 200 khi PostgreSQL dừng.
  reports/2026-11-10/ha-verification.json
    Drain WAF01; WAF02 dừng → bị loại sau ~8,54 giây;
    LB01 dừng → VIP sang LB02 sau ~2,53 giây; HTTPS 200; khôi phục VIP node 1.
  WebGUI: Chromium desktop/mobile, 6 trang, login và site editor, không lỗi JS.
  Đây là probe từ cụm, không phải benchmark tải/N-1 hay cam kết RTO production.

Giới hạn POC đã chọn:
  Hai VM chung LB/WAF/control plane; một PostgreSQL trên .100 là điểm lỗi đơn.
  Agent và Caddy tiếp tục phục vụ khi API/DB mất, nhưng không publish được khi DB mất.
  Chưa có SSO/OIDC, raw SecLang editor, exception theo route/target/expiry,
  GitOps/Vault, autoscale, tích hợp SIEM hoặc benchmark theo traffic thực tế.
  Chưa xác minh firewall/allowlist trên backend public 118.107.78.220:3000 vì chưa
  có quyền cấu hình server đó. Cần xác nhận chỉ cho phép nguồn WAF .206/.18 hoặc
  chuyển backend sang LAN trước khi kết luận không có đường đi tắt WAF.
  Hệ thống hiện active revision 1 / DetectionOnly. Blocking đã được kiểm thử rồi
  rollback. Bật On qua workflow khi ứng dụng đã được kiểm tra false positive.
