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
  5. Node 2 tự động triển khai khi heartbeat node 1 healthy, đúng revision và khớp
     SHA-256 cấu hình; complete khi cả hai node online, healthy, đúng revision/digest.
  6. Rollback: mở Lịch sử phiên bản, chọn Khôi phục; node 1 trước, node 2 tự động.
  7. Dừng rollout chỉ dừng tiến trình, không tự đổi các node đã apply về policy cũ.

  Phiên bản & triển khai hiển thị cấu hình đang lưu với 5 bước:
    Nháp → Kiểm tra → Phê duyệt → Thăm dò node 1 → Triển khai node 2.
  Chỉ hiển thị thao tác tiếp theo phù hợp quyền; node 2 chạy tự động.
  Mỗi node có revision đang chạy/yêu cầu, heartbeat và trạng thái khớp cấu hình.
  Bảng website đối chiếu snapshot thực tế trên từng node, chỉ ra trường còn khác
  (backend, mode, PL, rules, tham số nâng cao...). Website & policy và CRS rules
  có liên kết Xem tiến trình. Lịch sử phiên bản/triển khai thu gọn bên dưới.
  Sửa nháp sau khi kiểm tra không dùng lại phê duyệt của cấu hình cũ. Hộp thoại
  kiểm tra gửi fingerprint nháp; API trả 409 nếu người khác đã sửa trước khi gửi.
  “Đã triển khai” dựa trên snapshot và heartbeat/digest hiện tại, kể cả khi revision
  node nằm ngoài 30 phiên bản gần nhất. Lần triển khai complete trong lịch sử
  không thay thế xác nhận hiện tại khi agent offline, lỗi hoặc cấu hình lệch.
  Auto-promote ghi audit deployment.auto_promote; các bước deploy, abort và heartbeat
  dùng cùng advisory transaction lock để tránh tranh chấp khi hai API cùng xử lý.
  API promote cũ vẫn tương thích, nhưng UI không yêu cầu bấm triển khai node 2.
  Không cần migration DB mới cho luồng triển khai tự động.

  Kiểm thử luồng mới:
    /opt/waf-control/venv/bin/python -m unittest discover -s tests -v
    node scripts/verify_workflow_ui.cjs (Playwright, API giả lập; không đổi WAF)
    PYTHONPATH=. python scripts/verify_workflow_api.py (DB test riêng, quyền tạo schema;
    validate Caddy/Coraza thực tế, tự xóa schema test; không gọi agent thật).

Cấu hình Paranoia nâng cao (Website & policy → Chỉnh sửa website):
  PL chặn 1–4 quyết định các cấp rule được cộng điểm để chặn (CRS 4:
  tx.blocking_paranoia_level). Mỗi cấp bao gồm các rule của cấp thấp hơn.
  Mở “Cấu hình nâng cao” và chọn riêng từng tham số muốn tùy chỉnh:
    - PL phát hiện: mặc định bằng PL chặn, phải >= PL chặn và <= 4.
      Ví dụ PL chặn 1, PL phát hiện 2: chạy thêm rule PL2 để quan sát,
      chỉ điểm từ PL1 được tính vào quyết định chặn.
    - Ngưỡng điểm request/response: mặc định 5/4, cho phép 1–10000.
    - Điểm Critical/Error/Warning/Notice: mặc định 5/4/3/2, cho phép 1–100.
  Bỏ chọn một tham số để dùng mặc định; “Dùng mặc định cho tất cả” xóa
  tất cả tùy chỉnh nâng cao, giữ PL chặn và rule exception đã chọn.
  Ngưỡng response áp dụng cho các response được WAF kiểm tra. DetectionOnly
  vẫn chỉ ghi nhận. PL cao/tăng điểm có thể tăng cảnh báo nhầm; tăng ngưỡng
  làm giảm độ nhạy. Các tham số lưu riêng theo website trong crs_settings,
  đi vào snapshot/revision và rollback như các cấu hình policy khác.
  Sau khi lưu nháp, tạo/validate phiên bản → approve → canary → node 2.

Xem và tùy chọn từng rule (menu CRS rules, hoặc nút Rule của website):
  Danh mục gồm 625 rule của OWASP CRS 4.25.0 đang được nhúng trong Caddy,
  trong đó 341 rule phát hiện có thể bật/tắt. Rule điều khiển nội bộ CRS
  (khởi tạo, điều hướng PL, tính điểm/chặn, tổng hợp sự kiện) chỉ được xem.
  Chọn website, tìm theo ID/mô tả/tag, lọc theo nhóm, PL hoặc trạng thái.
  “Xem rule” hiển thị mô tả, severity, phase, tags, file/dòng nguồn và
  điều kiện SecLang gốc, bao gồm đầy đủ các điều kiện nối chuỗi.
  Checkbox cho phép rule chạy theo PL; bỏ chọn để tắt rule theo website.
  Rule ngoài PL không tự chạy chỉ vì được tích chọn. Trạng thái phân biệt
  tính điểm chặn, chỉ phát hiện, ngoài PL, đã tắt và rule hệ thống.
  DetectionOnly luôn hiển thị rule phát hiện là “Chỉ phát hiện”.
  Nhập lý do khi tắt rule, chọn “Lưu rule vào bản nháp”, rồi triển khai revision
  theo workflow hiện có. Các lựa chọn được giữ khi lọc/chuyển trang. Khi có
  người khác sửa danh sách rule trước, API trả 409 và yêu cầu tải lại.
  API PATCH /api/sites/{id}/rules chỉ cập nhật danh sách ngoại lệ/lý do,
  giữ nguyên backend, PL, mode và các tham số nâng cao. Audit lưu trước/sau.
  Viewer được xem danh mục/chi tiết/trạng thái; Engineer và Admin được lưu nháp.
  Ngoại lệ cũ có ID ngoài danh mục vẫn được giữ và đánh dấu để kiểm tra/bật lại.
  Danh mục nằm trong control/data/crs-rules.json, kèm CRS-LICENSE.txt.
  Khi đổi phiên bản CRS nhúng trong Caddy, sinh lại từ đúng nguồn của bản build:
    python3 scripts/build_rule_catalog.py /path/to/coraza-coreruleset/rules
  Đối chiếu phiên bản qua caddy build-info trên cả hai node trước khi cập nhật.
  Kiểm thử xử lý rule thực tế, dùng listener loopback tách biệt:
    /opt/waf-control/venv/bin/python scripts/verify_rule_runtime.py

Nâng cấp mã nguồn cho control plane đã có dữ liệu:
  Chạy control/schema.sql bằng PostgreSQL owner trước khi restart API.
  Schema có ALTER TABLE sites ADD COLUMN IF NOT EXISTS crs_settings jsonb
  NOT NULL DEFAULT '{}'; không cần chạy lại bootstrap/seeding/PKI.
  Cập nhật control/ trong /opt/waf-control/app trên cả hai node, restart
  waf-control và waf-agent-api. Không cần restart Caddy hay đổi revision WAF.
  Kiểm thử hồi quy: /opt/waf-control/venv/bin/python -m unittest discover -s tests -v

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
  mới sau khi node 1 áp dụng. Node 2 tự triển khai và thử lại nếu chứng thư chưa
  đồng bộ xong. Việc cấp/gia hạn ACME được thực hiện trên node 1.
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
  WebGUI nhận IP, rule IDs, hành động, HTTP method/protocol, hostname và URI
  (gồm query string); không nhận body hoặc headers/cookie. URI có thể chứa dữ liệu
  do client gửi trong query. Bản ghi cũ không có metadata URL hiển thị thiếu dữ liệu.
  Hai tab Sự kiện / Audit quản trị tìm kiếm toàn bộ lịch sử, phân trang 25 bản ghi;
  Sự kiện tìm theo URI, hostname, IP, node, rule ID, method và lọc Blocked/Detected.
  Chọn Chi tiết để xem URI gốc, đường dẫn và tham số URL đã giải mã.
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
