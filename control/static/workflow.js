'use strict';
const workflowLabels={draft:'Nháp · chưa kiểm tra',checked:'Đã kiểm tra · chờ phê duyệt',approved:'Đã phê duyệt · sẵn sàng triển khai',canary:'Đang thăm dò node 1',rollout:'Đang triển khai node 2',complete:'Đã triển khai trên cả hai node',aborted:'Đã dừng triển khai',attention:'Cần kiểm tra trạng thái node'};
function siteDeploymentTag(id){
 const site=data.workflow?.sites.find(s=>s.id===id);
 return site?`<div class="site-deployment">${tag(site.applied?'Đã triển khai':'Chưa triển khai đầy đủ',site.applied?'good':'warn')}</div>`:'';
}
function workflowButton(w){
 const active=w.active_deployment;
 if(active)return isAdmin()?action('Dừng triển khai','abort',active.id,'danger'):'';
 if(!data.sites.length)return canEdit()?action('+ Thêm website','new-site','','primary'):'';
 if(w.stage==='draft')return canEdit()?action('Kiểm tra cấu hình','new-revision','','primary'):'';
 if(w.stage==='checked')return isAdmin()?action('Phê duyệt phiên bản','approve',w.revision_id,'primary'):'';
 if(['approved','aborted'].includes(w.stage))return isAdmin()?action(w.stage==='aborted'?'Thử triển khai lại':'Triển khai node 1','deploy',w.revision_id,'primary'):'';
 return '';
}
function workflowSummary(){
 const w=data.workflow;if(!w)return '';
 return `<div class="release-summary ${w.applied?'synced':''}"><div><strong>${esc(workflowLabels[w.stage])}</strong><p>${w.applied?'Cấu hình đang lưu đã được xác nhận trên cả hai node.':`${w.pending_sites} website chưa được xác nhận triển khai đầy đủ. Thay đổi được lưu vào bản nháp trước khi áp dụng.`}</p></div>${action('Xem tiến trình →','view-workflow','')}</div>`;
}
function workflowNode(n){
 let label='Chưa triển khai',kind='warn';
 if(!n.online){label='Mất kết nối';kind='bad'}
 else if(['error','drift'].includes(n.health)){label=n.health==='drift'?'Cấu hình bị lệch':'Lỗi áp dụng';kind='bad'}
 else if(n.applied){label='Đã khớp cấu hình hiện tại';kind='good'}
 else if(n.matches_draft){label='Chờ xác nhận cấu hình';kind='warn'}
 return `<article class="release-node"><div class="release-node-head"><h3>${n.id==='waf-cluster-1'?'Node 1 · Thăm dò':'Node 2 · Tự động triển khai'}</h3>${tag(label,kind)}</div><p class="small muted mono">${esc(n.id)}</p><dl><dt>Phiên bản đang chạy</dt><dd>${n.actual_revision?'r'+n.actual_revision:'Chưa có'}</dd><dt>Phiên bản yêu cầu</dt><dd>${n.desired_revision?'r'+n.desired_revision:'Chưa có'}</dd><dt>Heartbeat gần nhất</dt><dd>${date(n.last_seen)}</dd></dl>${n.detail?`<p class="release-node-detail">${esc(n.detail)}</p>`:''}</article>`;
}
function workflowSiteRows(w){return table(['Website','Cấu hình đang lưu','Node 1','Node 2','Thay đổi chưa áp dụng'],w.sites.map(s=>{
 const changed=[...new Set(s.nodes.flatMap(n=>n.changed_fields))];
 return [`<strong>${esc(s.hostname)}</strong>`,tag(s.applied?'Đã triển khai':'Chưa triển khai đầy đủ',s.applied?'good':'warn'),...s.nodes.map(n=>tag(n.applied?'Đã khớp':n.matches?'Chờ xác nhận':'Chưa khớp',n.applied?'good':'warn')),`<div class="release-changes">${esc(changed.join(', ')||(s.applied?'Không còn thay đổi':'Cấu hình đã khớp; chờ agent xác nhận healthy và mã kiểm tra.'))}</div>`];
}));}
function workflowPage(){
 const w=data.workflow;
 if(!w)return head('Phiên bản & triển khai','Đang tải trạng thái cấu hình…');
 const descriptions={draft:'Cấu hình đã lưu chưa có phiên bản được kiểm tra. Kiểm tra Caddy/Coraza trên cả hai node để tiếp tục.',checked:`Phiên bản r${w.revision_id} đã vượt qua kiểm tra Caddy/Coraza. Admin phê duyệt để cho phép triển khai.`,approved:`Phiên bản r${w.revision_id} đã được phê duyệt. Bắt đầu trên node 1; node 2 sẽ tự động triển khai khi node 1 healthy và khớp cấu hình.`,canary:'Đang chờ node 1 nhận đúng phiên bản, healthy và khớp mã kiểm tra. Khi đạt điều kiện, hệ thống tự chuyển sang node 2.',rollout:'Node 1 đã đạt điều kiện thăm dò. Hệ thống đang triển khai node 2 và chờ cả hai node xác nhận.',complete:'Cấu hình đang lưu khớp với cấu hình thực tế trên cả hai node; heartbeat healthy và mã kiểm tra hợp lệ.',attention:'Phiên bản đã được triển khai trước đó, nhưng hiện chưa xác nhận được đầy đủ trạng thái trên hai node. Xem heartbeat, tình trạng agent và mã cấu hình bên dưới.',aborted:'Tiến trình đã dừng. Các node đã áp dụng giữ nguyên cấu hình; bạn có thể thử lại hoặc khôi phục phiên bản cũ.'};
 const current={draft:0,checked:2,approved:3,canary:3,rollout:4,complete:5,aborted:3,attention:4}[w.stage];
 const steps=[['Nháp','Lưu cấu hình website'],['Kiểm tra','Caddy + Coraza · 2 node'],['Phê duyệt','Admin xác nhận phiên bản'],['Thăm dò node 1','Chờ healthy & đúng cấu hình'],['Triển khai node 2','Tự động sau node 1']];
 let html=head('Phiên bản & triển khai','Theo dõi cấu hình từ bản nháp đến khi được xác nhận trên cả hai WAF node.');
 html+=`<section class="panel release-current"><div class="release-title"><div><p class="eyebrow">CẤU HÌNH HIỆN TẠI ${w.revision_id?' / r'+w.revision_id:''}</p><h2>${esc(workflowLabels[w.stage])}</h2></div>${tag(w.applied?'2 / 2 node đã khớp':`${w.nodes.filter(n=>n.applied).length} / 2 node đã khớp`,w.applied?'good':'warn')}</div><ol class="release-steps" aria-label="Tiến trình triển khai">${steps.map(([label,help],i)=>`<li class="${i<current?'done':i===current?'current':'waiting'}" ${i===current?'aria-current="step"':''}><span class="release-step-number">${i<current?'✓':i+1}</span><div><strong>${label}</strong><small>${help}</small><span class="release-step-status">${i<current?'Hoàn tất':i===current?'Bước hiện tại':'Chờ bước trước'}</span></div></li>`).join('')}</ol><div class="release-next"><div><p>${esc(descriptions[w.stage])}</p>${!isAdmin()&&!['draft','complete'].includes(w.stage)?'<p class="small muted">Admin phê duyệt và khởi tạo triển khai. Các bước trên node sẽ chạy tự động.</p>':''}${!canEdit()&&w.stage==='draft'?'<p class="small muted">Engineer hoặc Admin có thể kiểm tra bản nháp.</p>':''}</div><div class="actions">${workflowButton(w)}</div></div></section>`;
 if(w.active_deployment&&w.active_deployment.revision_id!==w.revision_id)html+=`<div class="notice"><strong>r${w.active_deployment.revision_id} đang được triển khai.</strong> Bản nháp hiện tại khác với phiên bản đang triển khai. Hoàn tất hoặc dừng lần triển khai #${w.active_deployment.id} trước khi triển khai cấu hình mới.</div>`;
 html+=`<div class="release-nodes">${w.nodes.map(workflowNode).join('')}</div>`;
 html+=panel('Website đã nhận cấu hình hiện tại chưa?',workflowSiteRows(w),`${w.pending_sites} / ${w.sites.length} chưa hoàn tất`);
 html+=`<div class="notice small">Một phiên bản chứa cấu hình của toàn bộ website trong cụm. “Đã khớp” yêu cầu snapshot đúng cấu hình đang lưu, agent online, healthy và mã kiểm tra hợp lệ. Trạng thái tự cập nhật mỗi 5 giây.</div>`;
 html+=`<details class="panel release-history"><summary>Lịch sử phiên bản <span class="muted">${data.revisions.length} phiên bản gần nhất</span></summary>${table(['Phiên bản','Ghi chú','Trạng thái','Ngày tạo',''],data.revisions.map(r=>[`<strong>r${r.id}</strong>${r.id===w.revision_id?'<div class="small muted">Khớp cấu hình đang lưu</div>':''}`,`<div class="release-changes">${esc(r.note)}</div>`,tag(r.approved_at?'Đã phê duyệt':r.validated?'Đã kiểm tra':'Chưa kiểm tra',r.approved_at?'good':'warn'),date(r.created_at),`<div class="actions">${action('Xem cấu hình','inspect',r.id)}${isAdmin()&&r.approved_at&&!w.active_deployment&&w.nodes.some(n=>n.actual_revision!==r.id)?action('Khôi phục','rollback',r.id):''}</div>`]))}</details>`;
 html+=`<details class="panel release-history"><summary>Lịch sử triển khai <span class="muted">${data.deployments.length} lần gần nhất</span></summary>${deployTable()}</details>`;
 return html;
}
