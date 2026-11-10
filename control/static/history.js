'use strict';
const historyState={events:{q:'',outcome:'',page:1},audit:{q:'',outcome:'',page:1}};
let historyRequest=0,historyItems=[];
function historyPage(){
 const waf=page==='events',state=historyState[page];
 return head(waf?'Sự kiện WAF':'Audit quản trị',waf?'Tra cứu request khớp rule Coraza và thông tin URL.':'Tra cứu hoạt động và thay đổi cấu hình của người quản trị.')+
 panel(waf?'Nhật ký sự kiện':'Nhật ký quản trị',`<form id="history-search" class="history-controls"><label>Tìm kiếm<input name="q" type="search" maxlength="200" value="${esc(state.q)}" placeholder="${waf?'URL, hostname, IP, node, rule ID, method…':'Người thực hiện, thao tác, chi tiết…'}"></label>${waf?`<label>Hành động<select name="outcome"><option value="">Tất cả</option><option value="blocked" ${state.outcome==='blocked'?'selected':''}>Blocked</option><option value="detected" ${state.outcome==='detected'?'selected':''}>Detected</option></select></label>`:''}<button class="primary" type="submit">Tìm kiếm</button><button class="secondary" type="button" data-history-reset>Xóa bộ lọc</button><button class="secondary" type="button" data-history-refresh>Làm mới</button></form><div id="history-results" aria-live="polite"><div class="empty">Đang tải nhật ký…</div></div>`);
}
async function loadHistory(){
 const target=page,state=historyState[target];if(!state)return;
 const request=++historyRequest,query=new URLSearchParams({q:state.q,outcome:state.outcome,page:state.page,size:25});
 const results=$('#history-results');if(!results)return;results.setAttribute('aria-busy','true');
 try{
  const result=await api(`/api/history/${target==='events'?'waf':'audit'}?${query}`);
  if(request!==historyRequest||page!==target||!user)return;
  state.page=result.page;historyItems=result.items;
  const rows=target==='events'?table(['Thời gian / Node','Website / URL request','Client IP','Rule IDs','Hành động',''],result.items.map(e=>[
   `${date(e.created_at)}<div class="muted">${esc(e.node_id)}</div>`,
   `<div class="event-url"><strong>${esc(e.request_host||e.hostname||`Site #${e.site_id}`)}</strong><div class="mono">${e.request_method?tag(e.request_method):''} ${esc(e.request_uri||'Chưa có URL trong bản ghi này')}</div></div>`,
   esc(e.client_ip||'—'),`<div class="event-rules mono">${esc(e.rule_ids.join(', '))}</div>`,tag(e.interrupted?'Blocked':'Detected',e.interrupted?'bad':'warn'),action('Chi tiết','event-detail',e.id)
  ])):table(['Thời gian','Người thực hiện','Thao tác','Chi tiết'],result.items.map(a=>[date(a.created_at),esc(a.actor),esc(a.action),`<div class="audit-detail mono">${esc(JSON.stringify(a.detail))}</div>`]));
  results.innerHTML=`<p class="history-count small muted">${result.total} ${target==='events'?'sự kiện':'bản ghi'}${state.q?' khớp tìm kiếm':''}</p>`+(result.total?rows:'<div class="empty">Không tìm thấy bản ghi phù hợp.</div>')+`<div class="history-pagination"><button class="secondary" data-history-page="${result.page-1}" ${result.page<=1?'disabled':''}>← Trước</button><span>Trang ${result.page} / ${result.pages}</span><button class="secondary" data-history-page="${result.page+1}" ${result.page>=result.pages?'disabled':''}>Sau →</button></div>`;
 }catch(error){if(request===historyRequest&&page===target&&user)results.innerHTML=`<div class="empty"><p class="error">${esc(error.message)}</p><button class="secondary" data-history-refresh>Thử lại</button></div>`}
 finally{if(request===historyRequest)results.removeAttribute('aria-busy')}
}
function eventDetail(id){
 const e=historyItems.find(item=>item.id===Number(id));if(!e)return;
 const uri=e.request_uri||'',host=e.request_host||e.hostname||'';
 let path=uri.split('?')[0],query=uri.includes('?')?uri.slice(uri.indexOf('?')+1):'';
 try{if(/^https?:\/\//i.test(uri)){const parsed=new URL(uri);path=parsed.pathname;query=parsed.search.slice(1)}}catch{}
 const detail=[['Thời gian',date(e.created_at)],['Node',e.node_id],['Site ID',e.site_id],['Hostname',host||'Chưa có dữ liệu'],['Method',e.request_method||'Chưa có dữ liệu'],['Giao thức',e.request_protocol||'Chưa có dữ liệu'],['URI gốc',uri||'Chưa có URL trong bản ghi này'],['Đường dẫn',path||'—'],['Query string',query||'—'],['Client IP',e.client_ip||'—'],['Rule IDs',e.rule_ids.join(', ')],['Hành động',e.interrupted?'Blocked':'Detected'],['Event key',e.event_key]];
 const params=[...new URLSearchParams(query)].map(([key,value])=>[esc(key),`<div class="audit-detail mono">${esc(value)}</div>`]);
 dialog(`Chi tiết sự kiện #${e.id}`,`<dl class="event-detail">${detail.map(([key,value])=>`<dt>${key}</dt><dd class="mono">${esc(value)}</dd>`).join('')}</dl>${params.length?'<h3>Tham số URL (đã giải mã)</h3>'+table(['Tên','Giá trị'],params):''}`,async()=>{},'Đóng');
}
document.querySelector('#main').addEventListener('submit',event=>{
 if(event.target.id!=='history-search')return;event.preventDefault();
 const form=new FormData(event.target),state=historyState[page];state.q=String(form.get('q')||'').trim();state.outcome=String(form.get('outcome')||'');state.page=1;loadHistory();
});
document.querySelector('#main').addEventListener('click',event=>{
 const button=event.target.closest('button');if(!button||!historyState[page])return;
 if(button.hasAttribute('data-history-page')){historyState[page].page=Number(button.dataset.historyPage);loadHistory()}
 if(button.hasAttribute('data-history-refresh'))loadHistory();
 if(button.hasAttribute('data-history-reset')){historyState[page]={q:'',outcome:'',page:1};render()}
 if(button.dataset.action==='event-detail')eventDetail(button.dataset.id);
});
