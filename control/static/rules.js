'use strict';
let ruleCatalogData=null,ruleCatalogLoading=false,ruleCatalogError='',ruleEditor=null;
const RULES_PER_PAGE=20;
function newRuleEditor(site){return {siteId:site.id,expected:[...site.excluded_rules],expectedReason:site.exception_reason||'',excluded:new Set(site.excluded_rules),reason:site.exception_reason||'',query:'',group:'',pl:'',state:'',page:1,dirty:false,saving:false};}
function ensureRuleCatalog(){
 if(ruleCatalogData||ruleCatalogLoading)return;
 ruleCatalogLoading=true;ruleCatalogError='';
 api('/api/rules').then(result=>{ruleCatalogData=result}).catch(error=>{ruleCatalogError=error.message}).finally(()=>{ruleCatalogLoading=false;if(page==='rules')render()});
}
function currentRuleSite(){return data.sites.find(site=>site.id===ruleEditor?.siteId)}
function ruleState(rule){
 const site=currentRuleSite();
 if(ruleEditor.excluded.has(rule.id))return 'disabled';
 if(rule.legacy)return 'unknown';
 if(!rule.selectable)return 'system';
 const detection=site.crs_settings?.detection_paranoia_level??site.paranoia;
 if(rule.pl>detection)return 'outside';
 if(rule.pl>site.paranoia||site.mode==='DetectionOnly')return 'detect';
 return 'enabled';
}
const ruleStateLabels={enabled:'Tính điểm chặn',detect:'Chỉ phát hiện',outside:'Ngoài PL',disabled:'Đã tắt',system:'Hệ thống · chỉ xem',unknown:'Không có trong CRS'};
function allCatalogRules(){
 const known=new Set(ruleCatalogData.rules.map(rule=>rule.id));
 const legacy=ruleEditor.expected.filter(id=>!known.has(id)).map(id=>({id,description:'Ngoại lệ cũ: ID không có trong danh mục CRS hiện tại',group:'legacy',group_label:'Ngoại lệ cũ',pl:null,phase:null,severity:'',selectable:true,legacy:true,tags:[]}));
 return [...ruleCatalogData.rules,...legacy];
}
function rulesResults(){
 const state=ruleEditor,query=state.query.trim().toLowerCase();
 const rules=allCatalogRules().filter(rule=>(!query||`${rule.id} ${rule.description} ${rule.group_label} ${rule.tags.join(' ')}`.toLowerCase().includes(query))&&(!state.group||rule.group===state.group)&&(!state.pl||String(rule.pl)===state.pl)&&(!state.state||ruleState(rule)===state.state));
 const pages=Math.max(1,Math.ceil(rules.length/RULES_PER_PAGE));state.page=Math.min(state.page,pages);
 const rows=rules.slice((state.page-1)*RULES_PER_PAGE,state.page*RULES_PER_PAGE).map(rule=>{
  const status=ruleState(rule),excluded=state.excluded.has(rule.id);
  return `<tr><td><input type="checkbox" data-rule-toggle="${rule.id}" aria-label="Cho phép rule ${rule.id} theo PL" ${excluded?'':'checked'} ${(!canEdit()||state.saving||(!rule.selectable&&!excluded))?'disabled':''}></td><td class="mono">${rule.id}</td><td class="rule-description"><strong>${esc(rule.description)}</strong><div class="muted">${esc(rule.group_label)} · ${rule.pl?'PL '+rule.pl:'PL —'} · ${esc(rule.severity||'—')}</div></td><td>${tag(ruleStateLabels[status],status==='disabled'?'bad':status==='enabled'?'good':status==='system'?'':'warn')}</td><td>${rule.legacy?'—':action('Xem rule','inspect-rule',rule.id)}</td></tr>`;
 }).join('');
 return `<p class="small muted" id="rules-result-count">${rules.length} / ${allCatalogRules().length} rule · ${state.excluded.size} rule đã tắt${state.dirty?' · Có thay đổi chưa lưu':''}</p><div class="table-wrap rule-table"><table><thead><tr><th>Cho phép theo PL</th><th>ID</th><th>Mô tả / nhóm / PL</th><th>Trạng thái trong bản nháp</th><th></th></tr></thead><tbody>${rows||'<tr><td colspan="5" class="empty">Không có rule phù hợp bộ lọc.</td></tr>'}</tbody></table></div><div class="rule-pagination"><button type="button" class="secondary" data-rules-page="${state.page-1}" ${state.page<=1?'disabled':''}>Trước</button><span>Trang ${state.page} / ${pages}</span><button type="button" class="secondary" data-rules-page="${state.page+1}" ${state.page>=pages?'disabled':''}>Sau</button></div>`;
}
function rulePage(){
 const intro=head('CRS rules','Xem toàn bộ rule và chọn ngoại lệ cho từng website.');
 if(!ruleCatalogData){if(!ruleCatalogError)ensureRuleCatalog();return intro+`<div class="notice">${esc(ruleCatalogError||'Đang tải danh mục CRS…')}${ruleCatalogError?'<button class="secondary" data-action="retry-rules">Thử lại</button>':''}</div>`;}
 if(!data.sites.length)return intro+'<div class="empty">Thêm website để xem trạng thái và tùy chọn rule.</div>';
 if(!currentRuleSite())ruleEditor=newRuleEditor(data.sites[0]);
 const site=currentRuleSite(),groups=[...new Map(allCatalogRules().map(rule=>[rule.group,rule.group_label]))];
 return intro+`<div id="rules-workspace"><div class="notice">Lựa chọn áp dụng cho bản nháp của website. Tích chọn nghĩa là cho phép rule chạy theo PL; rule ngoài PL cần tăng PL để được chạy. Rule hệ thống chỉ được xem. Tạo/validate revision và triển khai để áp dụng.</div><div class="panel rules-controls"><div class="form-row"><label>Website<select id="rules-site" ${ruleEditor.saving?'disabled':''}>${data.sites.map(s=>`<option value="${s.id}" ${s.id===site.id?'selected':''}>${esc(s.hostname)}</option>`).join('')}</select></label><div class="rule-policy-context"><strong>${esc(ruleCatalogData.version)}</strong><p>PL chặn ${site.paranoia} · PL phát hiện ${site.crs_settings?.detection_paranoia_level??site.paranoia} · ${esc(site.mode)}</p><p class="small muted">Trạng thái theo PL và mode; điều kiện riêng của rule vẫn quyết định khi nào rule khớp.</p></div></div><label>Tìm rule theo ID, mô tả hoặc tag<input id="rules-search" type="search" value="${esc(ruleEditor.query)}" placeholder="Ví dụ: 942100, SQL injection, XSS"></label><div class="rules-filters"><label>Nhóm<select id="rules-group"><option value="">Tất cả nhóm</option>${groups.map(([key,label])=>`<option value="${esc(key)}" ${key===ruleEditor.group?'selected':''}>${esc(label)}</option>`).join('')}</select></label><label>Paranoia level<select id="rules-pl"><option value="">Tất cả PL</option>${[1,2,3,4].map(pl=>`<option value="${pl}" ${String(pl)===ruleEditor.pl?'selected':''}>PL ${pl}</option>`).join('')}</select></label><label>Trạng thái<select id="rules-state"><option value="">Tất cả trạng thái</option>${Object.entries(ruleStateLabels).map(([key,label])=>`<option value="${key}" ${key===ruleEditor.state?'selected':''}>${label}</option>`).join('')}</select></label></div></div><section class="panel"><div id="rules-results">${rulesResults()}</div></section>${canEdit()?`<section class="panel rules-controls"><label>Lý do tắt rule (bắt buộc khi có rule bị tắt)<textarea id="rules-reason" maxlength="500" ${ruleEditor.saving?'disabled':''}>${esc(ruleEditor.reason)}</textarea></label><p class="small muted">Bật lại rule bằng cách tích chọn. Bộ lọc và chuyển trang giữ nguyên các lựa chọn chưa lưu.</p><p id="rules-save-error" class="error" role="alert"></p><div class="actions"><button class="primary" data-action="save-rules" ${ruleEditor.saving?'disabled':''}>Lưu rule vào bản nháp</button><button class="secondary" data-action="reload-rules" ${ruleEditor.saving?'disabled':''}>Tải lại / bỏ thay đổi</button></div></section>`:'<div class="notice">Tài khoản Viewer chỉ được xem rule và trạng thái của website.</div>'}</div>`;
}
function refreshRuleResults(){if($('#rules-results'))$('#rules-results').innerHTML=rulesResults()}
function selectRuleSite(id){
 if(ruleEditor?.siteId===Number(id)){page='rules';return render();}
 const apply=()=>{const site=data.sites.find(s=>s.id===Number(id));if(site){ruleEditor=newRuleEditor(site);page='rules';render()}};
 if(ruleEditor?.dirty&&ruleEditor.siteId!==Number(id)){
  if($('#rules-site'))$('#rules-site').value=ruleEditor.siteId;
  return dialog('Chuyển website','<p>Các lựa chọn rule chưa lưu của website hiện tại sẽ được bỏ.</p>',async()=>apply(),'Bỏ thay đổi & chuyển');
 }
 apply();
}
async function saveRuleSelection(){
 if(!canEdit()||!ruleEditor||ruleEditor.saving)return;
 const state=ruleEditor;
 $('#rules-save-error').textContent='';
 if(state.excluded.size&&!state.reason.trim()){ $('#rules-save-error').textContent='Cần nhập lý do cho rule exception';$('#rules-reason').focus();return; }
 state.saving=true;render();
 try{
  const result=await api(`/api/sites/${state.siteId}/rules`,'PATCH',{excluded_rules:[...state.excluded].sort((a,b)=>a-b),exception_reason:state.reason,expected_excluded_rules:state.expected,expected_exception_reason:state.expectedReason});
  state.expected=[...result.excluded_rules];state.expectedReason=result.exception_reason;state.dirty=false;
  const site=data.sites.find(s=>s.id===state.siteId);if(site){site.excluded_rules=[...result.excluded_rules];site.exception_reason=result.exception_reason;}
  await refresh();
  toast(result.message);
 }catch(error){state.error=error.message;}
 finally{state.saving=false;render();if(state.error){$('#rules-save-error').textContent=state.error;delete state.error;}}
}
async function ruleCommand(type,id){
 if(type==='site-rules')return selectRuleSite(id);
 if(type==='retry-rules'){ruleCatalogError='';ensureRuleCatalog();return render();}
 if(type==='save-rules')return saveRuleSelection();
 if(type==='reload-rules')return dialog('Tải lại rule','<p>Bỏ lựa chọn chưa lưu và đọc lại bản nháp mới nhất của website.</p>',async()=>{const id=ruleEditor.siteId;data=await api('/api/overview');ruleEditor=null;selectRuleSite(id)},'Tải lại');
 if(type==='inspect-rule'){
  const rule=await api('/api/rules/'+id);
  return dialog(`Rule ${rule.id}`,`<p><strong>${esc(rule.description)}</strong></p><p>${esc(rule.version)} · ${esc(rule.group_label)} · ${rule.pl?'PL '+rule.pl:'Rule hệ thống'} · Phase ${rule.phase} · ${esc(rule.severity||'—')}</p><p class="small">${esc(rule.file)}:${rule.line} · ${rule.chain_length} điều kiện trong chuỗi</p><p class="small">Tags: ${esc(rule.tags.join(', '))}</p><pre>${esc(rule.source)}</pre><p class="small">Nội dung gốc chỉ để xem. Lựa chọn bật/tắt được lưu theo website.</p>`,async()=>{},'Đóng');
 }
}
document.querySelector('#main').addEventListener('input',event=>{
 if(!ruleEditor)return;
 if(event.target.id==='rules-search'){ruleEditor.query=event.target.value;ruleEditor.page=1;refreshRuleResults();}
 if(event.target.id==='rules-reason'){ruleEditor.reason=event.target.value;ruleEditor.dirty=true;}
});
document.querySelector('#main').addEventListener('change',event=>{
 if(!ruleEditor||ruleEditor.saving)return;
 const input=event.target;
 if(input.id==='rules-site')return selectRuleSite(input.value);
 const filters={'rules-group':'group','rules-pl':'pl','rules-state':'state'};
 if(filters[input.id]){ruleEditor[filters[input.id]]=input.value;ruleEditor.page=1;return refreshRuleResults();}
 if(input.matches('[data-rule-toggle]')&&canEdit()){
  const id=Number(input.dataset.ruleToggle),rule=allCatalogRules().find(rule=>rule.id===id);
  if(!rule?.selectable&&!ruleEditor.excluded.has(id))return;
  if(input.checked)ruleEditor.excluded.delete(id);else ruleEditor.excluded.add(id);
  ruleEditor.dirty=true;refreshRuleResults();$(`[data-rule-toggle="${id}"]`)?.focus();
 }
});
document.querySelector('#main').addEventListener('click',event=>{
 const button=event.target.closest('[data-rules-page]');
 if(button&&!button.disabled){ruleEditor.page=Number(button.dataset.rulesPage);refreshRuleResults();}
});
