// Mocked lifecycle API: checks interactions and responsive UI without touching WAF.
const {chromium}=require('playwright');
const assert=require('assert');
(async()=>{
 const browser=await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
 const errors=[];
 for(const viewport of [{width:1440,height:1000},{width:390,height:844}]){
  const p=await browser.newPage({viewport});p.on('pageerror',e=>errors.push(e.message));
  let stage='draft',role='admin';const writes=[];
  function overview(){
   const applied=stage==='complete',active=['canary','rollout'].includes(stage)?{id:3,revision_id:7,state:stage,kind:'deploy'}:null;
   const nodes=[1,2].map(i=>({id:'waf-cluster-'+i,actual_revision:applied||i===1&&stage==='rollout'?7:6,desired_revision:7,online:true,health:'healthy',verified:true,matches_draft:applied||i===1&&stage==='rollout',applied:applied||i===1&&stage==='rollout',last_seen:'2026-11-10T00:00:00Z'}));
   const site={id:1,hostname:'example.test',backend_ip:'192.0.2.1',backend_port:3000,mode:'On',paranoia:1,enabled:true,excluded_rules:[],crs_settings:{}};
   return {server:'test',sites:[site],nodes,events:[],audit:[],policy_parameters:{},
    revisions:stage==='draft'?[]:[{id:7,note:'Thay đổi chế độ WAF',validated:true,approved_at:stage==='checked'?null:'now',created_at:'2026-11-10T00:00:00Z',digest:'a'.repeat(64)}],deployments:active?[active]:[],
    workflow:{stage,draft_digest:'a'.repeat(64),revision_id:stage==='draft'?null:7,nodes,applied,active_deployment:active,pending_sites:applied?0:1,sites:[{id:1,hostname:site.hostname,applied,nodes:nodes.map(n=>({id:n.id,matches:n.applied,applied:n.applied,changed_fields:n.applied?[]:['Chế độ WAF']}))}]}};
  }
  await p.route('**/api/**',async r=>{
   const path=new URL(r.request().url()).pathname;let body={};
   if(path==='/api/me')body={username:'test',role};
   if(path==='/api/overview')body=overview();
   if(r.request().method()==='POST'){
    writes.push({path,body:r.request().postDataJSON()});
    if(path==='/api/revisions'){stage='checked';body={id:7}}
    if(path.endsWith('/approve'))stage='approved';
    if(path.endsWith('/deploy'))stage='canary';
    if(path.endsWith('/abort'))stage='aborted';
   }
   await r.fulfill({json:body});
  });
  const url=process.env.WORKFLOW_TEST_URL||'http://127.0.0.1:19004/static/index.html';
  await p.goto(url);await p.locator('#main h1').waitFor();
  await p.locator('[data-page=sites]').click();await p.getByText('Nháp · chưa kiểm tra',{exact:true}).waitFor();
  await p.locator('[data-action=view-workflow]').click();assert.equal(await p.locator('.release-steps li').count(),5);
  await p.locator('[data-action=new-revision]').click();await p.locator('[name=note]').fill('Thay đổi chế độ WAF');await p.locator('#save-dialog').click();
  await p.getByText('Đã kiểm tra · chờ phê duyệt',{exact:true}).waitFor();
  assert.equal(writes[0].body.draft_digest,'a'.repeat(64));
  await p.locator('[data-action=approve]').click();await p.locator('#save-dialog').click();await p.getByText('Đã phê duyệt · sẵn sàng triển khai',{exact:true}).waitFor();
  await p.locator('[data-action=deploy]').click();assert((await p.locator('#editor').innerText()).includes('Node 2 tự động'));
  await p.locator('#save-dialog').click();await p.getByText('Đang thăm dò node 1',{exact:true}).waitFor();
  assert.equal(await p.locator('[data-action=promote]').count(),0);
  stage='rollout';await p.evaluate(()=>refresh());await p.getByRole('heading',{name:'Đang triển khai node 2',exact:true}).waitFor();
  assert.equal(await p.locator('.release-node .tag.good').count(),1);
  if(process.env.WORKFLOW_SCREENSHOT_DIR)await p.screenshot({path:`${process.env.WORKFLOW_SCREENSHOT_DIR}/workflow-${viewport.width}.png`,fullPage:true});
  stage='complete';await p.evaluate(()=>refresh());await p.getByText('Đã triển khai trên cả hai node',{exact:true}).waitFor();
  assert.equal(await p.locator('.release-steps .done').count(),5);
  assert.equal(await p.locator('.release-node .tag.good').count(),2);
  assert.equal(await p.locator('[data-action=deploy]').count(),0);
  stage='attention';await p.evaluate(()=>refresh());await p.getByText('Cần kiểm tra trạng thái node',{exact:true}).waitFor();
  assert.equal(await p.locator('[data-action=deploy]').count(),0);
  stage='aborted';await p.evaluate(()=>refresh());await p.getByText('Thử triển khai lại',{exact:true}).waitFor();
  assert(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  stage='checked';role='viewer';await p.reload();await p.locator('#main h1').waitFor();await p.locator('[data-page=revisions]').click();
  assert.equal(await p.locator('[data-action=approve]').count(),0);
  assert.equal(await p.locator('[data-action=deploy]').count(),0);
  await p.close();
 }
 assert.deepEqual(errors,[]);await browser.close();console.log(JSON.stringify({desktop:true,mobile:true,five_steps:true,full_interaction:true,auto_node_two:true,site_status:true,readonly:true,no_overflow:true,javascript_errors:errors}));
})().catch(e=>{console.error(e);process.exit(1)});
