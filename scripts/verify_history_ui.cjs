// Isolated browser checks with mocked API data; no cluster changes.
const {chromium}=require('playwright');
const assert=require('assert');
(async()=>{
 const browser=await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
 const errors=[];
 for(const viewport of [{width:1440,height:1000},{width:390,height:844}]){
  const page=await browser.newPage({viewport});page.on('pageerror',e=>errors.push(e.message));
  const requests=[];
  await page.route('**/api/**',async route=>{
   const url=new URL(route.request().url());let body={};
   if(url.pathname==='/api/me')body={username:'viewer',role:'viewer'};
   if(url.pathname==='/api/overview')body={sites:[],nodes:[],events:[],audit:[],revisions:[],deployments:[],server:'test'};
   if(url.pathname.startsWith('/api/history/')){
    requests.push(url);
    const waf=url.pathname.endsWith('/waf'),q=url.searchParams.get('q'),n=Number(url.searchParams.get('page'));
    const event={id:7,created_at:'2026-11-10T00:00:00Z',node_id:'node-1',site_id:1,hostname:'example.test',request_host:'example.test',request_uri:'/search?q=%3Cscript%3E&tag=a&tag=b',request_method:'POST',request_protocol:'HTTP/2.0',rule_ids:[942100],client_ip:'192.0.2.1',interrupted:true,event_key:'node-1:tx'};
    body={items:q==='missing'?[]:waf?[event,{...event,id:8,request_uri:'',request_method:''}]:[{id:1,actor:'admin',action:'site.create',detail:{hostname:'<img src=x onerror=alert(1)>'},created_at:event.created_at}],total:q==='missing'?0:30,page:n,pages:2};
   }
   await route.fulfill({json:body});
  });
  await page.goto(process.env.HISTORY_TEST_URL||'http://127.0.0.1:19003/static/index.html');
  await page.locator('#main h1').waitFor();
  await page.locator('[data-page=events]').click();await page.locator('[data-action=event-detail]').first().waitFor();
  assert.equal(await page.locator('#main').getByText('Audit quản trị',{exact:true}).count(),0);
  assert((await page.locator('#history-results').innerText()).includes('Chưa có URL'));
  await page.locator('[data-action=event-detail]').first().click();
  assert((await page.locator('#editor').innerText()).includes('<script>'));
  assert.equal(await page.locator('#editor dd').filter({hasText:'/search?q=%3Cscript%3E&tag=a&tag=b'}).count(),1);
  assert.equal(await page.locator('#editor script').count(),0);
  assert.equal(await page.locator('#editor tbody tr').count(),3);
  await page.locator('#cancel-dialog').click();
  await page.locator('#history-search input').fill('/search?q=');await page.locator('#history-search button[type=submit]').click();
  await page.waitForFunction(()=>document.querySelector('.history-count')?.textContent.includes('khớp tìm kiếm'));
  assert.equal(requests.at(-1).searchParams.get('q'),'/search?q=');
  await page.locator('[data-history-page="2"]').click();await page.getByText('Trang 2 / 2',{exact:true}).waitFor();
  await page.locator('[data-page=audit]').click();await page.locator('#history-results').getByText('site.create').waitFor();
  assert.equal(await page.locator('#history-results img').count(),0);
  await page.locator('#history-search input').fill('missing');await page.locator('#history-search button[type=submit]').click();await page.getByText('Không tìm thấy bản ghi phù hợp.').waitFor();
  await page.locator('[data-page=events]').click();assert.equal(await page.locator('#history-search input').inputValue(),'/search?q=');
  await page.getByText('Trang 2 / 2',{exact:true}).waitFor();
  await page.locator('[data-history-reset]').click();await page.getByText('Trang 1 / 2',{exact:true}).waitFor();
  assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  if(process.env.HISTORY_SCREENSHOT_DIR)await page.screenshot({path:`${process.env.HISTORY_SCREENSHOT_DIR}/history-${viewport.width}.png`,fullPage:true});
  await page.close();
 }
 assert.deepEqual(errors,[]);await browser.close();console.log(JSON.stringify({tabs:true,search:true,pagination:true,url_details:true,legacy:true,escaped_html:true,mobile:true,errors}));
})().catch(e=>{console.error(e);process.exit(1)});
