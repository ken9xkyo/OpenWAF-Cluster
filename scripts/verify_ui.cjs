const { chromium } = require('playwright');
const fs = require('fs');
const assert = require('assert');
(async () => {
  const password = fs.readFileSync('/run/waf-admin.txt','utf8').split('\n').find(x=>x.startsWith('Password: ')).slice(10);
  const browser = await chromium.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});
  const context = await browser.newContext({viewport:{width:1440,height:1000},timezoneId:'Asia/Ho_Chi_Minh'});
  const page = await context.newPage();
  const errors=[];
  page.on('pageerror',e=>errors.push(e.message));
  await page.goto('http://127.0.0.1:9000/');
  await page.locator('#login-form input[name=username]').fill('admin');
  await page.locator('#login-form input[name=password]').fill(password);
  await page.locator('#login-form button[type=submit]').click();
  await page.locator('#main h1').filter({hasText:'Tổng quan cụm WAF'}).waitFor();
  await page.screenshot({path:'/artifacts/waf-control-desktop.png',fullPage:true});
  await page.locator('nav button[data-page=sites]').click();
  await page.locator('[data-action=edit-site]').first().click();
  assert.equal(await page.locator('#editor input[name=hostname]').inputValue(),'test-waf.vtccloud.vn');
  await page.locator('#cancel-dialog').click();
  for (const name of ['revisions','nodes','events','users']) {
    await page.locator(`nav button[data-page=${name}]`).click();
    await page.locator('#main h1').waitFor();
    assert((await page.locator('#main').innerText()).length>50);
  }
  await page.locator('nav button[data-page=overview]').click();
  const mobile = await browser.newContext({viewport:{width:390,height:844},storageState:await context.storageState(),timezoneId:'Asia/Ho_Chi_Minh'});
  const phone = await mobile.newPage();
  phone.on('pageerror',e=>errors.push(e.message));
  await phone.goto('http://127.0.0.1:9000/');
  await phone.locator('#main h1').waitFor();
  assert(await phone.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));
  await phone.screenshot({path:'/artifacts/waf-control-mobile.png',fullPage:true});
  assert.deepEqual(errors,[]);
  console.log(JSON.stringify({login:true,pages:6,site_editor:true,mobile_no_overflow:true,javascript_errors:errors},null,2));
  await browser.close();
})().catch(e=>{console.error(e.message);process.exit(1)});
