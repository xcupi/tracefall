// Run ONLY against a disposable loopback server with a scratch data directory.
// Saves synthetic credentials, never a real API key. The test-connection route
// is intercepted in-browser; actual VT client behavior is tested with httptest.
// Usage: PLAYWRIGHT_MODULE=/path/to/playwright node tests/integrations.browser.cjs URL screenshots save|remove
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const [base,out,phase]=process.argv.slice(2);
if(!/^http:\/\/(127\.0\.0\.1|localhost):\d+$/.test(base)||!out||!['save','remove'].includes(phase))throw Error('Supply scratch loopback URL, output directory, and phase save/remove');
fs.mkdirSync(out,{recursive:true});
(async()=>{
 const browser=await chromium.launch({executablePath:process.env.CHROME_BIN||'/usr/bin/google-chrome',headless:true,args:['--no-sandbox']});
 const page=await browser.newPage({viewport:{width:1440,height:1000}});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 const replies=[];page.on('response',async r=>{if(r.url().includes('/api/admin/integrations/'))replies.push(await r.text().catch(()=>''));});
 const writes=[];page.on('request',r=>{if(r.url().includes('/api/admin/integrations/')&&r.method()!=='GET')writes.push(r.method());});
 try {
  await page.goto(base);
  await page.locator('#user-bar a[href="#/settings/integrations"]').click();
  await page.waitForSelector('#vt-key-input');
  assert.equal(await page.locator('#vt-key-input').getAttribute('type'),'password');
  if(phase==='remove'){
   assert.match(await page.locator('#vt-key-state').innerText(),/^Configured/);
   assert.equal(await page.locator('#vt-key-input').inputValue(),'');
   page.once('dialog',d=>d.accept());
   await page.click('#vt-key-remove');
   await page.waitForFunction(()=>document.querySelector('#vt-key-state')?.textContent.includes('Not configured'));
   const st=await page.evaluate(async()=>await (await fetch('/api/admin/integrations/virustotal')).json());
   assert.equal(st.configured,false);
   assert.equal(await page.locator('#vt-key-test').isDisabled(),true);
   console.log('PASS real restart restored saved key, empty masked field, Remove disabled configuration immediately, GET confirmed');
  }else{
   assert.match(await page.locator('#vt-key-state').innerText(),/Not configured/);
   assert.equal(await page.locator('#vt-key-test').isDisabled(),true);
   await page.fill('#vt-key-input','bad');await page.click('#vt-key-save');
   assert.deepEqual(writes,[],'invalid key must not be submitted');
   const synthetic='ab'.repeat(32);
   await page.fill('#vt-key-input',synthetic);
   await page.click('#vt-key-save');
   await page.waitForFunction(()=>document.querySelector('#vt-settings-msg')?.textContent.includes('Key saved and active'));
   assert.equal(await page.locator('#vt-key-input').inputValue(),'');
   assert.match(await page.locator('#vt-key-state').innerText(),/^Configured/);
   assert.deepEqual(writes,['PUT']);
   const st=await page.evaluate(async()=>await (await fetch('/api/admin/integrations/virustotal')).json());
   assert.deepEqual(st,{configured:true,source:'saved',editable:true});
   assert.equal(await page.evaluate(s=>document.documentElement.innerHTML.includes(s)||JSON.stringify(localStorage).includes(s)||JSON.stringify(sessionStorage).includes(s),synthetic),false);
   assert.equal(replies.some(s=>s.includes(synthetic)),false,'API reflected saved credential');
   // UI test only: this route must NEVER reach the live service with a dummy key.
   let tests=0;
   await page.route('**/api/admin/integrations/virustotal/test',async route=>{
    tests++;assert.deepEqual(route.request().postDataJSON(),{acknowledge:true});
    await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({ok:true,message:'Synthetic UI connection result — no external call'})});
   });
   assert.equal(await page.locator('#vt-key-test').isDisabled(),true);
   await page.check('#vt-test-ack');
   await page.click('#vt-key-test');
   await page.waitForFunction(()=>document.querySelector('#vt-settings-msg')?.textContent.includes('Synthetic UI connection result'));
   assert.equal(tests,1);assert.equal(await page.locator('#vt-test-ack').isChecked(),false);
   await page.screenshot({path:out+'/vt-settings-desktop.png',fullPage:true});
   await page.setViewportSize({width:390,height:844});await page.waitForTimeout(350);
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
   await page.screenshot({path:out+'/vt-settings-mobile.png',fullPage:true});
   await page.reload();await page.waitForSelector('#vt-key-input');
   assert.equal(await page.locator('#vt-key-input').inputValue(),'');
   assert.match(await page.locator('#vt-key-state').innerText(),/^Configured/);
   console.log('PASS global Settings link, password field, invalid-key validation, real Save + GET, no secret reflection/browser storage, explicit test consent with mocked response, reload, desktop/mobile layout');
   console.log('Synthetic key left in scratch storage for the real restart/remove phase');
  }
  assert.deepEqual(errors,[]);
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
