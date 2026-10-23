// Disposable loopback server ONLY, with tests' synthetic Codex stand-in.
// Never run this recipe against a real authorization/model CLI.
// PLAYWRIGHT_MODULE=/scratch/tools/node_modules/playwright node tests/chatgpt.browser.cjs URL OUT CONTROL [restart]
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const [base,out,control,phase]=process.argv.slice(2);
if(!/^http:\/\/(127\.0\.0\.1|localhost):\d+$/.test(base)||!out||!control)throw Error('Supply disposable loopback URL, screenshots, synthetic stand-in control directory');
if(fs.readFileSync(path.join(control,'synthetic-only'),'utf8').trim()!=='tracefall-browser-synthetic-codex')throw Error('Synthetic CLI marker required');
fs.mkdirSync(out,{recursive:true});
const calls=()=>fs.existsSync(path.join(control,'calls'))?fs.readFileSync(path.join(control,'calls'),'utf8'):'';
(async()=>{
 const browser=await chromium.launch({executablePath:process.env.CHROME_BIN||'/usr/bin/google-chrome',headless:true,args:['--no-sandbox']});
 const page=await browser.newPage({viewport:{width:1440,height:1100}});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 try{
  const before=calls().length;
  await page.goto(base+'/#/settings/integrations');await page.waitForSelector('#chatgpt-authorize');
  // A real CLI/server cannot update this local stand-in-only log. Fail BEFORE
  // any state-changing request unless this server actually ran our fake status.
  assert.ok(calls().length>before,'server did not use synthetic CLI; refusing authorization');
  const state=()=>page.locator('#chatgpt-state').innerText();
  if(phase==='restart'){
   assert.match(await state(),/Signed in/);assert.match(await state(),/Request not verified/);
   assert.equal(await page.locator('#chatgpt-provider').inputValue(),'codex-cli');
   assert.match(await page.locator('#chatgpt-effective-provider').innerText(),/codex-cli/);
   page.once('dialog',d=>d.dismiss());await page.click('#chatgpt-disconnect');assert.match(await state(),/Signed in/);
   page.once('dialog',d=>d.accept());await page.click('#chatgpt-disconnect');
   await page.waitForFunction(()=>document.querySelector('#chatgpt-state')?.textContent.includes('Not connected'));
   assert.equal((await page.evaluate(async()=>await(await fetch('/api/admin/integrations/chatgpt')).json())).request_verified,false);
   fs.writeFileSync(path.join(control,'fail-auth'),'synthetic failure');
   await page.click('#chatgpt-authorize');await page.waitForFunction(()=>document.querySelector('#chatgpt-state')?.textContent.includes('failed'));
   assert.equal((await page.locator('#chatgpt-settings-content').innerText()).includes('SECRET-RAW'),false);
   await page.screenshot({path:out+'/chatgpt-failed-desktop.png',fullPage:true});
   fs.unlinkSync(path.join(control,'fail-auth'));
   // Renderer-only status fixtures: real deadline/cancel behavior is proved by
   // Go subprocess tests, not by waiting 15 minutes or contacting OpenAI here.
   await page.route('**/api/admin/integrations/chatgpt',async route=>{
    if(route.request().method()!=='GET')throw Error('No writes in renderer-only fixture');
    await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({state:'expired',available:true,busy:false,request_verified:false,preference:'codex-cli',effective_provider:'openai-compatible',environment_managed:true})});
   });
   await page.reload();await page.waitForSelector('#chatgpt-authorize');
   assert.match(await state(),/expired/);assert.equal(await page.locator('#chatgpt-provider').isDisabled(),true);
   assert.match(await page.locator('#chatgpt-settings-content').innerText(),/TRACEFALL_LLM_PROVIDER/);
   await page.screenshot({path:out+'/chatgpt-expired-env-renderer.png',fullPage:true});
   console.log('PASS restart preserved provider + CLI status, verification reset, disconnect dismissal/confirmation + GET; real stand-in failure sanitization; expired/environment renderer-only fixtures');
  }else{
   assert.match(await state(),/Not connected/);assert.equal(await page.locator('#chatgpt-verify').isDisabled(),true);
   assert.ok(!calls().includes('|exec '),'page load sent model request');
   await page.click('#chatgpt-authorize');await page.waitForSelector('#chatgpt-user-code');
   assert.equal(await page.locator('#chatgpt-user-code').innerText(),'ABCD-12345');
   assert.equal(await page.locator('#chatgpt-official-link').getAttribute('href'),'https://auth.openai.com/codex/device');
   await page.focus('#chatgpt-cancel');await page.waitForTimeout(1800);
   assert.equal(await page.evaluate(()=>document.activeElement.id),'chatgpt-cancel','polling lost keyboard focus');
   await page.screenshot({path:out+'/chatgpt-waiting-desktop.png',fullPage:true});
   await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
   await page.screenshot({path:out+'/chatgpt-waiting-mobile.png',fullPage:true});await page.setViewportSize({width:1440,height:1100});
   await page.click('#chatgpt-cancel');await page.waitForFunction(()=>document.querySelector('#chatgpt-state')?.textContent.includes('cancelled'));
   assert.equal(await page.locator('#chatgpt-user-code').count(),0);
   await page.click('#chatgpt-authorize');await page.waitForSelector('#chatgpt-user-code');
   fs.writeFileSync(path.join(control,'approve'),'synthetic authorization only');
   await page.waitForFunction(()=>document.querySelector('#chatgpt-state')?.textContent.includes('Signed in'));
   assert.match(await state(),/Request not verified/);assert.ok(!calls().includes('|exec '),'authorize sent model request');
   await page.selectOption('#chatgpt-provider','codex-cli');await page.click('#chatgpt-provider-save');
   await page.waitForFunction(()=>document.querySelector('#chatgpt-effective-provider')?.textContent==='codex-cli');
   assert.equal(await page.locator('#chatgpt-verify').isDisabled(),true);await page.check('#chatgpt-verify-ack');await page.click('#chatgpt-verify');
   await page.waitForFunction(()=>document.querySelector('#chatgpt-state')?.textContent.includes('· Request verified'));
   assert.equal(await page.locator('#chatgpt-verify-ack').isChecked(),false);
   assert.match(fs.readFileSync(path.join(control,'prompt'),'utf8'),/TRACEFALL_TEST_OK/);
   assert.equal(await page.evaluate(()=>JSON.stringify(localStorage).includes('ABCD-12345')||JSON.stringify(sessionStorage).includes('ABCD-12345')),false);
   await page.screenshot({path:out+'/chatgpt-signed-in-desktop.png',fullPage:true});
   await page.setViewportSize({width:390,height:844});await page.waitForTimeout(200);
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
   await page.screenshot({path:out+'/chatgpt-signed-in-mobile.png',fullPage:true});
   await page.reload();await page.waitForSelector('#chatgpt-authorize');assert.match(await state(),/Request verified/);
   assert.equal(await page.locator('#chatgpt-verify-ack').isChecked(),false);
   console.log('PASS synthetic actual endpoints: waiting official URL/code, focus polling, cancel, authorize (no exec), select provider, acknowledged fake model verification, no code browser storage, reload, desktop/mobile');
  }
  assert.deepEqual(errors,[]);
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
