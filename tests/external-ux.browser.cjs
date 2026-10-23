// Browser regression checks against a scratch Tracefall server, never a real case.
// Usage: PLAYWRIGHT_MODULE=/path/to/playwright node tests/external-ux.browser.cjs http://127.0.0.1:18463 /absolute/output-dir
// Uses synthetic responses only for enrichment states, never calls a provider.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const base = process.argv[2];
const output = process.argv[3];
if (!base || !output || !/^http:\/\/(127\.0\.0\.1|localhost):\d+$/.test(base)) throw Error('Pass a scratch loopback server URL and screenshot output directory');
fs.mkdirSync(output, {recursive:true});
(async () => {
 const browser = await chromium.launch({executablePath:process.env.CHROME_BIN || '/usr/bin/google-chrome',headless:true,args:['--no-sandbox']});
 const page = await browser.newPage({viewport:{width:1440,height:1000}});
 const errors=[];
 page.on('pageerror',e=>errors.push(e.message));
 try {
 await page.goto(base);
 await page.waitForSelector('#app');
 const cid = await page.evaluate(async () => {
   const r=await fetch('/api/cases',{method:'POST',headers:{'Content-Type':'application/json','X-Tracefall-Client':'dashboard'},body:JSON.stringify({name:'UI regression — synthetic '+Date.now(),description:'No evidence or external calls'})});
   if(r.status!==201) throw Error('Create scratch case failed: '+r.status);
   return (await r.json()).id;
 });
 await page.goto(`${base}/#/cases/${cid}/external`);
 await page.waitForSelector('#ext-root');
 assert.equal(await page.locator('.external-card').count(),4);
 await page.locator('#nv-setup').evaluate(e=>e.open=true);
 assert.match(await page.locator('#nv-setup').innerText(),/codex-cli/);
 await page.screenshot({path:output+'/services-unconfigured.png',fullPage:true});
 await page.goto(`${base}/#/cases/${cid}/overview`);
 await page.waitForSelector('#add-evidence-btn');
 await page.click('#add-evidence-btn');
 const accept = await page.locator('#upload-file').getAttribute('accept');
 for(const ext of ['.vhd,','.vhdx,','.vmdk,','.vmem,']) assert.ok(accept.includes(ext));
 assert.equal(await page.locator('#ingest-path').inputValue(),'');
 console.log('PASS real app: empty providers, setup, virtual-disk picker, no default sample path');
 // Intercept only the app's own API wrapper, in this test tab. No provider request.
 await page.goto(`${base}/#/cases/${cid}/external`);
 await page.waitForSelector('#ext-root');
 await page.evaluate(async cid => {
  window.uxOriginalAPI=api;
  window.uxCalls=[];
  window.uxFixture={
   level:'pseudonymized',
   options:[{level:'none',selectable:true,description:'Nothing leaves this server.'},{level:'hashes',selectable:true,description:'File hashes only.'},{level:'pseudonymized',selectable:true,description:'Pseudonymized facts for the model.'}],
   nv:{configured:true,allowed:true,local:false,destination:'chatgpt.com (through the Codex CLI)',model:'test-model',notice:'Synthetic notice: review data controls before sending.',findings:2,run:{state:'running'},latest:{status:'ok',created_at:'2026-01-01T00:00:00Z',destination:'test provider',model:'test-model',payload_sha256:'hash-a',sentences:[{text:'Synthetic summary — not real evidence.',cites:[{kind:'finding',id:'finding-full-id-1234567890'},{kind:'event',id:'event-full-id-1234567890'}]}],rejected:0}},
   vt:{status:{configured:true,allowed:true,candidates:4,pending:1,already_answered:3,remaining:10,daily_used:3,daily_limit:500,monthly_used:3,monthly_limit:1000,run:{state:'running',done:3,total:4,found:3,not_found:0,errors:0}},results:[{indicator_type:'sha256',indicator:'a'.repeat(64),status:'ok',source_event_ids:['event-full-id-1234567890','event-2','event-3','event-4','event-5'],fetched_at:'2026-01-01T00:00:00Z',result:{found:true,malicious:1,suspicious:0,harmless:20,undetected:40}}]}
  };
  api=async (path,opts)=>{
   window.uxCalls.push({path,method:opts?.method||'GET'});
   if(opts?.method) throw Error('No writes allowed in synthetic UI fixture');
   if(path.endsWith('/egress'))return {level:uxFixture.level,options:uxFixture.options};
   if(path.endsWith('/enrich/virustotal'))return uxFixture.vt;
   if(path.endsWith('/enrich/narrative/payload'))return {destination:'test provider',model:'test-model',sent_at:'2026-01-01',sha256:'hash-a',system:'Synthetic instructions',user:'Synthetic facts'};
   if(path.endsWith('/enrich/narrative'))return uxFixture.nv;
   if(path.endsWith('/enrich/case-review'))return {configured:false,events:0,scope:'bounded_partial_parsed_case'};
   if(path.includes('/findings/')&&path.endsWith('/provenance'))return {finding_id:'finding-full-id-1234567890',supporting_events:[]};
   if(path.includes('/findings/'))return {title:'Synthetic finding title',description:'Source detail from fixture, not evidence.',supporting_event_ids:['event-full-id-1234567890']};
   if(path.endsWith('/events/event-5')) throw Error('Synthetic unavailable event');
   if(path.includes('/events/')) return {event:{event_type:'process_execution',source_reference:'synthetic:1',extra:{}},source_file:{path:'synthetic/process.log',parser:'test reader'},raw_evidence:{raw:'Synthetic source record — not real evidence'},observations:[]};
   throw Error('Unexpected fixture endpoint: '+path);
  };
  await renderExternalTab(document.querySelector('#tab-content'),cid);
 },cid);
 assert.equal(await page.locator('#external-vt .table-wrap').evaluate(e=>e.scrollWidth<=e.clientWidth),true,'All VT columns should fit the desktop card');
 await page.check('#nv-ack');
 await page.locator('#nv-privacy').evaluate(e=>e.open=true);
 await page.locator('#vt-allowance').evaluate(e=>e.open=true);
 await page.click('summary:text("more supporting events")');
 await page.click('#nv-payload');
 await page.locator('#nv-ack').focus();
 await page.waitForTimeout(3500);
 assert.equal(await page.locator('#nv-ack').isChecked(),true);
 assert.equal(await page.locator('#nv-privacy').evaluate(e=>e.open),true);
 assert.equal(await page.locator('#vt-allowance').evaluate(e=>e.open),true);
 assert.equal(await page.locator('details[id^="vt-sources-"]').evaluate(e=>e.open),true);
 assert.equal(await page.locator('#nv-payload-box').isVisible(),true);
 assert.match(await page.locator('#nv-payload-box').innerText(),/Synthetic facts/);
 assert.equal(await page.evaluate(()=>document.activeElement.id),'nv-ack');
 console.log('PASS polling: consent, disclosure, expanded sources, payload and keyboard focus survive');
 await page.locator('#external-llm [data-source-kind="finding"]').click();
 await page.waitForSelector('dialog[open] h3');
 assert.match(await page.locator('dialog').innerText(),/Synthetic finding title/);
 assert.match(await page.locator('dialog .source-id').innerText(),/finding-full-id-1234567890/);
 await page.waitForTimeout(3500);
 assert.equal(await page.locator('dialog[open]').count(),1);
 await page.locator('dialog .source-link').click();
 await page.waitForSelector('dialog:last-of-type .external-source-body:text("Synthetic source record")');
 assert.match(await page.locator('dialog:last-of-type').innerText(),/event-full-id-1234567890/);
 await page.keyboard.press('Escape');
 await page.keyboard.press('Escape');
 assert.equal(await page.locator('dialog[open]').count(),0);
 await page.waitForFunction(()=>document.activeElement?.dataset.sourceId==='finding-full-id-1234567890',null,{timeout:3000});
 assert.equal(await page.evaluate(()=>document.activeElement.dataset.sourceId),'finding-full-id-1234567890','Closing after polling must return focus to the replacement source button');
 await page.locator('#external-vt [data-source-id="event-5"]').click();
 await page.waitForSelector('dialog .external-source-body:text("Synthetic unavailable event")');
 await page.keyboard.press('Escape');
 await page.waitForFunction(()=>!document.querySelector('dialog'));
 console.log('PASS sources: full finding ID, finding detail, raw event provenance, missing-source error, Escape, dialogs survive polling');
 await page.evaluate(async cid=>{uxFixture.nv.run.state='finished';uxFixture.vt.status.run.state='finished';await renderExternalTab(document.querySelector('#tab-content'),cid,true);},cid);
 await page.screenshot({path:output+'/services-populated.png',fullPage:true});
 // A different model/provider/policy cannot inherit an earlier acknowledgement.
 await page.evaluate(async cid=>{uxFixture.nv.destination='different-provider.invalid';await renderExternalTab(document.querySelector('#tab-content'),cid,true);},cid);
 assert.equal(await page.locator('#nv-ack').isChecked(),false);
 assert.equal(await page.locator('#nv-start').isDisabled(),true);
 console.log('PASS changed destination resets authorization');
 // A new payload hash must not retain the previous request body on screen.
 await page.evaluate(async cid=>{uxFixture.nv.latest.payload_sha256='hash-b';await renderExternalTab(document.querySelector('#tab-content'),cid,true);},cid);
 assert.equal(await page.locator('#nv-payload-box').isVisible(),false);
 // Late responses from the old tab cannot overwrite a new route.
 const staleSafe=await page.evaluate(async cid=>{
  const content=document.querySelector('#tab-content'); const orig=api;
  let release;const gate=new Promise(r=>release=r);
  api=async (...args)=>{await gate;return orig(...args)};
  const pending=renderExternalTab(content,cid,true);
  content.innerHTML='<p id="new-tab-marker">Different tab</p>';
  release();await pending;api=orig;
  return !!document.querySelector('#new-tab-marker');
 },cid);
 assert.equal(staleSafe,true);
 console.log('PASS changed payload is not mislabeled; late response does not overwrite another tab');
 // Render fixture once more for narrow-screen layout.
 await page.evaluate(async cid=>{await renderExternalTab(document.querySelector('#tab-content'),cid);},cid);
 await page.setViewportSize({width:390,height:844});
 await page.waitForTimeout(350);
 await page.evaluate(()=>scrollTo(0,0));
 assert.equal(await page.locator('#external-vt .table-wrap').evaluate(e=>e.scrollWidth<=e.clientWidth),true,'VT results should fit the mobile card without hidden columns');
 await page.screenshot({path:output+'/services-mobile.png',fullPage:true,animations:'disabled'});
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
 const unsafe=await page.evaluate(()=>uxCalls.filter(c=>c.method!=='GET'));
 assert.deepEqual(unsafe,[]);
 assert.deepEqual(errors,[]);
 console.log('PASS 390px viewport: no page overflow; no external-service writes; no JS exceptions');
 } finally { await browser.close(); }
})().catch(e=>{console.error(e);process.exitCode=1;});
