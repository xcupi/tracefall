// Synthetic UI-only states on a disposable server; sends NO model request.
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');const assert=require('node:assert/strict');
const base=process.argv[2];if(!/^http:\/\/127\.0\.0\.1:\d+$/.test(base))throw Error('Disposable loopback URL required');
(async()=>{const browser=await chromium.launch({executablePath:'/usr/bin/google-chrome',headless:true,args:['--no-sandbox']});const page=await browser.newPage({viewport:{width:1440,height:1000}});
try{
await page.goto(base);const cid=await page.evaluate(async()=>{const r=await fetch('/api/cases',{method:'POST',headers:{'Content-Type':'application/json','X-Tracefall-Client':'dashboard'},body:JSON.stringify({name:'Synthetic review UI states '+Date.now()})});return(await r.json()).id});await page.goto(`${base}/#/cases/${cid}/external`);await page.waitForSelector('#ext-root');
await page.evaluate(async cid=>{
 window.reviewOriginalAPI=api;window.reviewWrites=[];
 window.rvFixture={configured:true,allowed:true,events:200,local:false,destination:'synthetic-provider.invalid',model:'synthetic-model',source_fingerprint:'source-a',latest:{status:'ok',coverage:{events_total:200,events_included:120,events_omitted:80},sentences:[{text:'Synthetic anchored lead, not real evidence.',cites:[{kind:'correlation',id:'corr-full-id'},{kind:'correlation',id:'missing-correlation'},{kind:'coverage',id:'missing-source'}]}]}};
 api=async(path,opts)=>{
  if(opts?.method){reviewWrites.push({path,opts});throw Error('No sends in UI-only fixture');}
  if(path.endsWith('/enrich/case-review'))return rvFixture;
  if(path.endsWith('/enrich/case-review/preview'))return {system:'Synthetic instructions',user:'Synthetic bounded packet',sha256:'payload-a',preview_key:'preview-a',source_fingerprint:rvFixture.source_fingerprint,coverage:{events_total:200,events_included:120,events_omitted:80}};
  if(path.endsWith('/correlations'))return [{correlation_id:'corr-full-id',title:'Synthetic correlation',description:'Synthetic description',event_ids:['missing-event']}];
  if(path.includes('/sources/'))throw Error('Synthetic source is missing');
  return reviewOriginalAPI(path,opts);
 };
 await renderExternalTab(document.querySelector('#tab-content'),cid);
},cid);
assert.equal(await page.locator('#rv-caps').count(),1,'Request caps must be visible without opening a disclosure');
assert.equal(await page.locator('#rv-caps').isVisible(),true);
assert.ok(await page.locator('#external-review').evaluate(e=>e.clientWidth>=600),'Desktop review must use the full card width like Summary');
await page.click('#rv-preview');await page.waitForSelector('#rv-preview-box:visible');await page.check('#rv-ack');await page.locator('#rv-ack').focus();
await page.evaluate(async cid=>{await renderExternalTab(document.querySelector('#tab-content'),cid,true)},cid);
assert.equal(await page.locator('#rv-ack').isChecked(),true,'Polling must preserve consent bound to the same provider/selection');
assert.equal(await page.locator('#rv-preview-box').isVisible(),true,'Polling must preserve inspected preview');assert.equal(await page.locator('#rv-start').isEnabled(),true);
assert.equal(await page.evaluate(()=>document.activeElement.id),'rv-ack');
await page.evaluate(async cid=>{rvFixture.destination='different.invalid';await renderExternalTab(document.querySelector('#tab-content'),cid,true)},cid);
assert.equal(await page.locator('#rv-ack').isChecked(),false,'New destination cannot inherit consent');assert.equal(await page.locator('#rv-start').isDisabled(),true);
await page.click('#rv-preview');await page.check('#rv-ack');
await page.evaluate(async cid=>{rvFixture.source_fingerprint='source-b';await renderExternalTab(document.querySelector('#tab-content'),cid,true)},cid);
assert.equal(await page.locator('#rv-preview-box').isVisible(),false,'Changed parsed inputs must hide old preview');assert.equal(await page.locator('#rv-start').isDisabled(),true);
await page.locator('[data-source-id="corr-full-id"]').click();await page.waitForSelector('dialog h3');assert.match(await page.locator('dialog').innerText(),/Synthetic correlation/);await page.keyboard.press('Escape');
await page.locator('[data-source-id="missing-correlation"]').click();await page.waitForFunction(()=>document.querySelector('dialog')?.textContent.includes('Source unavailable'));await page.keyboard.press('Escape');
await page.locator('[data-source-id="missing-source"]').click();await page.waitForFunction(()=>document.querySelector('dialog')?.textContent.includes('Synthetic source is missing'));await page.keyboard.press('Escape');
assert.deepEqual(await page.evaluate(()=>reviewWrites),[]);
console.log('PASS UI-only synthetic review: desktop width, polling preview/consent/focus, changed destination/input invalidation, correlation and missing source drill-down; zero sends');
}finally{await browser.close()}})().catch(e=>{console.error(e);process.exitCode=1});
