// UI-only external states. Invoked by case-review-batches.browser.cjs after
// its real synthetic flow. Every fixture write is intercepted: ZERO sends.
const assert=require('node:assert/strict');
module.exports=async function externalBatchStates(page,cid,seed,packetSeed,out){
 await page.evaluate(async({cid,seed,packetSeed})=>{
  window.batchOriginalAPI=api;window.batchWrites=[];window.batchReads=[];
  window.batchProvider={configured:true,allowed:false,egress_level:'none',privacy_contract:seed.privacy_contract,events:181,local:false,destination:'synthetic-external.invalid',model:'synthetic-ui-only',source_fingerprint:'fixture-source'};
  window.batchFixture={...seed,id:'synthetic-external-plan',plan_key:'key-1',provider_binding:'provider-1',state:'planned',local:false,destination:batchProvider.destination,model:batchProvider.model,egress_level:'none',total_batches:12,enabled_batches:12};
  window.batchPacket={...packetSeed,state:'succeeded',raw_answer:'<img src=x onerror="window.batchXSS=true"> UNTRUSTED SYNTHETIC ANSWER',sentences:[{text:'Synthetic fixture commentary only.',cites:[{kind:'coverage',id:'selection'},{kind:'correlation',id:'missing-correlation'},{kind:'coverage',id:'missing-source'}]}]};
  const b=`/cases/${cid}/enrich/case-review/batches`;
  api=async(p,opts)=>{
   if(p===`/cases/${cid}/enrich/case-review`)return batchProvider;
   if(p===`/cases/${cid}/egress`){const e=await batchOriginalAPI(p,opts);return {...e,level:batchProvider.egress_level};}
   if(p.startsWith(b)){
    if(opts?.method){batchWrites.push({p,opts});if(p.endsWith('/plan')){batchFixture={...batchFixture,id:batchFixture.id+'-new',plan_key:batchFixture.plan_key+'-new',egress_level:batchProvider.egress_level};return structuredClone(batchFixture);}throw Error('Synthetic start refusal: stale provider binding; build a new plan');}
    batchReads.push(p);
    if(p.includes('/history'))return {plans:[structuredClone(batchFixture)],total:1,has_more:false};
    if(p.endsWith('/payload'))return {payload:batchPacket.payload,privacy:batchPacket.privacy,attempted:true,state:batchPacket.state};
    if(p.includes('/packets?')){const after=Number(new URLSearchParams(p.split('?')[1]).get('after'));return {packets:Array.from({length:Math.min(10,12-after-1)},(_,i)=>({...batchPacket,seq:after+i+1,namespace:'fixture-packet-'+(after+i+1)}))};}
    if(window.batchDeferred){await new Promise(r=>window.batchRelease=r);}
    return structuredClone(batchFixture);
   }
   if(p.includes('/sources/missing-source/'))throw Error('Synthetic source missing');
   if(p.endsWith('/correlations'))return [];
   return batchOriginalAPI(p,opts);
  };
  await renderExternalTab(document.querySelector('#tab-content'),cid);
 },{cid,seed,packetSeed});
 // The previous real selection remains intentionally selected until a deliberate
 // new plan. Reopen/reload the tab only for this independent synthetic fixture.
 await page.evaluate(async cid=>{document.querySelector('#batch-review').remove();mountBatchReview(document.querySelector('#external-review'),cid,batchProvider);},cid);
 await page.locator('#batch-review > summary').click();await page.waitForSelector('#br-run-id');
 assert.equal(await page.locator('#br-start').isDisabled(),true,'External policy none blocks even a checked receipt');
 await page.check('#br-ack');assert.equal(await page.locator('#br-start').isDisabled(),true);
 assert.deepEqual(await page.evaluate(()=>batchWrites),[]);
 await page.evaluate(async cid=>{batchProvider.allowed=true;batchProvider.egress_level='pseudonymized';await renderExternalTab(document.querySelector('#tab-content'),cid,true);},cid);
 assert.equal(await page.locator('#br-ack').isChecked(),false,'Policy changes revoke consent');
 await page.click('#br-build');await page.waitForFunction(()=>document.querySelector('#br-run-id').textContent.endsWith('-new'));
 assert.equal(await page.locator('#br-start').isDisabled(),true,'External start must wait for explicit current-plan approval');
 await page.check('#br-ack');assert.equal(await page.locator('#br-start').isEnabled(),true);
 await page.fill('#br-requests','3');await page.locator('#br-ack').focus();
 await page.evaluate(async cid=>{await renderExternalTab(document.querySelector('#tab-content'),cid,true)},cid);
 assert.equal(await page.locator('#br-ack').isChecked(),true,'Same provider/policy polling preserves matching-plan consent');
 assert.equal(await page.evaluate(()=>document.activeElement.id),'br-ack','Same-provider polling preserves focus');
 assert.equal(await page.inputValue('#br-requests'),'3');
 const first=page.locator('#br-packets .batch-packet').first();await first.locator(':scope > summary').click();await first.locator('.batch-payload-button').click();await first.locator('.batch-payload').waitFor({state:'visible'});
 await first.locator('.batch-raw > summary').click();assert.match(await first.locator('.batch-raw pre').innerText(),/<img/);assert.equal(await first.locator('.batch-raw img').count(),0);assert.equal(await page.evaluate(()=>!!window.batchXSS),false,'Raw answer must never execute');
 await first.locator('[data-source-id="missing-correlation"]').click();await page.waitForFunction(()=>document.querySelector('dialog')?.textContent.includes('Source unavailable'));await page.keyboard.press('Escape');
 await first.locator('[data-source-id="missing-source"]').click();await page.waitForFunction(()=>document.querySelector('dialog')?.textContent.includes('Synthetic source missing'));await page.keyboard.press('Escape');
 await page.click('#br-packets-next');await page.waitForFunction(()=>document.querySelector('#br-packets .batch-packet').dataset.seq==='10');assert.equal(await page.locator('#br-packets .batch-packet').count(),2);
 await page.click('#br-packets-first');await page.waitForFunction(()=>document.querySelector('#br-packets .batch-packet').dataset.seq==='0');
 await page.click('#br-build');await page.waitForFunction(()=>document.querySelector('#br-run-id').textContent.endsWith('-new-new'));assert.equal(await page.locator('#br-ack').isChecked(),false,'Changed plan cannot inherit approval');
 await page.check('#br-ack');await page.click('#br-start');await page.waitForFunction(()=>document.querySelector('#br-message').textContent.includes('Synthetic start refusal'));assert.equal(await page.locator('#br-ack').isChecked(),false,'Start refusal revokes consent');assert.equal(await page.locator('#br-start').isDisabled(),true);
 await page.check('#br-ack');await page.evaluate(async()=>{batchFixture.plan_key='changed-key';await document.querySelector('#br-refresh').click();});await page.waitForFunction(()=>!document.querySelector('#br-ack').checked);assert.equal(await page.locator('#br-start').isDisabled(),true,'Changed key revokes consent');
 await page.check('#br-ack');await page.evaluate(async cid=>{batchProvider.model='changed-provider-model';await renderExternalTab(document.querySelector('#tab-content'),cid,true)},cid);assert.equal(await page.locator('#br-ack').isChecked(),false,'Changed provider revokes consent');
 await page.evaluate(()=>{batchFixture.state='interrupted';batchFixture.reason='Synthetic restart fixture: no automatic resend';});await page.click('#br-refresh');await page.waitForFunction(()=>document.querySelector('#br-status strong').textContent==='interrupted');assert.equal(await page.locator('#br-start').isDisabled(),true);
 await page.screenshot({path:out+'/batch-external-interrupted.png',fullPage:true});
 await page.evaluate(()=>{batchDeferred=true;});await page.click('#br-refresh');await page.waitForFunction(()=>typeof batchRelease==='function');
 await page.evaluate(()=>{document.querySelector('#tab-content').innerHTML='<p id="batch-other-tab">Other tab sentinel</p>';batchRelease();});await page.waitForTimeout(100);assert.equal(await page.locator('#batch-other-tab').count(),1);assert.equal(await page.locator('#br-plan').count(),0,'Late run response must not repaint another tab');
 const writes=await page.evaluate(()=>batchWrites);assert.ok(writes.length>0);assert.ok(writes.every(w=>w.p.endsWith('/plan')||w.p.endsWith('/start')));
 console.log('PASS external UI fixtures: zero sends, blocked/no-ack, same-provider focus and budget preservation, plan/key/provider/policy invalidation, start refusal, raw text safety, missing sources, packet paging, interrupted and late-response isolation');
};
