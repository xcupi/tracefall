// Synthetic stored-result UI fixtures: no backend/provider calls and no writes.
// PLAYWRIGHT_MODULE=/absolute/playwright node tests/review-vt-context.browser.cjs SCRATCH_OUTPUT
// Integrated read-only mode (no API mocks): append URL CASE_ID REVIEW_ID RUN_ID VT_ID.
// Parent seeds disposable DB + runs synthetic LLM separately; embedded assets must match.
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const [out,base,caseID,reviewID,runID,vtID]=process.argv.slice(2);
if(!path.isAbsolute(out||'')||!out.includes('/scratch/'))throw Error('Absolute scratch output required');
fs.mkdirSync(out,{recursive:true});
const assets=path.resolve(__dirname,'../internal/web/static'),source=fs.readFileSync(assets+'/app.js','utf8');
function extract(name){const start=source.indexOf('function '+name+'(');assert.ok(start>=0,name);const end=source.slice(start+1).search(/\n(?:async )?function /);return end<0?source.slice(start):source.slice(start,start+1+end);}
(async()=>{let browser;try{
 browser=await chromium.launch({executablePath:'/usr/bin/google-chrome',headless:true,args:['--no-sandbox']});
 const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[];page.setDefaultTimeout(5000);page.on('pageerror',e=>errors.push(e.message));
 if(base){
  assert.ok(/^http:\/\/127\.0\.0\.1:\d+$/.test(base)&&caseID&&reviewID&&runID&&vtID,'Explicit disposable loopback and seeded IDs required');
  for(const name of ['app.js','style.css'])assert.equal(await(await fetch(base+'/static/'+name)).text(),fs.readFileSync(assets+'/'+name,'utf8'),'Embedded asset '+name);
  const writes=[];await page.route('**/*',r=>{if(!['GET','HEAD'].includes(r.request().method())){writes.push(r.request().url());return r.abort();}return r.continue();});
  await page.goto(base+'/#/cases/'+encodeURIComponent(caseID)+'/external');await page.waitForSelector('#external-review');
  const singleURL=base+'/api/cases/'+encodeURIComponent(caseID)+'/enrich/case-review/'+encodeURIComponent(reviewID)+'/virustotal/'+encodeURIComponent(vtID);
  const singleResponse=page.waitForResponse(r=>r.url()===singleURL);
  await page.locator('#external-review [data-source-kind="enrichment"]').first().click();assert.ok((await singleResponse).ok(),'Frozen single DTO');await page.waitForSelector('dialog .stored-vt-source');
  assert.match(await page.locator('dialog').innerText(),/Outside opinion at lookup time/);await page.keyboard.press('Escape');await page.waitForSelector('dialog',{state:'detached'});
  await page.locator('#batch-review > summary').click();await page.waitForSelector('#br-run-id');assert.equal(await page.locator('#br-run-id').innerText(),runID);
  for(const [binding,id] of [['review-id',reviewID],['run-id',runID]]){
   const refs=page.locator('[data-source-kind="enrichment"]');
   const matches=await refs.evaluateAll((nodes,{binding,id,vtID})=>nodes.filter(n=>n.getAttribute('data-'+binding)===id&&n.dataset.sourceId===vtID).length,{binding,id,vtID});assert.ok(matches,'Seeded citation '+binding);
  }
  const packet=page.locator('#br-packets .batch-packet').filter({has:page.locator('[data-source-kind="enrichment"]')}).first();
  if(!await packet.evaluate(d=>d.open))await packet.locator(':scope > summary').click();
  const runURL=base+'/api/cases/'+encodeURIComponent(caseID)+'/enrich/case-review/batches/'+encodeURIComponent(runID)+'/virustotal/'+encodeURIComponent(vtID);
  const runResponse=page.waitForResponse(r=>r.url()===runURL);
  await packet.locator('[data-source-kind="enrichment"]').first().click();assert.ok((await runResponse).ok(),'Frozen run DTO');await page.waitForSelector('dialog .stored-vt-source');await page.keyboard.press('Escape');await page.waitForSelector('dialog',{state:'detached'});
  assert.equal(await page.locator('.external-card').count(),4);assert.deepEqual(writes,[]);
  await page.screenshot({path:out+'/integrated-desktop.png',fullPage:true});await page.setViewportSize({width:390,height:1000});await page.waitForTimeout(400);assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));await page.screenshot({path:out+'/integrated-mobile.png',fullPage:true});
  assert.deepEqual(errors,[]);console.log('PASS read-only seeded embedded-app VT inspection; seed/model execution is a separate parent gate');return;
 }
 await page.setContent('<main id="ext-root"><div id="single"></div><div id="batch"></div><div id="summary"></div></main>');
 await page.addStyleTag({path:assets+'/style.css'});
 const names=['esc','externalCitation','wireExternalCitations','renderReviewClaimGroups','renderCaseReviewSection','wireCaseReviewSection','mountBatchReview','renderNarrativeSection'];
 for(const name of ['renderStoredVTCoverage','renderStoredVTSource'])if(source.includes('function '+name+'('))names.push(name);
 await page.addScriptTag({content:names.map(extract).join('\n')+'\nfunction fmtTime(x){return x||"not recorded";}'});
 await page.evaluate(()=>{
  window.reads=[];window.writes=[];
  window.dto={id:'vt/full<&',provider:'virustotal',indicator_type:'sha256',indicator:'<img src=x onerror=alert(1)>',status:'found',fetched_at:'',verdicts_recorded:true,malicious:0,source_event_ids:['event/full<&'],scope:'review snapshot'};
  window.api=async(p,o)=>{if(o?.method){writes.push(p);throw Error('fixture refuses writes');}reads.push(p);if(p.includes('/virustotal/')){if(window.failVT||p.includes('wrong-context'))throw Object.assign(Error('SECRET RAW PROVIDER ERROR'),{status:404});return structuredClone(dto);}if(p.includes('/packets?'))return {packets:structuredClone(packets)};return structuredClone(plan);};
  // Provenance is outside this fixture's scope; verify exact ID and nested-dialog behavior.
  window.loadProvenanceInto=async(c,id,body)=>{reads.push('event:'+c+':'+id);body.textContent='Verified fixture source '+id;};
  window.rv={events:1,latest:{id:'review/full<&',status:'ok',coverage:{vt_recorded:true,vt_total:9,vt_included:2,vt_omitted:7,vt_invalid:1,vt_unlinked:3},sentences:[{kind:'hypothesis',text:'Synthetic outside opinion only',cites:[{kind:'enrichment',id:'vt/full<&'}]}]}};
  document.querySelector('#single').innerHTML=renderCaseReviewSection(rv);wireExternalCitations(document.querySelector('#single'),'case/full<&');
  window.plan={vt_recorded:true,id:'run/full<&',state:'succeeded',total_batches:1,synthesis_state:'succeeded',local:true,budget:{},progress:{primary_reviewed_events:1,distinct_successful_events:1},snapshot:{coverage:{vt_recorded:true,vt_total:9,vt_invalid:1,vt_unlinked:3}},vt_included:2,vt_omitted:7};
  window.packets=[{seq:0,kind:'event',state:'succeeded',coverage:{vt_recorded:true,vt_total:9,vt_included:1,vt_omitted:8},sentences:rv.latest.sentences},{seq:1,kind:'synthesis',state:'succeeded',coverage:{},sentences:rv.latest.sentences}];
  mountBatchReview(document.querySelector('#batch'),'case/full<&',{configured:false});
  document.querySelector('#summary').innerHTML=renderNarrativeSection({latest:{status:'ok',sentences:[{text:'Legacy findings only',cites:[{kind:'finding',id:'finding-original'}]}]}});
 });
 assert.equal(await page.locator('#single [data-source-kind="enrichment"]').count(),1,'Single renderer binds VT citation to latest.id');
 const single=page.locator('#single [data-source-kind="enrichment"]');await single.click();await page.waitForSelector('dialog .stored-vt-source');
 assert.ok((await page.evaluate(()=>reads)).includes('/cases/case%2Ffull%3C%26/enrich/case-review/review%2Ffull%3C%26/virustotal/vt%2Ffull%3C%26'),'Exact encoded frozen single URL');
 assert.ok((await page.locator('dialog').innerText()).includes('review/full<&'),'Dialog identifies exact single snapshot locally');
 assert.ok((await page.locator('dialog').innerText()).includes('case/full<&'),'Dialog identifies exact case locally');
 assert.match(await page.locator('dialog').innerText(),/Outside opinion at lookup time/);assert.match(await page.locator('dialog').innerText(),/time not recorded/);assert.match(await page.locator('dialog').innerText(),/malicious: 0/);assert.match(await page.locator('dialog').innerText(),/suspicious: not recorded/);assert.equal(await page.locator('dialog img').count(),0);
 await page.locator('dialog [data-source-kind="event"]').click();await page.waitForFunction(()=>document.querySelectorAll('dialog').length===2);await page.keyboard.press('Escape');await page.waitForFunction(()=>document.querySelectorAll('dialog').length===1);await page.waitForFunction(()=>document.activeElement?.dataset.sourceKind==='event');
 // Re-render the card as polling does; the detached-card dialog must survive.
 await page.evaluate(()=>{document.querySelector('#single').innerHTML=renderCaseReviewSection(rv);wireExternalCitations(document.querySelector('#single'),'case/full<&');});assert.equal(await page.locator('dialog[open]').count(),1);
 await page.keyboard.press('Escape');await page.waitForSelector('dialog',{state:'detached'});await page.waitForFunction(()=>document.activeElement?.dataset.sourceKind==='enrichment');
 for(const status of ['not_found','error','unusable','unknown']){
  await page.evaluate(s=>{dto.status=s;dto.verdicts_recorded=false;dto.source_event_ids=[];},status);await single.click();await page.waitForSelector('dialog .stored-vt-source');
  const text=await page.locator('dialog').innerText();assert.match(text,/not proof of safety/);assert.match(text,/Verdicts not recorded/);assert.match(text,/No verified source event references recorded/);assert.match(text,{not_found:/Not known to VirusTotal at lookup time/,error:/Stored lookup error/,unusable:/Stored result unusable/,unknown:/Status not recorded/}[status]);assert.ok(!text.includes('malicious: 0'));await page.keyboard.press('Escape');await page.waitForSelector('dialog',{state:'detached'});
 }
 await page.evaluate(()=>{window.failVT=true;});await single.click();await page.waitForFunction(()=>document.querySelector('dialog')?.textContent.includes('Frozen stored VirusTotal source unavailable'));assert.ok(!(await page.locator('dialog').innerText()).includes('SECRET'));await page.keyboard.press('Escape');await page.waitForSelector('dialog',{state:'detached'});await page.evaluate(()=>{window.failVT=false;dto.status='found';});
 // Wrong-context rejection is server-owned: an unavailable frozen endpoint must never fall back to live VT.
 await page.evaluate(()=>{const b=document.querySelector('#single [data-source-kind="enrichment"]');b.dataset.reviewId='wrong-context';});const beforeWrong=await page.evaluate(()=>reads.length);await single.click();await page.waitForFunction(()=>document.querySelector('dialog')?.textContent.includes('Frozen stored VirusTotal source unavailable'));assert.equal(await page.evaluate(()=>reads.length),beforeWrong+1);await page.keyboard.press('Escape');await page.waitForSelector('dialog',{state:'detached'});
 await page.evaluate(()=>{delete document.querySelector('#single [data-source-kind="enrichment"]').dataset.reviewId;});const beforeMissing=await page.evaluate(()=>reads.length);await single.click();await page.waitForFunction(()=>document.querySelector('dialog')?.textContent.includes('snapshot context not recorded'));assert.equal(await page.evaluate(()=>reads.length),beforeMissing);await page.keyboard.press('Escape');await page.waitForSelector('dialog',{state:'detached'});
 await page.evaluate(()=>{dto.fetched_at='2025-01-02T03:04:05Z';});
 await page.locator('#batch-review > summary').click();await page.waitForSelector('#br-run-id');
 for(const container of ['#br-packets','#br-synthesis-result']){await page.locator(container+' .batch-packet > summary').click();await page.locator(container+' [data-source-kind="enrichment"]').click();await page.waitForSelector('dialog .stored-vt-source');assert.ok((await page.evaluate(()=>reads)).includes('/cases/case%2Ffull%3C%26/enrich/case-review/batches/run%2Ffull%3C%26/virustotal/vt%2Ffull%3C%26'));await page.keyboard.press('Escape');await page.waitForSelector('dialog',{state:'detached'});}
 assert.equal(await page.locator('#br-packets .batch-coverage > :first-child').evaluate(n=>n.tagName),'SUMMARY','Coverage disclosure retains a first-child summary');
 await page.locator('#br-packets .batch-coverage > summary').click();assert.equal(await page.locator('#br-packets .batch-vt-coverage').isVisible(),true);
 assert.match(await page.locator('#single').innerText(),/Stored VirusTotal context/);assert.match(await page.locator('#single').innerText(),/included 2/);assert.match(await page.locator('#single').innerText(),/invalid 1/);assert.match(await page.locator('#br-status').innerText(),/Distinct stored VT included 2/);assert.match(await page.locator('#br-status').innerText(),/Primary reviewed events 1/);
 await page.evaluate(()=>{delete rv.latest.coverage;document.querySelector('#single').innerHTML=renderCaseReviewSection(rv);document.querySelector('#single').insertAdjacentHTML('beforeend',externalCitation('enrichment','no-context'));});assert.match(await page.locator('#single').innerText(),/Stored VirusTotal context:.*not recorded/);assert.match(await page.locator('#single').innerText(),/snapshot context not recorded/);
 assert.equal(await page.locator('#summary [data-claim-kind]').count(),0);assert.equal(await page.locator('#summary [data-source-kind="finding"]').count(),1);assert.equal(await page.locator('#br-start').isDisabled(),true);assert.equal(await page.locator('#br-build').count(),1);
 await page.evaluate(()=>{
  const node=document.createElement('div');node.id='preview-fixture';document.querySelector('main').appendChild(node);
  window.previewState={configured:true,allowed:true,local:false,events:1,destination:'synthetic.invalid',model:'synthetic',egress_level:'pseudonymized',privacy_contract:'synthetic-contract',source_fingerprint:'synthetic-fingerprint'};
  node.innerHTML='<section id="external-review">'+renderCaseReviewSection(previewState)+'</section>';
  const previous=api;window.api=async(p,o)=>p.endsWith('/preview') ? (reads.push(p),{...previewState,preview_key:'synthetic-key',system:'S',user:'U',privacy:{status:'checked',contract:previewState.privacy_contract,requires_separate_permission:true,payload_bytes:2},coverage:{vt_recorded:true,vt_total:10,vt_included:1,vt_omitted:9,vt_invalid:0,vt_unlinked:2}}) : previous(p,o);
  wireCaseReviewSection(node,'case/full<&',previewState,()=>{});
 });
 await page.locator('#preview-fixture #rv-preview').click();assert.match(await page.locator('#preview-fixture #rv-plan').innerText(),/included 1/);assert.equal(await page.locator('#preview-fixture #rv-start').isDisabled(),true,'Preview is not per-request consent');await page.locator('#preview-fixture #rv-ack').check();assert.equal(await page.locator('#preview-fixture #rv-start').isDisabled(),false,'Exact preview plus acknowledgement permits deliberate start only');
 for(const width of [1440,390]){await page.setViewportSize({width,height:1000});await page.waitForTimeout(100);assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),width+'px fit');await page.locator('#preview-fixture #rv-plan').screenshot({path:out+'/vt-preview-'+width+'.png'});await page.screenshot({path:out+'/vt-'+width+'.png',fullPage:true});await page.locator('#br-packets [data-source-kind="enrichment"]').click();await page.waitForSelector('dialog .stored-vt-source');await page.locator('dialog').screenshot({path:out+'/vt-dialog-'+width+'.png'});assert.ok(await page.locator('dialog').evaluate(d=>d.scrollWidth<=d.clientWidth));await page.keyboard.press('Escape');await page.waitForSelector('dialog',{state:'detached'});}
 assert.deepEqual(await page.evaluate(()=>writes),[]);assert.ok((await page.evaluate(()=>reads)).every(p=>!p.endsWith('/enrich/virustotal')),'Never resolve current live row');assert.deepEqual(errors,[]);fs.writeFileSync(out+'/fixture-reads.json',JSON.stringify(await page.evaluate(()=>reads),null,2));
 if(process.env.TRACEFALL_TEST_VT_PRESENCE_DIR){
  for(const name of ['historical','zero']){
   const data=JSON.parse(fs.readFileSync(path.join(process.env.TRACEFALL_TEST_VT_PRESENCE_DIR,name+'.json'),'utf8'));
   const presence=await browser.newPage({viewport:{width:1440,height:1000}});
   await presence.setContent('<main id="ext-root"><div id="single"></div><div id="batch"></div></main>');
   await presence.addStyleTag({path:assets+'/style.css'});
   await presence.addScriptTag({content:names.map(extract).join('\n')+'\nfunction fmtTime(x){return x||"not recorded";}'});
   await presence.evaluate(data=>{
    window.api=async p=>p.includes('/packets?')?data.packets:structuredClone(data.plan);
    document.querySelector('#single').innerHTML=renderCaseReviewSection(data.single);
    mountBatchReview(document.querySelector('#batch'),'synthetic',{configured:false});
   },data);
   await presence.locator('#batch-review > summary').click();await presence.waitForSelector('#br-run-id');
   await presence.waitForSelector('#br-packets .batch-packet');await presence.waitForSelector('#br-synthesis-result .batch-packet');
   const expected=name==='zero'?/included 0/:/included not recorded/;
   for(const selector of ['#single .stored-vt-coverage','#br-status .stored-vt-coverage','#br-packets .stored-vt-coverage','#br-synthesis-result .stored-vt-coverage']){
    const nodes=presence.locator(selector);assert.ok(await nodes.count(),name+' '+selector);
    for(const text of await nodes.allTextContents())assert.match(text,expected,name+' '+selector);
   }
   assert.match(await presence.locator('#br-status').innerText(),name==='zero'?/Distinct stored VT included 0/:/Distinct stored VT included not recorded/);
   // History is typed/unmarshalled/re-marshalled by the real history API.
   for(const p of data.history.plans){assert.equal(p.vt_recorded,name==='zero');assert.equal(p.snapshot.coverage.vt_recorded,name==='zero');}
   await presence.screenshot({path:out+'/vt-presence-'+name+'.png',fullPage:true});await presence.close();
  }
  console.log('PASS real stored historical/new-zero API -> single/plan/packet/synthesis browser render + history presence');
 }
 console.log('PASS zero-write synthetic VT context: frozen single/run/synthesis, errors/unknowns, escaping, nested source/Escape/focus, polling survival, counts, old Summary, batch controls, desktop/390px');
}finally{await browser?.close();}})().catch(e=>{console.error(e);process.exitCode=1;});
