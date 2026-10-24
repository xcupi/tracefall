// Zero-write synthetic UI fixtures, NOT actual provider output.
// PLAYWRIGHT_MODULE=/absolute/playwright node tests/review-claim-types.browser.cjs SCRATCH_OUTPUT
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const out=process.argv[2];
if(!path.isAbsolute(out||'')||!out.includes('/scratch/'))throw Error('Absolute scratch output required');
fs.mkdirSync(out,{recursive:true});
const source=fs.readFileSync(path.resolve(__dirname,'../internal/web/static/app.js'),'utf8');
function extract(name){const start=source.indexOf('function '+name+'(');assert.ok(start>=0,name);const end=source.slice(start+1).search(/\n(?:async )?function /);return end<0?source.slice(start):source.slice(start,start+1+end);}
(async()=>{let browser;try{
 browser=await chromium.launch({executablePath:'/usr/bin/google-chrome',headless:true,args:['--no-sandbox']});
 const page=await browser.newPage({viewport:{width:1440,height:1000}});const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.setContent('<main><div id="single"></div></main>');
 await page.addStyleTag({path:path.resolve(__dirname,'../internal/web/static/style.css')});
 const names=['esc','externalCitation','renderStoredVTCoverage','renderCaseReviewSection'];
 if(source.includes('function renderReviewClaimGroups('))names.push('renderReviewClaimGroups');
 await page.addScriptTag({content:names.map(extract).join('\n')});
 await page.evaluate(()=>{
  window.sentences=['observation','possible_conflict','hypothesis','gap','next_check'].map(kind=>({kind,text:kind+' synthetic only',cites:[{kind:'event',id:'event-original-full-id'}]}));
  window.rv={events:1,latest:{status:'ok',sentences}};
  document.querySelector('#single').innerHTML=renderCaseReviewSection(rv);
 });
 assert.equal(await page.locator('#single [data-claim-kind]').count(),5,'Single commentary groups the five backend-labelled types');
 console.log('PASS single claim grouping (synthetic UI only)');
 // Read-only stored-result fixtures exercise the real packet renderer, not a fake model call.
 await page.addScriptTag({content:['wireExternalCitations','mountBatchReview','renderNarrativeSection'].map(extract).join('\n')+'\nfunction fmtTime(x){return x || "not recorded";}'});
 await page.evaluate(()=>{
  sentences.push({text:'observation | legacy MUST NOT infer a type',cites:[{kind:'coverage',id:'selection'}]},
   {kind:'future_type',text:'<img src=x onerror="window.claimXSS=true"> unknown',cites:[{kind:'correlation',id:'correlation-original'}]},
   {kind:'unclassified',text:'Explicit fallback',cites:[]});
  document.querySelector('#single').innerHTML=renderCaseReviewSection(rv);
  const summary=document.createElement('div');summary.id='summary';summary.innerHTML=renderNarrativeSection({latest:rv.latest});document.querySelector('main').appendChild(summary);
  window.fixtureReads=[];window.fixtureWrites=[];
  window.plan={id:'fixture-run',state:'succeeded',total_batches:1,synthesis_state:'succeeded',local:true,budget:{},progress:{},snapshot:{}};
  window.packets=[{seq:0,kind:'event',state:'succeeded',namespace:'packet-A',sentences,coverage:{events_included:7},raw_answer:'<img src=x onerror="window.claimXSS=true"> raw'},
   {seq:1,kind:'synthesis',state:'succeeded',namespace:'synthesis-B',sentences,coverage:{events_included:2}}];
  window.api=async(p,opts)=>{if(opts?.method){fixtureWrites.push(p);throw Error('No writes allowed');}fixtureReads.push(p);if(p.endsWith('/enrich/case-review'))return {latest:{coverage:{events_included:11}}};if(p.includes('/packets?'))return {packets:structuredClone(packets)};if(p.endsWith('/correlations'))return [{correlation_id:'correlation-original',title:'Fixture original correlation',description:'Not evidence',event_ids:[]}];return structuredClone(plan);};
  const card=document.createElement('div');card.id='packet-fixture';document.querySelector('main').appendChild(card);mountBatchReview(card,'synthetic-case',{configured:false});
 });
 assert.equal(await page.locator('#single [data-claim-kind="unclassified"] li').count(),3);
 assert.equal(await page.locator('#single [data-claim-kind="observation"] li').count(),1,'No prefix inference or unknown upgrade');
 assert.match(await page.locator('#single [data-claim-kind="unclassified"]').innerText(),/not type-checked/);
 assert.equal(await page.locator('#single img').count(),0,'Model HTML escaped');
 assert.equal(await page.locator('#summary [data-claim-kind]').count(),0,'Summary never reclassified');
 assert.equal(await page.locator('#summary li').count(),8,'Summary keeps flat sentences and citations');
 assert.equal(await page.locator('#single [data-source-id="event-original-full-id"]').count(),5,'Single retains full original citation identity');
 await page.evaluate(()=>wireExternalCitations(document.querySelector('#single'),'synthetic-case'));
 await page.locator('#single [data-source-id="selection"]').click();await page.waitForSelector('dialog pre');
 assert.equal(JSON.parse(await page.locator('dialog pre').innerText()).events_included,11,'Single selection keeps legacy latest-review coverage semantics');
 await page.keyboard.press('Escape');await page.waitForSelector('dialog',{state:'detached'});
 await page.locator('#batch-review > summary').click();await page.waitForSelector('#br-run-id');
 assert.equal(await page.locator('#br-packets [data-claim-kind]').count(),6,'Packet uses same grouped categories');
 assert.equal(await page.locator('#br-synthesis-result [data-claim-kind]').count(),6,'Synthesis uses same grouped categories');
 for(const selector of ['#br-packets','#br-synthesis-result']){
  await page.locator(selector+' .batch-packet > summary').click();
  assert.equal(await page.locator(selector+' .batch-commentary [data-source-id="event-original-full-id"]').count(),5);
  await page.locator(selector+' .batch-selection').click();await page.waitForSelector('dialog');
  const expected=selector==='#br-packets'?7:2;
  assert.equal(JSON.parse(await page.locator('dialog pre').innerText()).events_included,expected,'Selection citation stays packet-specific');
  assert.match(await page.locator('dialog').innerText(),selector==='#br-packets'?/packet-A/:/synthesis-B/);
  await page.keyboard.press('Escape');await page.waitForSelector('dialog',{state:'detached'});
 }
 await page.locator('#br-packets .batch-commentary [data-source-id="correlation-original"]').click();
 await page.waitForFunction(()=>document.querySelector('dialog')?.textContent.includes('Fixture original correlation'));
 await page.keyboard.press('Escape');await page.waitForSelector('dialog',{state:'detached'});
 await page.locator('#br-packets .batch-raw > summary').click();assert.match(await page.locator('#br-packets .batch-raw pre').innerText(),/<img/);
 assert.equal(await page.locator('img').count(),0);assert.equal(await page.evaluate(()=>!!window.claimXSS),false);
 assert.match(await page.locator('#single .review-claim-legend').innerText(),/not truth-validated/);
 // Long model tokens must wrap without detector/severity styling or horizontal overflow.
 await page.evaluate(()=>{document.querySelector('#single [data-claim-kind="hypothesis"] li').prepend('x'.repeat(300));});
 for(const width of [1440,390]){
  await page.setViewportSize({width,height:1000});await page.waitForTimeout(350);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,width+'px page fits');
  assert.equal(await page.locator('.review-claim-group .severity,.review-claim-group .badge-critical').count(),0);
  await page.locator('#single .review-commentary').screenshot({path:out+'/claims-'+width+'.png'});
  await page.locator('#packet-fixture').screenshot({path:out+'/packets-'+width+'.png'});
 }
 assert.deepEqual(await page.evaluate(()=>fixtureWrites),[],'Category display makes zero writes/provider requests');
 console.log('PASS synthetic grouping, legacy/unknown fallback, escaping, original single/packet/synthesis citations, scoped coverage, raw disclosure, unchanged Summary, zero writes, desktop + 390px');
 assert.deepEqual(errors,[]);
 }finally{await browser?.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
