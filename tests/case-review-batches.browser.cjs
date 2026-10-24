// Synthetic-only real backend + this worktree's routed assets. Never a live model.
// PLAYWRIGHT_MODULE=/absolute/playwright node tests/case-review-batches.browser.cjs BINARY SCRATCH_OUTPUT
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),http=require('node:http'),net=require('node:net'),crypto=require('node:crypto');
const {spawn,execFileSync}=require('node:child_process');
const binary=process.argv[2],out=process.argv[3];
if(!binary||!path.isAbsolute(out||'')||!out.includes('/scratch/'))throw Error('Explicit binary and absolute scratch output required');
fs.mkdirSync(out,{recursive:true});
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const listen=s=>new Promise(r=>s.listen(0,'127.0.0.1',()=>r(s.address().port)));
const close=s=>new Promise(r=>s.close(r));
(async()=>{
 let browser,server,provider,port,providerPort; const requests=[]; let delay=0;
 try {
  provider=http.createServer(async(req,res)=>{
   if(req.method==='GET'){res.end('TRACEFALL_SYNTHETIC_BATCH_UI_PROVIDER');return;}
   let body='';for await(const b of req)body+=b;
   const json=JSON.parse(body);requests.push(json);fs.writeFileSync(out+'/requests.json',JSON.stringify(requests,null,2));
   await sleep(delay);
   res.setHeader('Content-Type','application/json');res.end(JSON.stringify({model:'synthetic-batch-ui-test',choices:[{message:{role:'assistant',content:'Synthetic observation is recorded. [E1]\nThis is a bounded partial selection. [K1]'},finish_reason:'stop'}]}));
  });
  providerPort=await listen(provider);
  const reserve=net.createServer();port=await listen(reserve);await close(reserve);
  const home=path.join(out,'home');fs.mkdirSync(home,{recursive:true});
  const log=fs.openSync(out+'/server.log','a');
  server=spawn(binary,['-port',String(port),'-db',out+'/case.db','-data-dir',out+'/data'],{cwd:out,env:{PATH:process.env.PATH,HOME:home,TMPDIR:out,TRACEFALL_LLM_PROVIDER:'openai-compatible',TRACEFALL_LLM_API_KEY:'synthetic-not-a-real-credential',TRACEFALL_LLM_MODEL:'synthetic-batch-ui-test',TRACEFALL_LLM_BASE_URL:`http://127.0.0.1:${providerPort}/v1`},stdio:['ignore',log,log]});
  const base=`http://127.0.0.1:${port}`;
  for(let i=0;i<100;i++){try{if((await fetch(base+'/api/cases')).ok)break;}catch{}await sleep(100);}
  assert.equal(await(await fetch(`http://127.0.0.1:${providerPort}`)).text(),'TRACEFALL_SYNTHETIC_BATCH_UI_PROVIDER');
  browser=await chromium.launch({executablePath:'/usr/bin/google-chrome',headless:true,args:['--no-sandbox']});
  const page=await browser.newPage({viewport:{width:1440,height:1000}}), errors=[];page.setDefaultTimeout(10000);page.on('pageerror',e=>{errors.push(e.message);console.error('PAGE ERROR',e.message)});console.log('Browser ready');
  const assets=path.resolve(__dirname,'../internal/web/static');
  await page.route('**/static/app.js',r=>r.fulfill({path:assets+'/app.js',contentType:'application/javascript'}));
  await page.route('**/static/style.css',r=>r.fulfill({path:assets+'/style.css',contentType:'text/css'}));
  const api=async(p,opts={})=>{const r=await page.request.fetch(base+'/api'+p,{...opts,headers:{'X-Tracefall-Client':'dashboard',...opts.headers}});const text=await r.text();assert.ok(r.ok(),r.status()+' '+p+' '+text);return text?JSON.parse(text):null;};
  const c=await api('/cases',{method:'POST',data:{name:'Synthetic batch UI',description:'Synthetic provider only; not evidence'}});
  const b=`/cases/${c.id}/enrich/case-review/batches`;
  assert.equal((await api(`/cases/${c.id}/enrich/case-review`)).model,'synthetic-batch-ui-test');
  const history=Array.from({length:181},(_,i)=>`echo synthetic-record-${i}`).join('\n')+'\n';
  const zip=execFileSync('python3',['-c',"import io,sys,zipfile; b=io.BytesIO(); z=zipfile.ZipFile(b,'w'); z.writestr('home/alice/.bash_history',sys.argv[1]); z.close(); sys.stdout.buffer.write(b.getvalue())",history]);
  const d=await api(`/cases/${c.id}/evidence`,{method:'POST',multipart:{file:{name:'synthetic.zip',mimeType:'application/zip',buffer:zip}}});
  await api(`/cases/${c.id}/evidence/${d.collection.collection_id}/import`,{method:'POST',data:{source_file_ids:d.source_files.map(s=>s.id)}});
  console.log('Import complete');await page.goto(`${base}/#/cases/${c.id}/external`,{waitUntil:'domcontentloaded'});await page.waitForSelector('#external-review');console.log('Review mounted');
  assert.equal(await page.locator('.external-card').count(),4);
  await page.locator('#batch-review > summary').click();await page.waitForFunction(()=>!document.querySelector('#br-build').disabled);
  await page.click('#br-build');await page.waitForSelector('#br-run-id');
  const id=await page.locator('#br-run-id').innerText();const plan=await api(b+'/'+id);
  assert.equal(plan.eligible_events,181);assert.equal(plan.total_batches,4);assert.equal(requests.length,0,'Local planning sends nothing');
  assert.equal(await page.locator('#br-packets .batch-packet').count(),4,'Plan must expose inspectable packets, not serialized JSON');
  const first=page.locator('#br-packets .batch-packet').first();
  await first.locator(':scope > summary').click();await first.locator('.batch-payload-button').click();
  await first.locator('.batch-payload').waitFor({state:'visible'});
  assert.match(await first.locator('.batch-payload').innerText(),/NOT a transmission receipt/);
  const pre=await api(b+'/'+id+'/packets/0/payload');assert.equal(pre.attempted,false);
  delay=350;await page.click('#br-start');
  await page.locator('#br-requests').count(); // No hidden provider controls or automatic sends.
  await first.locator('.batch-payload').focus();
  await first.locator('.batch-payload').evaluate(e=>e.scrollTop=110);
  const scroll=await first.locator('.batch-payload').evaluate(e=>e.scrollTop);
  await page.waitForFunction(()=>/Primary reviewed events 181/.test(document.querySelector('#br-status').textContent),{},{timeout:30000});
  assert.equal(await first.evaluate(e=>e.open),true,'Details preserved across progress');
  assert.equal(await first.locator('.batch-payload').evaluate(e=>e.scrollTop),scroll,'Visible payload internal scroll preserved');
  assert.equal(await page.evaluate(()=>document.activeElement.classList.contains('batch-payload')),true,'Payload focus preserved');
  const done=await api(b+'/'+id);assert.equal(done.progress.primary_reviewed_events,181);assert.equal(done.progress.distinct_successful_events,181);
  assert.equal(done.progress.requests_attempted,5);assert.equal(requests.length,5,'Four initial calls plus one synthesis');
  assert.equal(done.synthesis_state,'succeeded');
  const packets=(await api(b+'/'+id+'/packets?after=-1&limit=10')).packets;
  for(const packet of packets){
    const exact=await api(b+'/'+id+'/packets/'+packet.seq+'/payload');
    const req=requests.find(r=>r.messages[0].content===exact.payload.system && r.messages[1].content===exact.payload.user);assert.ok(req,'Exact persisted request must match captured synthetic provider bytes');
    const hash=crypto.createHash('sha256').update(exact.payload.system+'\0'+exact.payload.user).digest('hex');assert.equal(hash,exact.payload.sha256);assert.equal(exact.attempted,true);
  }
  await first.locator('.batch-payload-button').click();await page.waitForFunction(()=>document.querySelector('.batch-payload')?.textContent.startsWith('Attempted: durable admission'));
  const last=page.locator('#br-packets .batch-packet').last();await last.locator(':scope > summary').click();
  await last.locator('.batch-selection').click();await page.waitForSelector('dialog[aria-label="Batch packet coverage"]');
  assert.match(await page.locator('dialog').innerText(),/packet 3/);assert.equal(JSON.parse(await page.locator('dialog pre').innerText()).events_included,1,'Coverage selection must resolve THAT packet, not latest single review');await page.keyboard.press('Escape');
  await first.locator('.batch-commentary [data-source-kind="event"]').click();await page.waitForFunction(()=>document.querySelector('dialog')?.textContent.includes('raw record:'));await page.keyboard.press('Escape');
  await page.locator('#br-synthesis-result .batch-packet > summary').click();
  assert.ok(await page.locator('#br-synthesis-result .batch-commentary [data-source-kind="event"]').count(),'Synthesis keeps original citations');
  await page.waitForFunction(()=>['succeeded','partial','failed'].includes(document.querySelector('#br-status strong')?.textContent),{},{timeout:30000});
  assert.equal(await page.locator('#br-synthesis-result').evaluate(e=>[...e.childNodes].filter(n=>n.nodeType===Node.TEXT_NODE).map(n=>n.textContent).join('').trim()),'','A prepared synthesis must not retain stale not-prepared placeholder');
  await page.screenshot({path:out+'/batch-desktop.png',fullPage:true});await page.locator('#batch-review').screenshot({path:out+'/batch-card-desktop.png'});
  await page.setViewportSize({width:390,height:844});await page.evaluate(()=>scrollTo(0,0));await page.waitForTimeout(350); // Let the existing sidebar's responsive transition settle before capture.
  await page.screenshot({path:out+'/batch-mobile.png',fullPage:true});await page.locator('#batch-review').screenshot({path:out+'/batch-card-mobile.png'});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'390px viewport must not overflow');
  await page.setViewportSize({width:1440,height:1000});
  // One explicitly budget-limited initial call: remaining packets unreviewed, no synthesis.
  await page.fill('#br-requests','1');await page.uncheck('#br-synthesis');await page.click('#br-build');
  await page.waitForFunction(old=>document.querySelector('#br-run-id').textContent!==old,id);
  const partialId=await page.locator('#br-run-id').innerText();await page.click('#br-start');
  await page.waitForFunction(()=>document.querySelector('#br-status strong')?.textContent==='partial',{},{timeout:20000});
  const partial=await api(b+'/'+partialId);assert.equal(partial.enabled_batches,1);assert.equal(partial.progress.primary_reviewed_events,60);assert.equal(partial.progress.unreviewed,3);assert.equal(requests.length,6);
  // Inspect history without silently selecting latest; preserve editable budget too.
  await page.locator('#br-history > summary').click();await page.locator('#br-history-list button').filter({hasText:id}).click();
  assert.equal(await page.locator('#br-run-id').innerText(),id);await page.click('#br-refresh');assert.equal(await page.locator('#br-run-id').innerText(),id);assert.equal(await page.inputValue('#br-requests'),'1');
  assert.match(await page.locator('#br-status').innerText(),/Frozen budget: requests 8/,'History must show the actual approved budget, not the edited next-plan form');
  // Real cancellation of a slow synthetic loopback request; never retry/resume.
  delay=4000;await page.click('#br-build');await page.waitForFunction(old=>document.querySelector('#br-run-id').textContent!==old,id);const cancelId=await page.locator('#br-run-id').innerText();
  await page.click('#br-start');for(let i=0;i<100&&requests.length<7;i++)await sleep(50);assert.equal(requests.length,7);await page.click('#br-stop');
  await page.waitForFunction(()=>/cancelled/.test(document.querySelector('#br-status').textContent),{},{timeout:10000});const cancelled=await api(b+'/'+cancelId);assert.equal(cancelled.state,'cancelled');assert.equal(cancelled.progress.primary_reviewed_events,0);assert.equal(requests.length,7);
  fs.writeFileSync(out+'/runs.json',JSON.stringify({case_id:c.id,done,partial,cancelled},null,2));
  const beforeFixtures=requests.length;
  await require('./case-review-batches-ui.browser.cjs')(page,c.id,done,packets[0],out);
  assert.equal(requests.length,beforeFixtures,'External UI fixtures must send zero requests');
  assert.deepEqual(errors,[]);console.log('PASS synthetic batch UI: 181 events, local zero-send plan, 4 initial + synthesis, exact SHA-256 readback, distinct coverage, partial budget, retained history selection, real cancellation, payload/focus/scroll, desktop + 390px');
 } finally {
  await browser?.close();
  if(server){server.kill('SIGTERM');await Promise.race([new Promise(r=>server.once('exit',r)),sleep(5000)]);if(server.exitCode===null && server.signalCode===null){server.kill('SIGKILL');await new Promise(r=>server.once('exit',r));}}
  if(provider){provider.closeAllConnections();await close(provider);}
  for(const p of [port,providerPort].filter(Boolean)){const open=await new Promise(r=>{const s=net.connect(p,'127.0.0.1');s.once('connect',()=>{s.destroy();r(true)});s.once('error',()=>r(false));});assert.equal(open,false,'Disposable port must be closed: '+p);}
  console.log('Verified disposable server/provider ports closed');
 }
})().catch(e=>{console.error(e);process.exitCode=1;});
