// Disposable loopback server ONLY, configured for the synthetic-review-test model
// at http://127.0.0.1:18480. No real provider or credential is used.
// PLAYWRIGHT_MODULE=/scratch/node_modules/playwright node tests/case-review.browser.cjs BASE OUTPUT
const {chromium}=require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const base=process.argv[2],out=process.argv[3];
if(!/^http:\/\/127\.0\.0\.1:\d+$/.test(base)||!out)throw Error('Use a disposable loopback server and output directory');
fs.mkdirSync(out,{recursive:true});
(async()=>{
 const browser=await chromium.launch({executablePath:'/usr/bin/google-chrome',headless:true,args:['--no-sandbox']});
 const page=await browser.newPage({viewport:{width:1440,height:1000}});const errors=[];page.on('pageerror',e=>errors.push(e.message));
 try{
  const api=async(path,opts={})=>{const r=await page.request.fetch(base+'/api'+path,{...opts,headers:{'X-Tracefall-Client':'dashboard',...opts.headers}});const body=await r.text();assert.ok(r.ok(),`${r.status()} ${path} ${body}`);return body?JSON.parse(body):null;};
  const c=await api('/cases',{method:'POST',data:{name:'Synthetic bounded review browser test '+Date.now(),description:'No real evidence'}});
  const route=`/cases/${c.id}/enrich/case-review`;
  const st=await api(route);
  assert.equal(st.model,'synthetic-review-test','Safety gate: requires the fake model');assert.equal(st.local,true);assert.equal(st.destination,'127.0.0.1');
  const zip=require('node:child_process').execFileSync('python3',['-c',"import io,sys,zipfile; b=io.BytesIO(); z=zipfile.ZipFile(b,'w'); z.writestr('home/alice/.bash_history','whoami\\npwd\\nid\\n'); z.close(); sys.stdout.buffer.write(b.getvalue())"]);
  const d=await api(`/cases/${c.id}/evidence`,{method:'POST',multipart:{file:{name:'synthetic-history.zip',mimeType:'application/zip',buffer:zip}}});
  const ids=d.source_files.map(s=>s.id);assert.ok(ids.length,'Synthetic upload should discover history');
  await api(`/cases/${c.id}/evidence/${d.collection.collection_id}/import`,{method:'POST',data:{source_file_ids:ids}});
  assert.deepEqual(await api(`/cases/${c.id}/findings`),[]);
  await page.goto(`${base}/#/cases/${c.id}/external`);await page.waitForSelector('#external-review');
  assert.match(await page.locator('#external-review').innerText(),/bounded|Bounded/);
  assert.equal(await page.locator('#rv-start').isDisabled(),true);
  await page.click('#rv-preview');await page.waitForSelector('#rv-preview-box:visible');
  assert.match(await page.locator('#rv-plan').innerText(),/unflagged_included/);
  assert.match(await page.locator('#rv-preview-box').innerText(),/findings_total=0/);
  assert.equal((await api(route)).latest,undefined,'Preview must not create/send a review');
  assert.equal(await page.locator('#rv-start').isEnabled(),true,'Zero findings must not block events review');
  await page.click('#rv-start');await page.waitForSelector('.review-commentary ol',{timeout:15000});
  assert.match(await page.locator('.review-commentary').innerText(),/not evidence or a new finding/);
  await page.click('#rv-payload');await page.waitForSelector('#rv-payload-box:visible');
  assert.match(await page.locator('#rv-payload-box').innerText(),/BOUNDED PARSED CASE REVIEW/);
  assert.equal(await page.locator('#external-review [data-source-kind="event"]').count(),1);
  assert.equal(await page.locator('#external-review [data-source-kind="coverage"]').count(),1,'Coverage citations must remain inspectable');
  await page.locator('#external-review [data-source-kind="coverage"]').click();await page.waitForSelector('dialog .external-source-body pre');assert.match(await page.locator('dialog pre').innerText(),/events_included/);await page.keyboard.press('Escape');
  await page.locator('#external-review [data-source-kind="event"]').click();await page.waitForFunction(()=>document.querySelector('dialog .external-source-body')?.textContent.includes('raw record:'));await page.keyboard.press('Escape');
  await page.evaluate(()=>scrollTo(0,0));
  await page.screenshot({path:out+'/review-desktop.png',fullPage:true});
  await page.locator('#external-review').screenshot({path:out+'/review-card-desktop.png'});
  await page.setViewportSize({width:390,height:844});await page.evaluate(()=>scrollTo(0,0));await page.screenshot({path:out+'/review-mobile.png',fullPage:true});
  await page.locator('#external-review').screenshot({path:out+'/review-card-mobile.png'});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'No narrow-screen overflow');
  assert.deepEqual(errors,[]);
  const result=await api(route);fs.writeFileSync(out+'/review-case.json',JSON.stringify({id:c.id,latest:result.latest},null,2));
  console.log('PASS synthetic provider: actual upload/import, zero-findings bounded preview/start/status/persistence, exact payload UI, event/coverage drill-down, desktop/mobile');
 }catch(e){console.error('Browser state:',await page.locator('dialog').allTextContents());await page.screenshot({path:out+'/review-failure.png',fullPage:true});throw e;}finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
