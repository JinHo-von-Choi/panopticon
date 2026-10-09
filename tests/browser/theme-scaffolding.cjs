// Run: node tests/browser/theme-scaffolding.cjs
// Isolated static server with API contract fixtures and failure/recovery scenarios.
const {chromium}=require('playwright-core');
const http=require('http'), fs=require('fs'), path=require('path'), assert=require('assert/strict');
const root=path.resolve(__dirname, '../../netwatcher/web/static');
let apiMode='unavailable', graphSize=4, mttd=12.5, source='SNAPSHOT', delayNist=false;
const requests=[];
function fixture(url) {
 if(url==='/api/topology/graph') return {source, node_count:graphSize,edge_count:Math.max(0,graphSize-1),graph:{nodes:Array.from({length:graphSize},(_,i)=>({id:`10.0.${Math.floor(i/250)}.${i%250+1}`,severity:i===3?'OK':undefined})),links:Array.from({length:Math.max(0,graphSize-1)},(_,i)=>({source:`10.0.${Math.floor(i/250)}.${i%250+1}`,target:`10.0.${Math.floor((i+1)/250)}.${(i+1)%250+1}`}))}};
 if(url==='/api/topology/high-risk') return {devices:[{ip:'10.0.0.1',risk_score:9.5},{ip:'10.0.0.2',risk_score:7.5}]};
 if(url.startsWith('/api/topology/device/')) return {device:{id:decodeURIComponent(url.split('/').pop()),hostname:'<script>bad()</script>'},neighbors:['10.0.0.2'],risk:{risk_score:9.5}};
 if(url==='/api/compliance/frameworks') return {frameworks:[{id:'nist_csf',name:'NIST CSF'},{id:'pci_dss',name:'PCI DSS'}]};
 if(url.startsWith('/api/compliance/coverage/')) return {coverage_score:url.endsWith('pci_dss')?.5:.875,active_engines:['suricata'],controls:{}};
 if(url==='/api/compliance/kpis') return {alert_volume:1234,mttd_seconds:mttd,period_days:30};
}
const server=http.createServer((req,res)=>{
 const url=new URL(req.url,'http://localhost');
 if(url.pathname.startsWith('/api/')) {
  res.setHeader('Content-Type','application/json');
  if(url.pathname==='/api/auth/status') return res.end(JSON.stringify({enabled:false}));
  requests.push(url.pathname);
  const data=fixture(url.pathname);
  if(apiMode==='ok' && data) {
   if(delayNist && url.pathname==='/api/compliance/coverage/nist_csf') return setTimeout(()=>res.end(JSON.stringify(data)),250);
   return res.end(JSON.stringify(data));
  }
  res.statusCode=503;return res.end('{}');
 }
 const file=path.join(root,url.pathname==='/'?'index.html':url.pathname);
 try {res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.json')?'application/json':file.endsWith('.html')?'text/html':'application/octet-stream');res.end(fs.readFileSync(file));}catch {res.statusCode=404;res.end();}
});
(async()=>{await new Promise(r=>server.listen(0,'127.0.0.1',r));const base=`http://127.0.0.1:${server.address().port}`;const browser=await chromium.launch({executablePath:'/usr/bin/google-chrome',headless:true,args:['--no-sandbox']});
try{
 const page=await browser.newPage({viewport:{width:1440,height:1000}});const errors=[];page.on('pageerror',e=>errors.push(e.message));await page.goto(base);await page.waitForFunction(()=>window.i18next?.isInitialized);await page.waitForTimeout(250);
 const missing=await page.evaluate(()=>[...document.querySelectorAll('[data-i18n], [data-i18n-aria-label]')].filter(e=>/^(tabs\.(topology|compliance)|console\.(theme|topology|compliance|badge|source|navigation))/.test(e.dataset.i18n||e.dataset.i18nAriaLabel)).filter(e=>!window.i18next.exists(e.dataset.i18n||e.dataset.i18nAriaLabel)).map(e=>e.dataset.i18n));assert.deepEqual(missing,[]);
 for(const theme of ['operator','auditor','cinematic']) {await page.selectOption('#theme-selector',theme);assert.equal(await page.getAttribute('html','data-theme'),theme);const sizes=await page.evaluate(()=>['body','#theme-selector','.theme-switch label','.scope-hint','.badge-sev','.hud-meta'].map(s=>parseFloat(getComputedStyle(document.querySelector(s)).fontSize)));assert.ok(sizes.every(s=>s>=13),`${theme} fonts ${sizes}`);assert.equal(await page.evaluate(()=>localStorage.getItem('nw_theme')),theme);}
 assert.equal(await page.getAttribute('html','data-hud-scanlines'),null);assert.equal(await page.getAttribute('html','data-hud-sound'),null);
 await page.check('#hud-sound-toggle');assert.equal(await page.getAttribute('html','data-hud-sound'),'on');assert.equal(await page.locator('#hud-sound-state').innerText(),'ON');await page.uncheck('#hud-sound-toggle');assert.equal(await page.locator('#hud-sound-state').innerText(),'OFF');
 await page.check('#hud-scanlines-toggle');assert.equal(await page.getAttribute('html','data-hud-scanlines'),'on');await page.emulateMedia({reducedMotion:'reduce'});assert.equal(await page.evaluate(()=>getComputedStyle(document.body,'::after').display),'none');await page.emulateMedia({reducedMotion:'no-preference',forcedColors:'active'});assert.equal(await page.evaluate(()=>getComputedStyle(document.body,'::after').display),'none');await page.emulateMedia({forcedColors:'none'});
 await page.selectOption('#theme-selector','operator');assert.equal(await page.getAttribute('html','data-hud-scanlines'),null);
 for(const lang of ['en','ko']) {await page.selectOption('#lang-selector',lang);await page.waitForFunction(l=>window.i18next.language===l,lang);for(const tab of ['topology','compliance']) {await page.click(`[data-tab="${tab}"]`);assert.ok(await page.locator(`#tab-${tab}`).evaluate(e=>e.classList.contains('active')));assert.ok(!(await page.locator(`[data-tab="${tab}"]`).innerText()).startsWith('tabs.'));}}

 // API failures are visible and leave refresh available.
 await page.click('[data-tab="topology"]');
 await page.waitForFunction(()=>document.querySelector('#topology-state').textContent===window.i18next.t('console.topology.unavailable'));
 assert.equal(await page.locator('#topology-refresh').isEnabled(),true);
 await page.click('[data-tab="compliance"]');
 await page.waitForFunction(()=>document.querySelector('#compliance-state').textContent===window.i18next.t('console.compliance.unavailable'));
 assert.equal(await page.locator('#compliance-refresh').isEnabled(),true);
 apiMode='ok';
 await page.selectOption('#lang-selector','en');
 await page.click('[data-tab="topology"]');
 await page.waitForFunction(()=>document.querySelector('#topology-state').hidden && document.querySelector('#topology-canvas').width>0);
 assert.equal(await page.locator('#topology-counts').innerText(),'nodes 4 · edges 3');
 assert.equal(await page.locator('#topology-source-badge').innerText(),'SNAPSHOT');
 // Assert actual node and link pixels rather than only successful fetches.
 const pixels=await page.evaluate(()=>{
  const c=document.querySelector('#topology-canvas'),ctx=c.getContext('2d'),r=c.getBoundingClientRect(),d=c.width/r.width;
  const cols=Math.ceil(Math.sqrt(4*r.width/r.height));
  const rows=Math.ceil(4/cols),cw=r.width/cols,ch=r.height/rows;
  const sample=(x,y)=>[...ctx.getImageData(Math.round(x*d),Math.round(y*d),1,1).data].slice(0,3);
  const hex=name=>{const v=getComputedStyle(document.documentElement).getPropertyValue('--'+name).trim();return [1,3,5].map(i=>parseInt(v.slice(i,i+2),16));};
  return {nodes:Array.from({length:4},(_,i)=>sample((i%cols+.5)*cw,(Math.floor(i/cols)+.5)*ch)),expected:['critical','warning','text-faint','green'].map(hex),link:[-1,0,1].flatMap(dx=>[-1,0,1].map(dy=>sample(cw+dx,ch/2+dy))),background:sample(2,2)};
 });
 assert.deepEqual(pixels.nodes,pixels.expected);assert.ok(pixels.link.some(pixel=>pixel.some((v,i)=>v!==pixels.background[i])),'link pixels missing');
 const box=await page.locator('#topology-canvas').boundingBox();
 const cols=Math.ceil(Math.sqrt(4*box.width/box.height));
 await page.locator('#topology-canvas').click({position:{x:box.width/cols/2,y:box.height/Math.ceil(4/cols)/2}});
 await page.waitForFunction(()=>document.querySelector('#device-modal-body').textContent.includes('neighbors'));
 assert.equal(await page.locator('#device-modal-title').innerText(),'10.0.0.1');
 assert.equal(await page.locator('#device-modal-body script').count(),0);
 assert.ok(requests.includes('/api/topology/device/10.0.0.1'));
 await page.keyboard.press('Escape');
 await page.locator('#topology-canvas').focus();await page.keyboard.press('ArrowRight');await page.keyboard.press('Enter');
 await page.waitForFunction(()=>!document.querySelector('#device-modal-overlay').classList.contains('hidden'));
 await page.keyboard.press('Escape');
 source='LIVE';await page.click('#topology-refresh');
 await page.waitForFunction(()=>document.querySelector('#topology-source-badge').textContent==='LIVE');
 graphSize=0;await page.click('#topology-refresh');
 await page.waitForFunction(()=>document.querySelector('#topology-state').textContent===window.i18next.t('console.topology.empty'));
 graphSize=5000;source='SNAPSHOT';await page.click('#topology-refresh');
 await page.waitForFunction(()=>document.querySelector('#topology-counts').textContent==='nodes 5000 · edges 4999' && document.querySelector('#topology-state').hidden);
 await page.setViewportSize({width:800,height:800});
 await page.waitForFunction(()=>Math.abs(document.querySelector('#topology-canvas').width/document.querySelector('#topology-canvas').getBoundingClientRect().width-Math.min(devicePixelRatio,2))<.01);
 await page.setViewportSize({width:1440,height:1000});
 await page.click('[data-tab="compliance"]');
 await page.waitForFunction(()=>document.querySelectorAll('#compliance-kpis .hud-kpi').length===3);
 assert.deepEqual(await page.locator('#compliance-framework option').allTextContents(),['NIST CSF','PCI DSS']);
 assert.deepEqual(await page.locator('#compliance-kpis .hud-kpi-score').allTextContents(),['1,234','12.5 s','87.5%']);
 assert.equal(await page.getAttribute('#compliance-coverage','aria-valuenow'),'87.5');
 assert.equal(await page.locator('#compliance-coverage-bar').evaluate(e=>e.style.width),'87.5%');
 await page.selectOption('#compliance-framework','pci_dss');
 await page.waitForFunction(()=>document.querySelector('#compliance-coverage-score').textContent==='50.0%');

 delayNist=true;
 const previousNist=requests.filter(url=>url==='/api/compliance/coverage/nist_csf').length;
 await page.selectOption('#compliance-framework','nist_csf');
 while(requests.filter(url=>url==='/api/compliance/coverage/nist_csf').length===previousNist) await page.waitForTimeout(10);
 await page.selectOption('#compliance-framework','pci_dss');
 await page.waitForFunction(()=>document.querySelector('#compliance-coverage-score').textContent==='50.0%');
 await page.waitForTimeout(300);
 assert.equal(await page.locator('#compliance-coverage-score').innerText(),'50.0%');
 assert.equal(await page.inputValue('#compliance-framework'),'pci_dss');
 delayNist=false;
 mttd=null;await page.click('#compliance-refresh');
 await page.waitForFunction(()=>document.querySelector('#compliance-kpis').textContent.includes('Insufficient data'));
 assert.equal(await page.inputValue('#compliance-framework'),'pci_dss');
 await page.selectOption('#lang-selector','ko');
 await page.waitForFunction(()=>document.querySelector('#compliance-kpis').textContent.includes('데이터 부족'));
 assert.ok(!(await page.locator('#compliance-kpis').innerText()).includes('console.'));
 apiMode='unavailable';await page.click('#compliance-refresh');
 await page.waitForFunction(()=>document.querySelector('#compliance-state').textContent===window.i18next.t('console.compliance.unavailable'));
 assert.equal(await page.locator('#compliance-kpis .hud-kpi').count(),0);
 assert.equal(await page.getAttribute('#compliance-coverage','aria-valuenow'),null);
 apiMode='ok';await page.click('#compliance-refresh');
 await page.waitForFunction(()=>document.querySelectorAll('#compliance-kpis .hud-kpi').length===3);
 assert.ok(requests.includes('/api/compliance/coverage/pci_dss'));
 assert.ok(requests.includes('/api/topology/high-risk'));
 console.log('PASS: topology node/link pixels, risk colors, click/keyboard drawer, 5000 nodes, resize, source badges, empty/failure recovery; framework coverage, KPI units/null, refresh, live en/ko labels');
 await page.selectOption('#theme-selector','auditor');await page.reload();await page.waitForFunction(()=>window.i18next?.isInitialized);assert.equal(await page.inputValue('#theme-selector'),'auditor');assert.equal(await page.evaluate(()=>getComputedStyle(document.body).backgroundColor),'rgb(255, 255, 255)');
 await page.setViewportSize({width:390,height:844});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'mobile overflow');assert.deepEqual(errors,[]);

 const contrasts=await page.evaluate(async()=>{
 const mod=await import('/js/modules/theme.js');
 const rgb=c=>(c.match(/[\d.]+/g)||[]).map(Number);
 const luminance=c=>c.slice(0,3).map(v=>v/255).map(v=>v<=.04045?v/12.92:((v+.055)/1.055)**2.4).reduce((a,v,i)=>a+v*[.2126,.7152,.0722][i],0);
 const ratio=(a,b)=>{a=luminance(a);b=luminance(b);return(Math.max(a,b)+.05)/(Math.min(a,b)+.05)};
 const results=[];
 for(const theme of ['operator','auditor']) {mod.setTheme(theme,false); const root=getComputedStyle(document.documentElement); const hex=v=>[1,3,5].map(i=>parseInt(v.slice(i,i+2),16));
 for(const text of ['--text','--text-dim','--text-faint']) for(const bg of ['--bg','--surface','--surface2','--surface3']) results.push({theme,text,bg,ratio:ratio(hex(root.getPropertyValue(text).trim()),hex(root.getPropertyValue(bg).trim()))});
 for(const badge of document.querySelectorAll('.hud-legend .badge')) {const st=getComputedStyle(badge);const fg=rgb(st.color),bg=rgb(st.backgroundColor),base=hex(root.getPropertyValue('--bg').trim()); const alpha=bg[3]??1;results.push({theme,badge:badge.className,ratio:ratio(fg,bg.slice(0,3).map((v,i)=>v*alpha+base[i]*(1-alpha)))});}
 }
 return results;
 });assert.ok(contrasts.every(c=>c.ratio>=4.5),JSON.stringify(contrasts.filter(c=>c.ratio<4.5)));console.log('PASS: Operator/Auditor text and badge contrast >=4.5:1; minimum '+Math.min(...contrasts.map(c=>c.ratio)).toFixed(2));

 await page.evaluate(()=>window.dispatchEvent(new Event('nw-session-ended')));
 assert.equal(await page.locator('#compliance-kpis .hud-kpi').count(),0);
 assert.equal(await page.locator('#compliance-framework option').count(),0);
 assert.equal(await page.getAttribute('#compliance-coverage','aria-valuenow'),null);
 assert.equal(await page.locator('#topology-counts').innerText(),'노드 — · 연결 —');
 assert.deepEqual(errors,[]);
 console.log('PASS: stale framework response ignored; session end clears topology and compliance data');
 const cssParsing=await page.evaluate(()=>{const sheet=[...document.styleSheets].find(s=>s.href?.endsWith('/themes.css'));return {rules:sheet.cssRules.length,empty:[...sheet.cssRules].filter(r=>r.style&&r.style.length===0).map(r=>r.selectorText)}});assert.ok(cssParsing.rules>50);assert.deepEqual(cssParsing.empty,[]);console.log('PASS: Chromium CSS parsing ('+cssParsing.rules+' rules)');
 console.log('PASS: theme switching/persistence, font scale, HUD defaults/reduced-motion/forced-colors, en/ko tabs, mobile overflow, no JS runtime errors');
}finally{await browser.close();server.close();}
})().catch(e=>{console.error(e);server.close();process.exitCode=1;});
