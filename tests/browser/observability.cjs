// Run: node tests/browser/observability.cjs
// 관측 탭, 에이전트 탭, 기능 상태 안내를 고정 API 응답으로 검증한다.
const {chromium}=require(process.env.PANOPTICON_PLAYWRIGHT_CORE || 'playwright-core');
const http=require('http'), fs=require('fs'), path=require('path'), assert=require('assert/strict');
const root=path.resolve(__dirname, '../../netwatcher/web/static');
const now=Math.floor(Date.now()/1000);
let queryFails=false;
const bucket=t=>new Date(t*1000).toISOString();
function fixture(url) {
 if(url.pathname==='/api/capabilities') return {input_mode:'native',features:{traffic:true},states:{
   devices:{state:'unsupported',reason:'eve_mode_no_device_collection'},topology:{state:'unsupported',reason:'no_topology_source'},
   agents:{state:'available',reason:null}}};
 if(url.pathname==='/api/observability/panels') return {input_mode:'native',panels:{
   alerts_by_severity:{kind:'timeseries',unit:'alerts',supported:true},
   top_sources:{kind:'bar',unit:'alerts',supported:true},
   alert_heatmap:{kind:'heatmap',unit:'alerts',supported:true},
   new_devices:{kind:'timeseries',unit:'devices',supported:true},
   eve_event_types:{kind:'timeseries',unit:'records',supported:false}}};
 if(url.pathname==='/api/observability/query') {
  if(queryFails) return null;
  const from=url.searchParams.get('from'), to=url.searchParams.get('to');
  return {as_of:new Date().toISOString(),from,to,bucket_seconds:60,tz:'UTC',panels:{
   alerts_by_severity:{kind:'timeseries',unit:'alerts',state:'ok',series:{CRITICAL:[[bucket(now-120),2],[bucket(now-60),1]],WARNING:[[bucket(now-60),4]]}},
   top_sources:{kind:'bar',unit:'alerts',state:'ok',rows:[{label:'10.0.0.1',value:5},{label:'10.0.0.2',value:2}]},
   alert_heatmap:{kind:'heatmap',unit:'alerts',state:'ok',cells:[{x:1,y:9,value:3}]},
   new_devices:{kind:'timeseries',unit:'devices',state:'ok',series:{}}}};
 }
 if(url.pathname==='/api/compliance/frameworks') return {frameworks:[{id:'nist_csf',name:'NIST CSF'}]};
 if(url.pathname==='/api/compliance/kpis') return {alert_volume:3,mean_alert_interval_seconds:null};
 if(url.pathname==='/api/compliance/coverage/nist_csf') return {framework:'nist_csf',coverage_score:0.5,active_engines:['port_scan'],controls:{}};
 if(url.pathname==='/api/compliance/gaps/nist_csf') return {framework:'nist_csf',gap_count:1,gaps:[{id:'DE.CM-1',name:'Network monitored',status:'gap',engines:['arp_spoof','dns_anomaly']}]};
 if(url.pathname==='/api/compliance/report/nist_csf') return '<html><body>report</body></html>';
 if(url.pathname==='/api/hunting/navigator') return {techniques:[]};
 if(url.pathname==='/api/hunting/coverage') return {total_techniques:2,covered:1,gaps:[{technique_id:'T1046',name:'Network Service Discovery',tactic:'discovery'}]};
 if(url.pathname==='/api/topology/graph') return {source:'snapshot',graph:{nodes:[{id:'10.0.0.1'},{id:'10.0.0.2'}],links:[{source:'10.0.0.2',target:'10.0.0.1'}]}};
 if(url.pathname==='/api/topology/high-risk') return {devices:[],threshold:7};
 if(url.pathname==='/api/topology/gateways') return {gateways:[{ip:'10.0.0.1',hostname:'router'}]};
 if(url.pathname==='/api/agents') return {total:1,now,agents:[{agent_uuid:'11111111-1111-1111-1111-111111111111',hostname:'web-1',platform:'linux/x86_64',
   enrolled_at:now-100,last_seen:now-2,latency_ms:3.5,resources:{load_1:0.5,memory_total_bytes:8589934592,memory_available_bytes:4294967296,agent_rss_bytes:3145728}}]};
 if(url.pathname.endsWith('/events')) return {batches:[{seq:1,received_at:now,events:[{kind:'connection',local_address:'10.0.0.5:5000',remote_address:'198.51.100.7:443',state:'ESTABLISHED',inode:1,observed_at:now}]}],next_before_seq:null};
 return undefined;
}
const server=http.createServer((req,res)=>{
 const url=new URL(req.url,'http://localhost');
 if(url.pathname.startsWith('/api/')) {
  res.setHeader('Content-Type','application/json');
  if(url.pathname==='/api/auth/status') return res.end(JSON.stringify({enabled:false}));
  const data=fixture(url);
  if(typeof data==='string'){res.setHeader('Content-Type','text/html');return res.end(data);}
  if(data) return res.end(JSON.stringify(data));
  res.statusCode=data===null?503:404;return res.end('{}');
 }
 const file=path.join(root,url.pathname==='/'?'index.html':url.pathname);
 try {res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':file.endsWith('.json')?'application/json':file.endsWith('.html')?'text/html':'application/octet-stream');res.end(fs.readFileSync(file));}catch {res.statusCode=404;res.end();}
});
(async()=>{await new Promise(r=>server.listen(0,'127.0.0.1',r));const base=`http://127.0.0.1:${server.address().port}`;
const browser=await chromium.launch({executablePath:process.env.PANOPTICON_CHROME||'/usr/bin/google-chrome',headless:true,args:['--no-sandbox']});
try{
 const page=await browser.newPage({viewport:{width:1440,height:1000}});const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto(base);await page.waitForFunction(()=>window.i18next?.isInitialized);await page.selectOption('#lang-selector','en');
 await page.waitForFunction(()=>window.i18next.language==='en');

 // 기능 상태: 지원하지 않는 장치 화면은 이유를 글로 보여 준다.
 await page.click('[data-tab="devices"]');
 const notice=page.locator('[data-capability-notice="devices"]');
 await notice.waitFor({state:'visible'});
 assert.match(await notice.innerText(),/does not collect devices/);

 // 관측 탭: 지원 패널은 그리고, 미지원 패널은 고를 수 없다.
 await page.click('[data-tab="observability"]');
 await page.waitForFunction(()=>document.querySelector('#obs-status').textContent.startsWith('As of'));
 assert.equal(await page.locator('#obs-grid .obs-card').count(),5);
 assert.equal(await page.locator('#obs-panel-picker input[type=checkbox]:disabled').count(),1);
 assert.equal(await page.locator('#obs-panel-eve_event_types .empty-state').innerText(),'This panel is not supported in this deployment.');
 assert.ok(await page.locator('#obs-panel-alerts_by_severity canvas').count()===1);
 assert.equal(await page.locator('#obs-panel-new_devices .empty-state').innerText(),'No records in the selected range.');
 assert.equal(await page.locator('#obs-panel-alert_heatmap .obs-heatmap-cell').count(),7*24);
 assert.equal(await page.locator('#obs-panel-top_sources details.obs-table tr').count(),3);

 // 막대를 누르면 같은 기간과 출발지로 사건 목록을 연다.
 const point=await page.evaluate(()=>{const canvas=document.querySelector('#obs-panel-top_sources canvas');const chart=Chart.getChart(canvas);
   const bar=chart.getDatasetMeta(0).data[0];const box=canvas.getBoundingClientRect();return {x:box.left+(bar.x+bar.base)/2,y:box.top+bar.y};});
 await page.mouse.click(point.x,point.y);
 await page.waitForFunction(()=>document.querySelector('#tab-events').classList.contains('active'));
 assert.equal(await page.inputValue('#filter-search'),'10.0.0.1');
 assert.match(await page.inputValue('#filter-since'),/^\d{4}-\d{2}-\d{2}$/);

 // 갱신 실패: 마지막 그래프를 남기고 실패를 알린다.
 queryFails=true;
 await page.click('[data-tab="observability"]');
 await page.waitForFunction(()=>document.querySelector('#obs-status').textContent.startsWith('Refresh failed'));
 assert.ok(await page.locator('#obs-panel-alerts_by_severity canvas').count()===1);
 queryFails=false;

 // 패널 선택은 브라우저에 남는다.
 await page.click('.obs-picker summary');
 await page.locator('#obs-panel-picker input[type=checkbox]').first().uncheck();
 assert.equal(await page.locator('#obs-grid .obs-card').count(),4);
 assert.ok((await page.evaluate(()=>localStorage.getItem('panopticon.observability'))).includes('alerts_by_severity'));

 // 에이전트 탭: 연결 상태와 연결 이벤트.
 await page.click('[data-tab="agents"]');
 await page.waitForFunction(()=>document.querySelectorAll('#agents-body tr').length===1);
 assert.match(await page.locator('#agents-body tr').innerText(),/web-1.*Connected/s);
 await page.locator('#agents-body tr').click();
 await page.waitForFunction(()=>document.querySelectorAll('#agents-events tr').length===1);
 assert.match(await page.locator('#agents-events tr').innerText(),/198\.51\.100\.7:443/);
 assert.equal(await page.locator('#agents-more').isHidden(),true);

 // 컴플라이언스: 격차 표와 보고서 내려받기.
 await page.click('[data-tab="compliance"]');
 await page.waitForFunction(()=>document.querySelectorAll('#compliance-gaps tr').length===1);
 assert.match(await page.locator('#compliance-gaps tr').textContent(),/DE\.CM-1.*arp_spoof, dns_anomaly/s);
 assert.equal(await page.locator('#compliance-gap-count').innerText(),'(1)');
 const [download]=await Promise.all([page.waitForEvent('download'),page.click('#compliance-report')]);
 assert.equal(download.suggestedFilename(),'compliance-nist_csf.html');

 // MITRE: 이 기간에 탐지가 없는 기법.
 await page.click('[data-tab="mitre"]');
 await page.waitForFunction(()=>document.querySelectorAll('#mitre-gaps tr').length===1);
 assert.match(await page.locator('#mitre-gaps tr').textContent(),/T1046.*Network Service Discovery/s);

 // 토폴로지: 게이트웨이는 후보로만 표시한다.
 await page.click('[data-tab="topology"]');
 await page.waitForFunction(()=>document.querySelector('#topology-gateways').textContent.includes('10.0.0.1'));
 assert.equal(await page.locator('#topology-gateways').innerText(),'10.0.0.1 (router)');

 assert.deepEqual(errors,[]);
 console.log('observability browser checks passed');
}finally{await browser.close();server.close();}})().catch(error=>{console.error(error);process.exit(1);});
