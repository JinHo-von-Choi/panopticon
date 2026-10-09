const fs = require('fs');
const assert = require('assert/strict');
const {chromium} = require(process.env.PANOPTICON_PLAYWRIGHT_CORE);
const fixture = JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
async function login(page,user) {
    await page.goto(fixture.url);
    await page.locator('#login-username').fill(user);
    await page.locator('#login-password').fill(fixture.password);
    await page.getByRole('button',{name:'로그인',exact:true}).click();
    await page.locator('#login-overlay.hidden').waitFor({state:'attached'});
    await page.locator('[data-tab="governance"]').click();
    await page.evaluate(async()=>{window.proposalVerification=await import('/js/modules/proposals.js');});
    await ready(page);
}
async function ready(page) {await page.waitForFunction(()=>window.proposalVerification.proposalStatus().loaded && !window.proposalVerification.proposalStatus().busy);}
async function failed(page) {await page.waitForFunction(()=>window.proposalVerification.proposalStatus().failed);}
async function refresh(page) {await page.locator('#proposal-control-refresh').click();await page.waitForFunction(()=>!window.proposalVerification.proposalStatus().failed);await ready(page);}
(async()=>{
    const browser=await chromium.launch({executablePath:process.env.PANOPTICON_CHROME||'/usr/bin/google-chrome',headless:true,args:['--no-sandbox']});
    const errors=[];
    try {
        const context=await browser.newContext({viewport:{width:1440,height:1100}});
        const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));page.on('dialog',d=>d.accept());
        await login(page,'control-admin');
        assert.equal(await page.locator('#proposal-panel').isVisible(),true);
        assert.equal(await page.locator('#proposals-body tr').count(),50);
        await page.locator('#proposal-page-next').click();await page.waitForFunction(()=>window.proposalVerification.proposalStatus().offset===50);await ready(page);
        assert.equal(await page.locator('#proposals-body tr').count(),1);
        await page.locator('#proposal-page-prev').click();await page.waitForFunction(()=>window.proposalVerification.proposalStatus().offset===0);await ready(page);
        await page.locator('#proposal-threshold').fill('10');
        await page.locator('#proposal-reason').fill('<img src=x onerror=window.proposalInjected=1>');
        await page.locator('#proposal-create-submit').click();
        await page.waitForFunction(()=>document.querySelector('#proposals-body').textContent.includes('onerror=window.proposalInjected=1'));await ready(page);
        assert.equal(await page.locator('#proposals-body img').count(),0);
        assert.equal(await page.evaluate(()=>window.proposalInjected),undefined);
        const id=Number(await page.locator('#proposals-body tr').first().getAttribute('data-proposal-id'));
        const row=()=>page.locator(`[data-proposal-id="${id}"]`);
        assert.equal(await row().locator('[data-proposal-approve]').isDisabled(),true);
        await row().locator('[data-proposal-validate]').click();
        const records=count=>Array.from({length:count},(_,i)=>({src_ip:'192.0.2.1',dst_ip:'192.0.2.2',dst_port:i,bytes:120,ts:i/100,ip_proto:'tcp'}));
        for(const [label,count] of [['normal',6],['attack',20]]) {
            await page.locator(`#replay-${label}-file`).setInputFiles({name:label+'.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(records(count)))});
        }
        await page.locator('#replay-label-confirmed').check();await page.locator('#replay-submit').click();
        await page.locator('#replay-comparison [data-state="preserved"]').waitFor({timeout:30000});
        await page.locator('#replay-comparison > button').click();
        await page.waitForFunction(id=>!document.querySelector(`[data-proposal-approve="${id}"]`)?.disabled,id);
        await row().locator('[data-proposal-approve]').click();
        await page.waitForFunction(id=>!document.querySelector(`[data-proposal-approve="${id}"]`),id);await ready(page);
        assert.ok((await row().textContent()).includes('반영'));
        assert.equal(await page.locator('[data-proposal-validate]').first().isDisabled(),true);
        const victim=await page.locator('[data-proposal-reject]').first().getAttribute('data-proposal-reject');
        const mutation='**/api/proposals/'+victim+'/reject';
        await page.route(mutation,r=>r.fulfill({status:409,contentType:'application/json',body:JSON.stringify({detail:{code:'proposal_changed'}})}));
        await page.locator(`[data-proposal-reject="${victim}"]`).click();await failed(page);
        await page.evaluate(()=>window.i18next.emit('languageChanged','ko'));
        assert.equal(await page.locator(`[data-proposal-reject="${victim}"]`).isDisabled(),true);
        await page.unroute(mutation);await refresh(page);
        let deliveries=0;
        await page.route(mutation,async r=>{deliveries++;await r.fetch();await r.abort('failed');});
        await page.locator(`[data-proposal-reject="${victim}"]`).click();await failed(page);
        assert.equal(deliveries,1);
        await page.evaluate(id=>window.proposalVerification.decideProposal(Number(id),'reject'),victim);
        assert.equal(deliveries,1);
        await page.unroute(mutation);await refresh(page);
        assert.equal(await page.locator(`[data-proposal-reject="${victim}"]`).count(),0);
        const other=await page.locator('[data-proposal-reject]').first().getAttribute('data-proposal-reject');
        const otherMutation='**/api/proposals/'+other+'/reject';
        await page.route(otherMutation,async r=>{
            const body=r.request().postDataJSON();
            await r.fulfill({status:200,contentType:'application/json',body:JSON.stringify({status:'applied',control_process:'separate',request_id:body.request_id,base_version:'a'.repeat(64),validation_required:true,proposal:{id:Number(other)+1,status:'rejected'}})});
        });
        await page.locator(`[data-proposal-reject="${other}"]`).click();await failed(page);
        await page.unroute(otherMutation);await refresh(page);
        for(const width of [1440,390]) {
            await page.setViewportSize({width,height:1000});
            assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2));
        }
        await page.setViewportSize({width:1440,height:1100});await page.screenshot({path:fixture.screenshot,fullPage:true});
        const viewer=await browser.newPage();viewer.on('pageerror',e=>errors.push(e.message));await login(viewer,'viewer');
        assert.equal(await viewer.locator('#proposal-create-form').isVisible(),false);
        assert.equal(await viewer.locator('[data-proposal-approve],[data-proposal-reject],[data-proposal-validate]').count(),0);
        const analyst=await browser.newPage();analyst.on('pageerror',e=>errors.push(e.message));await login(analyst,'analyst');
        assert.equal(await analyst.locator('#proposal-create-form').isVisible(),true);
        assert.equal(await analyst.locator('[data-proposal-approve],[data-proposal-reject]').count(),0);
        assert.ok(await analyst.locator('[data-proposal-validate]').count()>0);
        let release,entered;const started=new Promise(r=>entered=r);const held=new Promise(r=>release=r);
        await page.route(otherMutation,async r=>{entered();await held;await r.fulfill({status:503,body:'{}'});});
        await page.locator(`[data-proposal-reject="${other}"]`).click();await started;
        await page.evaluate(()=>window.i18next.emit('languageChanged','ko'));
        assert.equal(await page.locator(`[data-proposal-reject="${other}"]`).isDisabled(),true);
        await page.locator('#btn-logout').click();
        release();await page.locator('#login-overlay:not(.hidden)').waitFor();
        await page.waitForTimeout(100);
        assert.equal(await page.locator('#proposals-body tr').count(),0);
        assert.equal(await page.locator('#proposal-create-form').isVisible(),false);
        await analyst.locator('#proposal-threshold').fill('20');
        await analyst.locator('#proposal-create-submit').click();
        await analyst.waitForFunction(()=>document.querySelector('#proposals-body tr')?.textContent.includes('threshold=20'));await ready(analyst);
        let releaseReplay,enteredReplay;const replayStarted=new Promise(r=>enteredReplay=r);const replayHold=new Promise(r=>releaseReplay=r);
        await analyst.route('**/api/replay-runs?*',async r=>{enteredReplay();await replayHold;await r.continue();});
        await analyst.locator('[data-proposal-validate]').first().click();await replayStarted;
        await analyst.locator('#btn-logout').click();releaseReplay();
        await analyst.locator('#login-overlay:not(.hidden)').waitFor();await analyst.waitForTimeout(100);
        assert.equal(await analyst.locator('#replay-comparison').textContent(),'');
        assert.equal(await analyst.locator('#replay-runs').textContent(),'');
        assert.equal(await analyst.locator('#proposals-body tr').count(),0);
        assert.deepEqual(errors,[]);
        console.log('proposal browser checks passed');
    } finally {await browser.close();}
})().catch(e=>{console.error(e.stack);process.exit(1);});
