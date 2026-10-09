const fs = require('fs');
const assert = require('assert/strict');
const crypto = require('crypto');
const {chromium} = require(process.env.PANOPTICON_PLAYWRIGHT_CORE);
const fixture = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));

async function open(page, username) {
    await page.goto(fixture.url);
    await page.getByLabel('사용자 이름', {exact:true}).fill(username);
    await page.getByLabel('비밀번호', {exact:true}).fill(fixture.password);
    await page.getByRole('button', {name:'로그인',exact:true}).click();
    await page.locator('#login-overlay.hidden').waitFor({state:'attached'});
    await page.evaluate(id => window.showEventDetail(id), fixture.event_id);
    await page.locator('#evidence-refresh').waitFor();
}
async function ready(page) {await page.waitForFunction(() => !document.getElementById('evidence-refresh').disabled);}
async function change(page) {
    const done = page.waitForResponse(response => response.url().endsWith('/evidence/pin'));
    await page.locator('#evidence-change').click(); await done; await ready(page);
}

(async () => {
    const browser = await chromium.launch({executablePath:process.env.PANOPTICON_CHROME || '/usr/bin/google-chrome',headless:true,args:['--no-sandbox']});
    const errors = [];
    try {
        const page = await browser.newPage({viewport:{width:1440,height:1000}});
        page.on('pageerror',error => errors.push(error.message));
        page.on('dialog',dialog => dialog.accept('사건 조사 자료 보존'));
        await open(page,'control-admin');
        let downloaded = page.waitForEvent('download');
        await page.locator('#evidence-download').click();
        const file = await downloaded;
        assert.equal(file.suggestedFilename(),`event-${fixture.event_id}.pcap`);
        assert.equal(crypto.createHash('sha256').update(fs.readFileSync(await file.path())).digest('hex'),fixture.sha256);
        await ready(page);
        await change(page);
        assert.equal(await page.locator('#evidence-change').innerText(),'검토 보존 해제');
        await page.evaluate(() => window.i18next.emit('languageChanged', 'ko'));
        assert.equal(await page.locator('#evidence-change').innerText(),'검토 보존 해제');
        await change(page);
        const mutation = '**/api/events/*/evidence/pin';
        await page.route(mutation,route => route.fulfill({status:409,contentType:'application/json',body:'{}'}));
        await change(page);
        assert.equal(await page.locator('#evidence-change').isDisabled(),true);
        assert.match(await page.locator('#evidence-control-status').innerText(),/거절/);
        await page.unroute(mutation);
        await page.locator('#evidence-refresh').click(); await ready(page);
        let finishPending, pendingArrived;
        const pendingHold = new Promise(resolve => {finishPending=resolve;});
        const pendingArrival = new Promise(resolve => {pendingArrived=resolve;});
        await page.route(mutation,async route => {
            pendingArrived(); await pendingHold;
            await route.fulfill({status:409,contentType:'application/json',body:'{}'});
        });
        await page.locator('#evidence-change').click(); await pendingArrival;
        await page.evaluate(() => window.i18next.emit('languageChanged', 'ko'));
        assert.equal(await page.locator('#evidence-change').isDisabled(),true);
        const pendingResponse = page.waitForResponse(response => response.url().endsWith('/evidence/pin'));
        finishPending(); await pendingResponse;
        await page.unroute(mutation);
        assert.equal(await page.locator('#evidence-change').isDisabled(),true);
        await page.locator('#evidence-refresh').click(); await ready(page);
        await page.route(mutation,route => route.fulfill({status:200,contentType:'application/json',body:'{"status":"applied","request_id":"other"}'}));
        await change(page);
        assert.equal(await page.locator('#evidence-change').isDisabled(),true);
        assert.match(await page.locator('#evidence-control-status').innerText(),/확인하지 못/);
        await page.unroute(mutation);
        await page.locator('#evidence-refresh').click(); await ready(page);
        let deliveries = 0;
        await page.route(mutation,async route => {deliveries++;await route.fetch();await route.abort();});
        await page.locator('#evidence-change').click();
        await page.waitForFunction(() => document.getElementById('evidence-control-status').textContent.includes('확인하지 못'));
        assert.equal(deliveries,1);
        assert.equal(await page.locator('#evidence-change').isDisabled(),true);
        await page.evaluate(() => window.i18next.emit('languageChanged', 'ko'));
        assert.equal(await page.locator('#evidence-change').isDisabled(),true);
        await page.unroute(mutation);
        await page.locator('#evidence-refresh').click(); await ready(page);
        assert.equal(await page.locator('#evidence-change').innerText(),'검토 보존 해제');
        await change(page);
        await page.route('**/api/events/*/evidence/file',route => route.fulfill({status:200,headers:{'Content-Length':'24','X-Content-SHA256':'0'.repeat(64)},body:Buffer.alloc(24)}));
        await page.locator('#evidence-download').click(); await ready(page);
        assert.match(await page.locator('#evidence-control-status').innerText(),/완료하지 못/);
        await page.unroute('**/api/events/*/evidence/file');
        await page.locator('#evidence-refresh').click(); await ready(page);
        for (const width of [1440,390]) {
            await page.setViewportSize({width,height:900});
            assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth+2));
        }
        let release, arrived;
        const hold = new Promise(resolve => {release=resolve;});
        const arrival = new Promise(resolve => {arrived=resolve;});
        await page.route('**/api/events/*/evidence',async route => {arrived();await hold;await route.continue();});
        await page.locator('#evidence-refresh').click(); await arrival;
        await page.evaluate(async () => (await import('/js/core/api.js')).handleUnauthorized());
        release(); await page.locator('#login-overlay:not(.hidden)').waitFor();
        await page.waitForTimeout(200);
        await page.unroute('**/api/events/*/evidence');
        await open(page,'viewer');
        assert.equal(await page.locator('#evidence-change').count(),0);
        assert.equal(await page.locator('#evidence-download').isDisabled(),false);
        assert.deepEqual(errors,[]);
        process.stdout.write('evidence browser checks passed\n');
    } finally {await browser.close();}
})().catch(error => {process.stderr.write(error.stack+'\n');process.exit(1);});
