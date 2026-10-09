const fs = require('fs');
const assert = require('assert/strict');
const {chromium} = require(process.env.PANOPTICON_PLAYWRIGHT_CORE);
const fixture = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
async function login(page, username) {
    await page.goto(fixture.url);
    await page.getByLabel('사용자 이름', {exact:true}).fill(username);
    await page.getByLabel('비밀번호', {exact:true}).fill(fixture.password);
    await page.getByRole('button', {name:'로그인',exact:true}).click();
    await page.locator('#login-overlay.hidden').waitFor({state:'attached'});
    await page.locator('#connection-status.connected').waitFor({state:'visible'});
    await page.locator('[data-tab="blocklist"]').click();
    await page.evaluate(async () => {window.blocklistVerification = await import('/js/modules/blocklist.js');});
    await page.waitForFunction(() => window.blocklistVerification.blocklistStatus().loaded);
}
async function add(page, value) {
    await page.locator('#btn-add-blocklist').click();
    await page.locator('#bf-type').selectOption('ip');
    await page.locator('#bf-value').fill(value);
    await page.locator('#bf-notes').fill('Browser operator evidence');
    await page.locator('#blocklist-form button[type="submit"]').click();
}
(async () => {
    const browser = await chromium.launch({executablePath:process.env.PANOPTICON_CHROME, headless:true,args:['--no-sandbox']});
    const errors = [];
    try {
        const context = await browser.newContext({viewport:{width:1440,height:1000}});
        const page = await context.newPage();
        page.on('pageerror',error => errors.push(error.message));
        page.on('dialog',dialog => dialog.accept());
        await login(page,'control-admin');
        assert.equal(await page.locator('#blocklist-body button').count(),0);
        const raw = '198.51.100.7/24';
        const normalized = fixture.legacy ? raw : '198.51.100.0/24';
        await add(page,raw);
        await page.locator('#blocklist-form-overlay.hidden').waitFor({state:'attached'});
        const row = page.locator('#blocklist-body tr').filter({hasText:normalized});
        await row.waitFor();
        assert.equal(await row.locator('td').count(),4);
        assert.equal(await page.locator('#blocklist-table th').count(),4);
        await row.locator('[data-bl-details]').click();
        await page.waitForFunction(() => document.querySelector('#bl-details').textContent.includes('Browser operator evidence'));
        await row.locator('[data-remove-type]').click();
        await page.waitForFunction(() => window.blocklistVerification.blocklistStatus().loaded && !document.querySelector('#blocklist-body').textContent.includes('198.51.100.'));
        const mutation = fixture.legacy ? '**/api/blocklist/ip' : '**/api/blocklist/entry';
        await page.route(mutation,route => route.request().method() === 'GET' ? route.continue() : route.fulfill({status:409,contentType:'application/json',body:JSON.stringify({detail:{code:'owned_conflict'}})}));
        await add(page,'198.51.100.33');
        await page.waitForFunction(() => window.blocklistVerification.blocklistStatus().failed);
        assert.equal(await page.locator('#blocklist-form button[type="submit"]').isDisabled(),true);
        await page.evaluate(async () => {await window.blocklistVerification.loadBlocklist(0);});
        assert.equal(await page.locator('#btn-add-blocklist').isDisabled(),true);
        await page.locator('#blocklist-form-cancel-btn').click();
        await page.unroute(mutation);
        await page.locator('#bl-refresh').click();
        await page.waitForFunction(() => window.blocklistVerification.blocklistStatus().loaded);
        let deliveries = 0;
        await page.route(mutation,async route => {
            if (route.request().method() === 'GET') return route.continue();
            deliveries++; await route.fetch(); await route.abort('failed');
        });
        await add(page,'198.51.100.44');
        await page.waitForFunction(() => window.blocklistVerification.blocklistStatus().failed);
        assert.equal(deliveries,1);
        await page.evaluate(async () => {await window.blocklistVerification.changeBlocklist('ip','198.51.100.55',true);});
        assert.equal(deliveries,1);
        await page.locator('#blocklist-form-cancel-btn').click();
        await page.unroute(mutation);
        await page.locator('#bl-refresh').click();
        await page.waitForFunction(() => window.blocklistVerification.blocklistStatus().loaded);
        assert.equal(await page.locator('#blocklist-body tr').filter({hasText:'198.51.100.44'}).count(),1);
        for (const width of [1440,390]) {
            await page.setViewportSize({width,height:900});
            assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth+2));
        }
        let arrived,release;
        const arrival = new Promise(resolve => {arrived=resolve;});
        const hold = new Promise(resolve => {release=resolve;});
        await page.route('**/api/blocklist?*',async route => {arrived();await hold;await route.continue();});
        await page.locator('#bl-refresh').click(); await arrival;
        await page.evaluate(async () => {(await import('/js/core/api.js')).handleUnauthorized();});
        release(); await page.locator('#login-overlay:not(.hidden)').waitFor();
        await page.waitForTimeout(200);
        assert.equal(await page.evaluate(() => window.blocklistVerification.blocklistStatus().loaded),false);
        assert.equal(await page.locator('#blocklist-body tr').count(),0);
        await context.close();
        const readerContext = await browser.newContext({viewport:{width:390,height:900}});
        const reader = await readerContext.newPage();
        reader.on('pageerror',error => errors.push(error.message));
        await login(reader,'viewer');
        assert.equal(await reader.locator('#btn-add-blocklist').isDisabled(),true);
        assert.equal(await reader.locator('#blocklist-body [data-remove-type]:not([disabled])').count(),0);
        await reader.locator('[data-bl-details]').click();
        await reader.waitForFunction(() => document.querySelector('#bl-details').textContent.includes('Browser operator evidence'));
        assert.ok(await reader.evaluate(() => document.documentElement.scrollWidth <= innerWidth+2));
        assert.deepEqual(errors,[]);
        await readerContext.close();
        console.log('blocklist browser checks passed');
    } finally {await browser.close();}
})().catch(error => {console.error(error);process.exit(1);});
