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
    await page.locator('[data-tab="defense"]').click();
    await page.evaluate(async () => {window.rulesVerification = await import('/js/modules/rules.js');});
    await page.waitForFunction(() => window.rulesVerification.rulesStatus().loaded);
}
async function ready(page) {await page.waitForFunction(() => window.rulesVerification.rulesStatus().loaded && !window.rulesVerification.rulesStatus().busy);}

(async () => {
    const browser = await chromium.launch({executablePath:process.env.PANOPTICON_CHROME || '/usr/bin/google-chrome',headless:true,args:['--no-sandbox']});
    const errors = [];
    try {
        const context = await browser.newContext({viewport:{width:1440,height:1000}});
        const page = await context.newPage();
        page.on('pageerror',error => errors.push(error.message));
        await login(page,'control-admin');
        const toggle = page.locator('[data-rule-toggle="OWNED-001"]');
        assert.equal(await page.locator('#signature-rules').isVisible(),true);
        assert.equal(await page.locator('#defense-legacy').isVisible(),false);
        assert.equal(await page.locator('#response-panel').isVisible(),false);
        assert.equal(await toggle.isChecked(),true);
        assert.equal(await page.locator('#rules-body tr').count(),50);
        await page.locator('#rules-pagination').getByRole('button',{name:'Next',exact:true}).click(); await ready(page);
        assert.equal(await page.locator('#rules-body tr').count(),11);
        await page.locator('#rules-pagination').getByRole('button',{name:'Prev',exact:true}).click(); await ready(page);
        await toggle.uncheck(); await ready(page);
        assert.equal(await toggle.isChecked(),false);
        await toggle.check(); await ready(page);
        assert.equal(await toggle.isChecked(),true);
        const mutation = fixture.legacy ? '**/api/rules/OWNED-001/toggle' : '**/api/rules/entry';
        await page.route(mutation,route => route.fulfill({status:409,contentType:'application/json',body:JSON.stringify({detail:{code:'owned_conflict'}})}));
        await toggle.uncheck();
        await page.waitForFunction(() => window.rulesVerification.rulesStatus().failed);
        assert.equal(await page.locator('#btn-rules-reload').isDisabled(),true);
        await page.evaluate(async () => {await window.rulesVerification.loadRules();});
        assert.equal(await toggle.isDisabled(),true);
        await page.unroute(mutation);
        await page.locator('#btn-rules-refresh').click(); await ready(page);
        assert.equal(await toggle.isChecked(),true);
        let deliveries = 0;
        await page.route(mutation,async route => {deliveries++;await route.fetch();await route.abort('failed');});
        await toggle.uncheck();
        await page.waitForFunction(() => window.rulesVerification.rulesStatus().failed);
        assert.equal(deliveries,1);
        await page.evaluate(async () => {await window.rulesVerification.changeRule('OWNED-001',true);});
        assert.equal(deliveries,1);
        await page.unroute(mutation);
        await page.locator('#btn-rules-refresh').click(); await ready(page);
        assert.equal(await toggle.isChecked(),false);
        await page.locator('#btn-rules-reload').click(); await ready(page);
        assert.equal(await toggle.isChecked(),true);
        // 성공 응답이어도 대상·적용 상태가 다르면 결과를 확정하지 않는다.
        await page.route(mutation,async route => {
            const body = route.request().postDataJSON();
            await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(fixture.legacy
                ? {status:'ok',rule_id:'other-rule',enabled:false}
                : {status:'applied',request_id:body.request_id,base_version:'a'.repeat(64),rules_hash:'b'.repeat(64),control_process:'separate',rule:{id:'other-rule'}})});
        });
        await toggle.uncheck();
        await page.waitForFunction(() => window.rulesVerification.rulesStatus().failed);
        await page.unroute(mutation);
        await page.locator('#btn-rules-refresh').click(); await ready(page);
        assert.equal(await toggle.isChecked(),true);
        for (const width of [1440,390]) {
            await page.setViewportSize({width,height:900});
            assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth+2));
        }
        let arrived,release;
        const arrival = new Promise(resolve => {arrived=resolve;});
        const hold = new Promise(resolve => {release=resolve;});
        await page.route('**/api/rules?*',async route => {arrived();await hold;await route.continue();});
        await page.locator('#btn-rules-refresh').click(); await arrival;
        await page.evaluate(async () => {(await import('/js/core/api.js')).handleUnauthorized();});
        release(); await page.locator('#login-overlay:not(.hidden)').waitFor();
        await page.waitForTimeout(200);
        assert.equal(await page.evaluate(() => window.rulesVerification.rulesStatus().loaded),false);
        assert.equal(await page.locator('#rules-body tr').count(),0);
        await context.close();
        const readerContext = await browser.newContext({viewport:{width:390,height:900}});
        const reader = await readerContext.newPage();
        reader.on('pageerror',error => errors.push(error.message));
        await login(reader,'viewer');
        assert.equal(await reader.locator('[data-rule-toggle]:not([disabled])').count(),0);
        assert.equal(await reader.locator('#btn-rules-reload').isDisabled(),true);
        assert.equal(await reader.evaluate(async () => window.rulesVerification.changeRule('OWNED-001',false)),false);
        assert.equal(await reader.locator('[data-rule-toggle="OWNED-001"]').isChecked(),true);
        assert.deepEqual(errors,[]);
        await readerContext.close();
        console.log('rules browser checks passed');
    } finally {await browser.close();}
})().catch(error => {console.error(error);process.exit(1);});
