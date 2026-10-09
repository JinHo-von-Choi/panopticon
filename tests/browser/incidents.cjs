const fs = require('fs');
const path = require('path');
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
    await page.locator('[data-tab="incidents"]').click();
    await page.locator('.incident-item').first().waitFor();
}

(async () => {
    const browser = await chromium.launch({executablePath:process.env.PANOPTICON_CHROME,
        headless:true,args:['--no-sandbox']});
    const errors = [];
    try {
        const context = await browser.newContext({viewport:{width:1440,height:1000}});
        const page = await context.newPage();
        page.on('pageerror', error => errors.push(error.message));
        await login(page, 'incident-admin');
        await page.locator(`[data-incident-id="${fixture.primary}"]`).click();
        await page.getByRole('heading',{name:'출발지 IP',exact:true}).waitFor();
        await page.getByRole('heading',{name:'탐지 엔진',exact:true}).waitFor();
        assert.equal(await page.locator('[data-block-ip]').count(), 0);
        let writes = 0;
        page.on('request', request => {
            if (request.method()==='POST' && /\/incidents\/\d+\/resolve$/.test(request.url())) writes++;
        });
        let release;
        const held = new Promise(resolve => {release=resolve;});
        let entered;
        const enteredPromise = new Promise(resolve => {entered=resolve;});
        await page.route(`**/api/incidents/${fixture.primary}/resolve`, async route => {
            const response = await route.fetch();
            assert.equal(response.status(), 200);
            entered();
            await held;
            await route.fulfill({response,status:503,body:'{"detail":"Lost reply"}'});
        });
        await page.locator('#incident-resolve').click();
        await enteredPromise;
        await page.getByText('해결 요청을 처리하는 중입니다.',{exact:true}).waitFor();
        assert.equal(await page.locator('#incident-resolve').isDisabled(), true);
        assert.equal(await page.locator('#btn-incidents-refresh').isDisabled(), true);
        release();
        await page.getByText('해결 결과를 확인하지 못했습니다. 자동 재요청하지 않습니다. 새로고침으로 상태를 확인하세요.',{exact:true}).waitFor();
        await page.waitForTimeout(500);
        assert.equal(writes, 1);
        assert.equal(await page.locator('#incident-resolve').isDisabled(), true);
        await page.unroute(`**/api/incidents/${fixture.primary}/resolve`);
        await page.route('**/api/incidents?*', route => route.fulfill({status:503,body:'{}'}));
        await page.locator('#btn-incidents-refresh').click();
        await page.locator('#incident-control-status').filter({hasText:'사건을 불러오지 못했습니다.'}).waitFor();
        assert.equal(await page.locator('.incident-item').count(), 0);
        assert.equal(await page.locator('#incident-resolve').count(), 0);
        await page.unroute('**/api/incidents?*');
        await page.locator('#incidents-show-resolved').check();
        await page.locator(`[data-incident-id="${fixture.primary}"]`).click();
        await page.locator('#incident-detail .incident-resolved-tag').waitFor();
        assert.equal(writes, 1);
        for (const viewport of [{width:1440,height:1000},{width:390,height:844}]) {
            await page.setViewportSize(viewport);
            assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
            await page.screenshot({path:path.join(path.dirname(process.argv[2]),`incidents-${viewport.width}.png`),fullPage:true});
        }
        const viewerContext = await browser.newContext({viewport:{width:390,height:844}});
        const viewer = await viewerContext.newPage();
        viewer.on('pageerror', error => errors.push(error.message));
        await login(viewer, 'viewer');
        await viewer.locator(`[data-incident-id="${fixture.secondary}"]`).click();
        assert.equal(await viewer.locator('#incident-resolve').isDisabled(), true);
        assert.equal(await viewer.locator('[data-block-ip]').count(), 0);
        await viewerContext.close();
        await page.locator(`[data-incident-id="${fixture.secondary}"]`).click();
        let releaseFinal;
        const heldFinal = new Promise(resolve => {releaseFinal=resolve;});
        let enteredFinal;
        const enteredFinalPromise = new Promise(resolve => {enteredFinal=resolve;});
        await page.route(`**/api/incidents/${fixture.secondary}/resolve`, async route => {
            const response = await route.fetch();
            assert.equal(response.status(), 200);
            enteredFinal();
            await heldFinal;
            await route.fulfill({response});
        });
        await page.locator('#incident-resolve').click();
        await enteredFinalPromise;
        await page.getByRole('button',{name:'로그아웃',exact:true}).click();
        releaseFinal();
        await page.waitForTimeout(500);
        assert.equal(writes, 2);
        assert.equal(await page.locator('.incident-item').count(), 0);
        assert.equal(await page.locator('#incident-control-status').textContent(), '');
        assert.deepEqual(errors, []);
        console.log('incident browser checks passed');
    } finally {
        await browser.close();
    }
})().catch(error => {console.error(error);process.exitCode=1;});
