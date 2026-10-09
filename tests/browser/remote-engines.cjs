const fs = require('fs');
const path = require('path');
const assert = require('assert/strict');
const {chromium} = require(process.env.PANOPTICON_PLAYWRIGHT_CORE);
const fixture = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));

async function login(page, username) {
    await page.goto(fixture.url);
    await page.getByLabel('사용자 이름', {exact: true}).fill(username);
    await page.getByLabel('비밀번호', {exact: true}).fill(fixture.password);
    await page.getByRole('button', {name: '로그인', exact: true}).click();
    await page.locator('#login-overlay.hidden').waitFor({state: 'attached'});
    await page.locator('#connection-status.connected').waitFor({state:'visible'});
    await page.locator('[data-tab="engines"]').click();
    await page.locator('[data-engine="port_scan"]').waitFor({state:'attached'});
}

(async () => {
    const browser = await chromium.launch({executablePath: process.env.PANOPTICON_CHROME,
        headless: true, args: ['--no-sandbox']});
    const errors = [];
    try {
        const context = await browser.newContext({viewport: {width: 1440, height: 1000}});
        const page = await context.newPage();
        page.on('pageerror', error => errors.push(error.message));
        await login(page, 'control-admin');
        const select = page.locator('.engine-card').filter({has:page.locator('[data-engine="port_scan"]')}).getByRole('button');
        await select.focus();
        await select.press('Enter');
        assert.equal(await select.evaluate(node => node === document.activeElement), true);
        assert.equal(await page.getByLabel(/포트 스캔 임계값/).count(), 1);
        const field = page.locator('#engine-config-form [name="threshold"]');
        await field.fill('12oops');
        let writes = 0;
        page.on('request', request => {
            if (['PUT','PATCH'].includes(request.method()) && request.url().includes('/api/engines/')) writes++;
        });
        await page.getByRole('button', {name:'설정 저장',exact:true}).click();
        await page.getByText('숫자와 목록의 입력 형식을 확인하세요.', {exact:true}).waitFor();
        assert.equal(writes, 0);
        await field.fill('20');
        let displayedVersion;
        await page.route('**/api/engines/port_scan/config', async route => {
            const body = route.request().postDataJSON();
            assert.match(body.request_id, /^[a-f0-9-]{36}$/);
            assert.match(body.base_version, /^[a-f0-9]{64}$/);
            displayedVersion = body.base_version;
            await route.continue();
        });
        await page.getByRole('button', {name:'설정 저장',exact:true}).click();
        await page.getByText('센서에 설정을 반영했습니다.', {exact:true}).first().waitFor();
        await page.waitForFunction(() => document.querySelector('#engine-config-form [name="threshold"]')?.value === '20');
        assert.equal(writes, 1);
        assert.ok(displayedVersion);
        await page.unroute('**/api/engines/port_scan/config');
        await page.evaluate(async () => {
            const {getAuthToken}=await import('/js/core/api.js');
            const headers={'Authorization':'Bearer '+getAuthToken(),'Content-Type':'application/json'};
            const current=await (await fetch('/api/engines/port_scan',{headers})).json();
            const response=await fetch('/api/engines/port_scan/config',{method:'PUT',headers,
                body:JSON.stringify({request_id:crypto.randomUUID(),base_version:current.base_version,config:{threshold:30}})});
            if(!response.ok) throw Error('Concurrent configuration did not apply');
        });
        await field.fill('22');
        await page.getByRole('button', {name:'설정 저장',exact:true}).click();
        await page.getByText('변경이 거절됐습니다. 권한과 최신 설정을 확인하세요.', {exact:true}).waitFor();
        assert.equal(await page.getByRole('button', {name:'설정 저장',exact:true}).isDisabled(), true);
        assert.equal(await page.locator('[data-engine-state]').textContent(), '상태 확인 필요');
        await page.locator('#engine-control-refresh').click();
        await page.waitForFunction(() => document.querySelector('#engine-config-form [name="threshold"]')?.value === '30');
        let delivered = 0;
        await page.route('**/api/engines/port_scan/toggle', async route => {
            delivered++;
            const response = await route.fetch();
            assert.equal(response.status(), 200);
            await route.fulfill({response, status:503, body:'{"detail":{"code":"sensor_result_unknown"}}'});
        });
        await page.locator('[data-engine="port_scan"]').locator('..').click();
        await page.getByText('변경 결과를 확인하지 못했습니다. 자동 재요청하지 않습니다. 설정을 다시 조회하세요.', {exact:true}).waitFor();
        await page.waitForTimeout(500);
        assert.equal(delivered, 1);
        assert.equal(await page.locator('[data-engine="port_scan"]').isDisabled(), true);
        assert.equal(await page.getByRole('button', {name:'설정 저장',exact:true}).isDisabled(), true);
        await page.locator('#engine-control-refresh').click();
        await page.waitForFunction(() => {
            const node=document.querySelector('[data-engine="port_scan"]');
            return node && !node.checked && !node.disabled;
        });
        assert.equal(delivered, 1);
        await page.unroute('**/api/engines/port_scan/toggle');
        assert.equal(await page.locator('[data-engine-state]').textContent(), '탐지 꺼짐');
        await page.route('**/api/engines', route => route.fulfill({status:503,body:'{}'}));
        await page.locator('#engine-control-refresh').click();
        await page.getByText('설정을 불러오지 못했습니다. 다시 조회하세요.', {exact:true}).waitFor();
        assert.equal(await page.locator('[data-engine]').count(), 0);
        await page.unroute('**/api/engines');
        await page.locator('#engine-control-refresh').click();
        await page.locator('#engine-config-form').waitFor();
        for (const viewport of [{width:1440,height:1000},{width:390,height:844}]) {
            await page.setViewportSize(viewport);
            assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
            assert.equal(await page.getByRole('button', {name:'설정 저장',exact:true}).isVisible(), true);
            await page.screenshot({path:path.join(path.dirname(process.argv[2]),`engines-${viewport.width}.png`), fullPage:true});
        }
        const viewerContext = await browser.newContext({viewport:{width:390,height:844}});
        const viewer = await viewerContext.newPage();
        viewer.on('pageerror', error => errors.push(error.message));
        await login(viewer, 'viewer');
        assert.equal(await viewer.locator('[data-engine="port_scan"]').isDisabled(), true);
        await viewer.locator('[data-engine="port_scan"]').locator('..').locator('..').click();
        assert.equal(await viewer.getByRole('button', {name:'설정 저장',exact:true}).isDisabled(), true);
        await viewerContext.close();
        await page.locator('#engine-config-form [name="threshold"]').fill('25');
        let release;
        const held = new Promise(resolve => { release=resolve; });
        let entered;
        const enteredPromise = new Promise(resolve => { entered=resolve; });
        await page.route('**/api/engines/port_scan/config', async route => {
            const response=await route.fetch();
            assert.equal(response.status(),200);
            entered();
            await held;
            await route.fulfill({response});
        });
        await page.getByRole('button', {name:'설정 저장',exact:true}).click();
        await enteredPromise;
        await page.locator('#btn-logout').click();
        await page.locator('#login-overlay').waitFor({state:'visible'});
        release();
        await page.waitForTimeout(500);
        assert.equal(await page.locator('[data-engine]').count(),0);
        assert.equal(await page.locator('#engine-control-status').textContent(),'');
        assert.deepEqual(errors,[]);
        console.log('engine browser checks passed');
    } finally {
        await browser.close();
    }
})().catch(error => { console.error(error); process.exit(1); });
