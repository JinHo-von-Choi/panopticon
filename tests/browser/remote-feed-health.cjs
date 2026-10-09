const fs = require('fs');
const assert = require('assert/strict');
const {chromium} = require(process.env.PANOPTICON_PLAYWRIGHT_CORE);
const fixture = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
(async () => {
    const browser = await chromium.launch({executablePath:process.env.PANOPTICON_CHROME || '/usr/bin/google-chrome',headless:true,args:['--no-sandbox']});
    const errors = [];
    let page;
    try {
        page = await browser.newPage({viewport:{width:1440,height:1000}});
        page.on('pageerror',error => errors.push(error.message));
        await page.goto(fixture.url);
        await page.getByLabel('사용자 이름',{exact:true}).fill('feed-viewer');
        await page.getByLabel('비밀번호',{exact:true}).fill(fixture.password);
        await page.getByRole('button',{name:'로그인',exact:true}).click();
        await page.locator('#login-overlay.hidden').waitFor({state:'attached'});
    await page.locator('#connection-status.connected').waitFor({state:'visible'});
        await page.waitForFunction(async () =>
            (await import('/js/core/api.js')).isAuthEnabled() &&
            (await import('/js/core/capabilities.js')).featureEnabled('engines'));
        await page.locator('[data-tab="governance"]').click();
        await page.locator(`[data-feed-status="${fixture.phase==='escape' ? 'ok' : fixture.phase}"]`).waitFor();
        const box = page.locator('#support-profile-box');
        const content = await box.innerText();
        if (fixture.phase === 'ok') {
            assert.match(content,/최신/);assert.match(content,/1 IP/);assert.match(content,/1 도메인/);
        } else if (fixture.phase === 'stale') {
            assert.match(content,/갱신 지연/);assert.match(content,/SUP-060/);
        } else if (fixture.phase === 'degraded') {
            assert.match(content,/일부 피드 확인 필요/);assert.match(content,/SUP-060/);
            const rows=page.locator('#feed-source-status tbody tr');
            assert.equal(await rows.count(),2);
            assert.match(await rows.nth(0).innerText(),/최신.*다운로드/s);
            assert.match(await rows.nth(1).innerText(),/갱신 지연.*캐시 사용/s);
        } else if (fixture.phase === 'escape') {
            assert.match(content,/<img src=x onerror=window.feedInjected=1>/);
            assert.equal(await page.locator('#feed-source-status img').count(),0);
            assert.equal(await page.evaluate(() => window.feedInjected),undefined);
        } else if (fixture.phase === 'unknown') {
            assert.match(content,/확인 불가/);assert.match(content,/— IP/);assert.doesNotMatch(content,/0 IP|한 번도|갱신 기록 없음/);
        } else {
            assert.match(content,/연결 안 됨/);assert.match(content,/— IP/);assert.doesNotMatch(content,/0 IP|갱신 기록 없음/);
        }
        for (const width of [1440,390]) {
            await page.setViewportSize({width,height:900});
            assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth+2));
        }
        if (fixture.phase === 'ok') {
            let release,arrived;
            const hold = new Promise(resolve => {release=resolve;});
            const arrival = new Promise(resolve => {arrived=resolve;});
            await page.route('**/api/support-profile',async route => {const response=await route.fetch();arrived();await hold;await route.fulfill({response});});
            await page.evaluate(() => {import('/js/modules/governance.js').then(module => module.loadSupportProfile());});
            await arrival;
            await page.evaluate(async () => (await import('/js/core/api.js')).handleUnauthorized());
            release();await page.locator('#login-overlay:not(.hidden)').waitFor();
            await page.waitForTimeout(200);
            assert.equal(await box.innerText(),'');
        }
        assert.deepEqual(errors,[]);
        process.stdout.write('feed health browser checks passed\n');
    } catch (error) {
        if (page) process.stderr.write(JSON.stringify(await page.evaluate(() => ({
            activeTab: document.querySelector('.tab.active')?.dataset.tab,
            observation: document.getElementById('observation-box')?.innerText.slice(0,500),
            support: document.getElementById('support-profile-box')?.innerText.slice(0,500),
            loginVisible: !document.getElementById('login-overlay')?.classList.contains('hidden')
        })))+'\n'+JSON.stringify(errors)+'\n');
        throw error;
    } finally {await browser.close();}
})().catch(error => {process.stderr.write(error.stack+'\n');process.exit(1);});
