const fs = require('fs');
const assert = require('assert/strict');
const {chromium} = require(process.env.PANOPTICON_PLAYWRIGHT_CORE);
const fixture = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
(async () => {
    const browser = await chromium.launch({executablePath:process.env.PANOPTICON_CHROME || '/usr/bin/google-chrome',headless:true,args:['--no-sandbox']});
    const errors = [];
    const responses = [];
    let page;
    let stage = "navigation";
    try {
        page = await browser.newPage({viewport:{width:1440,height:1000}});
        page.on('pageerror', error => errors.push(error.message));
        page.on('response', response => {
            const path = new URL(response.url()).pathname;
            if (path.startsWith('/api/')) responses.push({path, status: response.status()});
        });
        await page.goto(fixture.url);
        stage = "capabilities";
        await page.waitForFunction(async () =>
            (await import('/js/core/api.js')).isAuthEnabled() &&
            (await import('/js/core/capabilities.js')).featureEnabled('eve_observations'));
        stage = "initial-data";
        await page.locator("#connection-status.connected").waitFor({state: "visible"});
        await page.locator('#console-readiness[data-state="not_ready"]').waitFor({state: "visible"});
        await page.evaluate(() => {
            window.eveInputTrace = [];
            for (const type of ['pointerdown', 'pointerup', 'click']) {
                document.addEventListener(type, event => {
                    const button = event.target.closest('button');
                    window.eveInputTrace.push({type, trusted: event.isTrusted,
                        button: button?.id, tab: button?.dataset.tab});
                }, true);
            }
        });
        stage = "select-governance";
        await page.locator('#console-readiness').click();
        await page.locator('#tab-governance.active').waitFor({state:'visible'});
        stage = "observation";
        const box = page.locator('#observation-box');
        await box.getByRole('columnheader', {name:'수집 대기량',exact:true}).waitFor();
        const cells = box.locator('tbody tr').first().locator('td');
        if (fixture.phase === 'backlog') {
            assert.equal(await cells.nth(1).innerText(), '수집 대기량 증가');
            assert.match(await cells.nth(3).innerText(), /MB|MiB/);
        } else {
            assert.equal(await cells.nth(3).innerText(), '확인 불가');
            assert.equal(await cells.nth(1).innerText(), '수집 확인 필요');
        }
        assert.equal(await cells.nth(4).innerText(), '0');
        assert.equal(await cells.nth(5).innerText(), '0');
        for (const width of [1440,390]) {
            await page.setViewportSize({width,height:900});
            assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 2));
        }
        assert.deepEqual(errors, []);
        process.stdout.write('EVE backlog browser checks passed\n' + JSON.stringify({phase: fixture.phase, requests: responses.length}) + '\n');
    } catch (error) {
        if (page) process.stderr.write(JSON.stringify({phase: fixture.phase, stage, responses, error: error.message, state: await page.evaluate(async () => ({
            inputTrace: window.eveInputTrace,
            focus: document.activeElement?.id,
            authEnabled: (await import("/js/core/api.js")).isAuthEnabled(),
            eveEnabled: (await import("/js/core/capabilities.js")).featureEnabled("eve_observations"),
            activeTab: document.querySelector('.tab.active')?.dataset.tab,
            observation: document.getElementById('observation-box')?.innerText.slice(0,500),
            support: document.getElementById('support-profile-box')?.innerText.slice(0,500),
            loginVisible: !document.getElementById('login-overlay')?.classList.contains('hidden')
        }))})+'\n'+JSON.stringify(errors)+'\n');
        throw error;
    } finally {await browser.close();}
})().catch(error => {process.stderr.write(error.stack+'\n');process.exit(1);});
