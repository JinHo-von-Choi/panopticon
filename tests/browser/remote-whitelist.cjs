const fs = require('fs');
const assert = require('assert/strict');
const {chromium} = require(process.env.PANOPTICON_PLAYWRIGHT_CORE);
const fixture = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));

async function login(page, username) {
    await page.goto(fixture.url);
    await page.getByLabel('사용자 이름', {exact:true}).fill(username);
    await page.getByLabel('비밀번호', {exact:true}).fill(fixture.password);
    await page.getByRole('button', {name:'로그인', exact:true}).click();
    await page.locator('#login-overlay.hidden').waitFor({state:'attached'});
    await page.locator('[data-tab="whitelist"]').click();
    await page.evaluate(async () => {window.whitelistVerification = await import('/js/core/whitelist-state.js');});
    await page.waitForFunction(() => window.whitelistVerification.whitelistStatus().loaded);
}
async function add(page, value) {
    await page.locator('#btn-add-whitelist').click();
    await page.locator('#wf-type').selectOption('ip');
    await page.locator('#wf-value').fill(value);
    await page.locator('#whitelist-form button[type="submit"]').click();
}

(async () => {
    const browser = await chromium.launch({executablePath:process.env.PANOPTICON_CHROME,
        headless:true, args:['--no-sandbox']});
    const errors = [];
    try {
        const context = await browser.newContext({viewport:{width:1440,height:1000}});
        const page = await context.newPage();
        page.on('pageerror', error => errors.push(error.message));
        page.on('dialog', dialog => dialog.accept());
        let writes = 0;
        const writeDetails = [];
        page.on('request', request => {
            if (request.method() === 'PUT' && request.url().endsWith('/api/whitelist/entry')) {
                writes++;
                const body = request.postDataJSON();
                writeDetails.push({type:body.type,value:body.value,present:body.present});
            }
        });
        await login(page, 'control-admin');
        if (fixture.legacy) {
            const cases = [['ip','192.0.2.2','192.0.2.2'],['ip_range','192.0.2.71/24','192.0.2.0/24'],
                ['mac','02:AA:00:00:00:91','02:aa:00:00:00:91'],['domain','Backup.Example','backup.example'],
                ['suffix','.Office.Example','.office.example']];
            const operations = [];
            page.on('request', request => {
                if (request.method() === 'POST' && request.url().endsWith('/api/whitelist/toggle')) {
                    operations.push(request.postDataJSON());
                }
            });
            for (const [type,value,normalized] of cases) {
                for (let repeat=0;repeat<2;repeat++) {
                    await page.locator('#btn-add-whitelist').click();
                    await page.locator('#wf-type').selectOption(type);
                    await page.locator('#wf-value').fill(value);
                    await page.locator('#whitelist-form button[type="submit"]').click();
                    await page.locator('#whitelist-form-overlay.hidden').waitFor({state:'attached'});
                    assert.equal(await page.locator('#whitelist-body tr').filter({hasText:normalized}).count(),1);
                }
                await page.locator('#whitelist-body tr').filter({hasText:normalized}).getByRole('button').click();
                await page.waitForFunction(text => !document.querySelector('#whitelist-body').textContent.includes(text),normalized);
            }
            assert.equal(operations.length,15);
            assert.equal(operations.filter(body => body.present === true).length,10);
            assert.equal(operations.filter(body => body.present === false).length,5);
            assert.equal(writes,0);
            for (const width of [1440,390]) {
                await page.setViewportSize({width,height:900});
                assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth+2));
            }
            assert.deepEqual(errors,[]);
            await context.close();
            console.log('whitelist browser checks passed');
            return;
        }
        await add(page, '192.0.2.91');
        await page.locator('#whitelist-body tr').filter({hasText:'192.0.2.91'}).waitFor();
        assert.equal(writes, 1);
        await page.evaluate(async () => {
            const {getAuthToken} = await import('/js/core/api.js');
            const headers = {'Authorization':'Bearer '+getAuthToken(),'Content-Type':'application/json'};
            const current = await (await fetch('/api/whitelist',{headers})).json();
            const response = await fetch('/api/whitelist/entry',{method:'PUT',headers,
                body:JSON.stringify({request_id:crypto.randomUUID(),base_version:current.base_version,
                    type:'ip',value:'192.0.2.92',present:true})});
            if (!response.ok) throw Error('Concurrent change failed');
        });
        await add(page, '192.0.2.93');
        await page.waitForFunction(() => document.querySelector('#whitelist-control-status').textContent.includes('거절'));
        assert.equal(await page.locator('#btn-add-whitelist').isDisabled(), true);
        await page.evaluate(async () => { await (await import('/js/modules/devices.js')).fetchWhitelist(); });
        assert.equal(await page.locator('#btn-add-whitelist').isDisabled(), true);
        await page.locator('#whitelist-form-cancel-btn').click();
        await page.locator('#whitelist-refresh').click();
        await page.locator('#whitelist-body tr').filter({hasText:'192.0.2.92'}).waitFor();
        let deliveries = 0;
        let requestId;
        await page.route('**/api/whitelist/entry', async route => {
            const body = route.request().postDataJSON();
            assert.match(body.request_id,/^[a-f0-9-]{36}$/);
            assert.match(body.base_version,/^[a-f0-9]{64}$/);
            assert.equal(body.present,true);
            requestId = body.request_id;
            deliveries++;
            const applied = await route.fetch();
            assert.equal(applied.status(),200);
            await route.abort();
        });
        await add(page, '192.0.2.94');
        await page.waitForFunction(() => document.querySelector('#whitelist-control-status').textContent.includes('결과를 확인하지'));
        assert.equal(await page.locator('#btn-add-whitelist').isDisabled(),true);
        assert.equal(deliveries,1);
        const beforeBlocked = writes;
        await page.locator('#whitelist-form-cancel-btn').click();
        await page.evaluate(async eventId => { await window.showEventDetail(eventId); },fixture.event_id);
        assert.equal(await page.locator('[data-wl-event-ip]').isDisabled(),true);
        await page.evaluate(async () => {
            await (await import('/js/modules/devices.js')).toggleWhitelist('ip','192.0.2.95');
        });
        assert.equal(writes,beforeBlocked);
        await page.evaluate(() => window.closeModal());
        await page.unroute('**/api/whitelist/entry');
        await page.locator('#whitelist-refresh').click();
        await page.locator('#whitelist-body tr').filter({hasText:'192.0.2.94'}).waitFor();
        const audit = await page.evaluate(async identifier => {
            const {getAuthToken} = await import('/js/core/api.js');
            return (await fetch('/api/audit/changes/'+identifier,{headers:{'Authorization':'Bearer '+getAuthToken()}})).json();
        },requestId);
        assert.equal(audit.outcome,'applied');
        assert.equal(audit.requires_reconciliation,false);
        await page.locator('#whitelist-body tr').filter({hasText:'192.0.2.91'}).getByRole('button').click();
        await page.waitForFunction(() => !document.querySelector('#whitelist-body').textContent.includes('192.0.2.91'));
        await page.evaluate(async () => { await window.showDeviceDetail('02:00:00:00:00:91'); });
        await page.locator('[data-wl-mac]').click();
        await page.waitForFunction(() => window.whitelistVerification.whitelistData.macs.includes('02:00:00:00:00:91'));
        await page.evaluate(() => window.closeDeviceModal());
        await page.waitForFunction(() => !window.whitelistVerification.whitelistStatus().busy);
        for (const width of [1440,390]) {
            await page.setViewportSize({width,height:900});
            assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 2));
            const state = await page.evaluate(async () => (await import('/js/core/whitelist-state.js')).whitelistStatus());
            assert.equal(await page.locator('#btn-add-whitelist').isDisabled(),false,JSON.stringify({state,writes:writeDetails}));
        }
        await page.setViewportSize({width:1440,height:900});
        let arrived;
        const held = new Promise(resolve => {arrived = resolve;});
        let release;
        const hold = new Promise(resolve => {release = resolve;});
        await page.route('**/api/whitelist',async route => { arrived(); await hold; await route.continue(); });
        await page.locator('#whitelist-refresh').click();
        await held;
        await page.evaluate(async () => { (await import('/js/core/api.js')).handleUnauthorized(); });
        release();
        await page.locator('#login-overlay:not(.hidden)').waitFor();
        await page.waitForTimeout(150);
        const afterLogout = await page.evaluate(async () => {
            const state = await import('/js/core/whitelist-state.js');
            return {loaded:state.whitelistStatus().loaded,ips:state.whitelistData.ips};
        });
        assert.equal(afterLogout.loaded,false);
        assert.deepEqual(afterLogout.ips,[]);
        await context.close();
        const viewer = await browser.newContext({viewport:{width:390,height:900}});
        const reader = await viewer.newPage();
        reader.on('pageerror',error => errors.push(error.message));
        await login(reader,'viewer');
        assert.equal(await reader.locator('#btn-add-whitelist').isDisabled(),true);
        assert.equal(await reader.locator('#whitelist-body [data-wl-remove]:not([disabled])').count(),0);
        assert.ok(await reader.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 2));
        await viewer.close();
        assert.deepEqual(errors,[]);
        console.log('whitelist browser checks passed');
    } finally { await browser.close(); }
})().catch(error => {console.error(error.stack);process.exitCode=1;});
