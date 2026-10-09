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
    await page.locator('[data-tab="defense"]').click();
    await page.locator('.response-columns').waitFor();
}

(async () => {
    const browser = await chromium.launch({executablePath: process.env.PANOPTICON_CHROME,
        headless: true, args: ['--no-sandbox']});
    try {
        const context = await browser.newContext({viewport: {width: 1440, height: 1000}});
        const page = await context.newPage();
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        await login(page, 'admin');
        assert.equal(await page.locator('#defense-legacy').isVisible(), false);
        const proposal = page.locator(`[data-proposal-id="${fixture.proposal}"]`);
        await proposal.locator('summary').click();
        await proposal.getByText('관측된 관련 자산', {exact: true}).waitFor();
        await proposal.getByLabel('승인 사유', {exact: true}).fill('업무 장치 소유 관계 확인');
        await proposal.getByRole('button', {name: '승인 기록', exact: true}).click();
        await page.getByText('승인을 기록했습니다. 실행은 별도로 요청하세요.', {exact: true}).waitFor();
        let action = page.locator('[data-action-id]').first();
        await action.getByText('승인됨 · 실행 전', {exact: true}).waitFor();
        const id = await action.getAttribute('data-action-id');
        await action.getByRole('button', {name: '실행 의도 기록', exact: true}).click();
        action = page.locator(`[data-action-id="${id}"]`);
        await action.getByText('미확정', {exact: true}).waitFor();
        assert.equal(await action.locator('[data-response-operation="activate"]').count(), 0);
        await action.getByRole('button', {name: '실제 상태 대조', exact: true}).click();
        await page.getByText('요청 결과를 기록했습니다. Shadow 모드에서는 OS를 변경하지 않습니다.', {exact: true}).waitFor();
        await action.locator('summary').click();
        await action.getByText(/확인되지 않음/).first().waitFor();
        for (const viewport of [{width: 1440, height: 1000}, {width: 390, height: 844}]) {
            await page.setViewportSize(viewport);
            assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
            assert.equal(await page.locator('[data-response-result]').isVisible(), true);
            await page.screenshot({path: path.join(path.dirname(process.argv[2]), `response-${viewport.width}.png`), fullPage: true});
        }
        let deliveries = 0;
        const lostUrl = `**/api/change-proposals/${fixture.lost_proposal}/approve`;
        await page.route(lostUrl, async route => {
            deliveries++;
            const response = await route.fetch();
            assert.equal(response.status(), 201);
            await route.fulfill({response, status: 503, body: JSON.stringify({error: 'Injected response loss'})});
        });
        const lost = page.locator(`[data-proposal-id="${fixture.lost_proposal}"]`);
        await lost.getByLabel('승인 사유', {exact: true}).fill('응답 유실 회귀 검사');
        await lost.getByRole('button', {name: '승인 기록', exact: true}).click();
        await page.getByText('요청 결과를 확인하지 못했습니다. 자동 재요청하지 않습니다. 새로고침해 기록을 확인하세요.', {exact: true}).waitFor();
        await page.waitForTimeout(600);
        assert.equal(deliveries, 1);
        assert.equal(await lost.getByRole('button', {name: '승인 기록', exact: true}).isDisabled(), true);
        await page.locator('[data-response-refresh]').click();
        await page.waitForFunction(() => document.querySelectorAll('[data-action-id]').length === 2);
        assert.equal(deliveries, 1);
        // 기능 정보가 없으면 기존 차단 조작 화면으로 돌아가지 않는다.
        await page.route('**/api/response/capabilities', route => route.fulfill({status: 503, body: '{}'}));
        await page.locator('[data-tab="events"]').click();
        await page.locator('[data-tab="defense"]').click();
        await page.getByText('자료를 불러오지 못했습니다. 새로고침해 확인하세요.', {exact: true}).waitFor();
        assert.equal(await page.locator('#defense-legacy').isVisible(), false);
        assert.equal(await page.locator('[data-response-approve]').count(), 0);
        const viewerContext = await browser.newContext({viewport: {width: 390, height: 844}});
        const viewer = await viewerContext.newPage();
        viewer.on('pageerror', error => errors.push(error.message));
        await login(viewer, 'viewer');
        assert.equal(await viewer.locator('[data-response-operation], [data-response-approve]').count(), 0);
        const viewerAction = viewer.locator(`[data-action-id="${id}"]`);
        await viewerAction.locator('summary').click();
        await viewerAction.getByText(/확인되지 않음/).first().waitFor();
        await page.unroute('**/api/response/capabilities');
        let intercepted;
        let release;
        const held = new Promise(resolve => { release = resolve; });
        const started = new Promise(resolve => { intercepted = resolve; });
        await page.route('**/api/response-actions?limit=50', async route => {
            const response = await route.fetch();
            intercepted();
            await held;
            await route.fulfill({response});
        });
        await page.locator('#response-panel').getByRole('button', {name: '새로고침', exact: true}).click();
        await started;
        await page.evaluate(async () => (await import('/js/core/api.js')).handleUnauthorized());
        await page.locator('#login-overlay:not(.hidden)').waitFor();
        release();
        await page.waitForTimeout(250);
        assert.equal(await page.locator('#response-panel').evaluate(element => element.childElementCount), 0);
        assert.deepEqual(errors, []);
        await viewerContext.close();
        await context.close();
        process.stdout.write('browser checks passed: approval, separate execution, receipts, mobile, viewer, lost reply, capability failure, stale session\n');
    } finally {
        await browser.close();
    }
})().catch(error => {process.stderr.write(error.stack + '\n'); process.exitCode = 1;});
