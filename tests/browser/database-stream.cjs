const fs = require('fs');
const assert = require('assert/strict');
const {chromium} = require(process.env.PANOPTICON_PLAYWRIGHT_CORE);
const fixture = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));

(async () => {
    const browser = await chromium.launch({executablePath: process.env.PANOPTICON_CHROME,
        headless: true, args: ['--no-sandbox']});
    try {
        const page = await browser.newPage({viewport: {width: 1440, height: 1000}});
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        await page.goto(fixture.url);
        await page.getByLabel('사용자 이름', {exact: true}).fill('admin');
        await page.getByLabel('비밀번호', {exact: true}).fill(fixture.password);
        await page.getByRole('button', {name: '로그인', exact: true}).click();
        await page.locator('#connection-status.connected').waitFor();
        process.stdout.write('READY\n');
        await page.locator('#events-body').getByText('먼저 커밋 경보', {exact: true}).waitFor();
        assert.equal(await page.locator('#events-body').getByText('늦은 커밋 경보', {exact: true}).count(), 0);
        process.stdout.write('FIRST\n');
        await page.locator('#events-body').getByText('늦은 커밋 경보', {exact: true}).waitFor();
        const refreshed = page.waitForResponse(response => response.url().includes('/api/events?') && response.status() === 200);
        process.stdout.write('SECOND\n');
        await page.locator('.toast-title').getByText('실시간 경보 재조회', {exact: true}).first().waitFor();
        await refreshed;
        await page.locator('#events-body').getByText('먼저 커밋 경보', {exact: true}).waitFor();
        await page.locator('#events-body').getByText('늦은 커밋 경보', {exact: true}).waitFor();
        assert.deepEqual(errors, []);
        process.stdout.write('browser stream checks passed: committed alerts, late commit, gap notice, stored-record refresh\n');
    } finally {
        await browser.close();
    }
})().catch(error => {process.stderr.write(error.stack + '\n'); process.exitCode = 1;});
