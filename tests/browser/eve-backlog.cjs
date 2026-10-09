const fs = require('fs');
const assert = require('assert/strict');
const {chromium} = require(process.env.PANOPTICON_PLAYWRIGHT_CORE);
const fixture = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
(async () => {
    const browser = await chromium.launch({executablePath:process.env.PANOPTICON_CHROME || '/usr/bin/google-chrome',headless:true,args:['--no-sandbox']});
    const errors = [];
    try {
        const page = await browser.newPage({viewport:{width:1440,height:1000}});
        page.on('pageerror', error => errors.push(error.message));
        await page.goto(fixture.url);
        await page.locator('[data-tab="governance"]').click();
        const box = page.locator('#observation-box');
        await box.getByRole('columnheader', {name:'수집 대기량',exact:true}).waitFor();
        const cells = box.locator('tbody tr').first().locator('td');
        if (fixture.phase === 'backlog') {
            assert.equal(await cells.nth(1).innerText(), '수집 대기량 증가');
            assert.match(await cells.nth(3).innerText(), /MB|MiB/);
        } else {
            assert.equal(await cells.nth(3).innerText(), '확인 불가');
            assert.equal(await cells.nth(1).innerText(), '수집 상태 점검 필요');
        }
        assert.equal(await cells.nth(4).innerText(), '0');
        assert.equal(await cells.nth(5).innerText(), '0');
        for (const width of [1440,390]) {
            await page.setViewportSize({width,height:900});
            assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 2));
        }
        assert.deepEqual(errors, []);
        process.stdout.write('EVE backlog browser checks passed\n');
    } finally {await browser.close();}
})().catch(error => {process.stderr.write(error.stack+'\n');process.exit(1);});
