// Run: node tests/browser/mitre-matrix.cjs
const { chromium } = require(process.env.PANOPTICON_PLAYWRIGHT_CORE || 'playwright-core');
const http = require('http'), fs = require('fs'), path = require('path'), assert = require('assert/strict');
const root = path.resolve(__dirname, '../../netwatcher/web/static');
const layer = {
    name: 'NetWatcher Coverage', domain: 'enterprise-attack',
    versions: { attack: '14', navigator: '4.9.1', layer: '4.5' },
    techniques: [
        { techniqueID: 'T1046', tactic: 'discovery', score: 25, comment: 'Detected 2 time(s)',
            metadata: [{ name: 'Technique name', value: 'Network Service Discovery' }, { name: 'Detection count', value: '2' }] },
        { techniqueID: 'T1190', tactic: 'initial_access', score: 50, comment: 'Detected 5 time(s)',
            metadata: [{ name: 'Technique name', value: 'Exploit Public-Facing Application' }] },
        { techniqueID: 'T1071.004', tactic: 'command-and-control', score: 75, comment: 'Detected 20 time(s)',
            metadata: [{ name: 'Technique name', value: 'DNS' }] },
        { techniqueID: 'T1486', tactic: 'impact', score: 100, comment: 'Detected 50 time(s)',
            metadata: [{ name: 'Technique name', value: 'Data Encrypted for Impact' }] },
        { techniqueID: 'T1498', tactic: 'impact', score: 100, comment: 'Detected 100 time(s)',
            metadata: [{ name: 'Technique name', value: '<img src=x onerror=alert(1)>' }] },
        { techniqueID: 'T9999', tactic: '', score: 25, comment: 'Custom layer' },
        { techniqueID: 'T1595', tactic: 'reconnaissance', enabled: false, score: 25 },
    ],
};
let mode = 'ok', delayOne = false;
const requests = [], pending = new Set();
const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/')) {
        res.setHeader('Content-Type', 'application/json');
        if (url.pathname === '/api/auth/status') return res.end('{"enabled":false}');
        if (url.pathname === '/api/hunting/navigator') {
            requests.push(url.searchParams.get('hours'));
            const current = mode;
            const data = current === 'empty' ? { ...layer, techniques: [] } : current === 'invalid' ? {} : layer;
            const respond = () => { res.statusCode = current === 'error' ? 503 : 200; res.end(JSON.stringify(data)); };
            if (delayOne && url.searchParams.get('hours') === '1') {
                const promise = new Promise(resolve => setTimeout(() => { respond(); resolve(); }, 300));
                pending.add(promise); promise.finally(() => pending.delete(promise)); return;
            }
            return respond();
        }
        res.statusCode = 503; return res.end('{}');
    }
    const file = path.join(root, url.pathname === '/' ? 'index.html' : url.pathname);
    try {
        res.setHeader('Content-Type', file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.json') ? 'application/json' : 'text/html');
        res.end(fs.readFileSync(file));
    } catch { res.statusCode = 404; res.end(); }
});
(async () => {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const browser = await chromium.launch({ executablePath: process.env.PANOPTICON_CHROME || '/usr/bin/google-chrome', headless: true, args: ['--no-sandbox'] });
    try {
        const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
        const errors = []; page.on('pageerror', e => errors.push(e.message));
        await page.goto(`http://127.0.0.1:${server.address().port}`);
        await page.waitForFunction(() => window.i18next?.isInitialized);
        await page.selectOption('#lang-selector', 'en');
        await page.click('[data-tab="mitre"]');
        await page.waitForFunction(() => document.querySelectorAll('.mitre-technique-card').length === 6);
        assert.deepEqual(requests, ['24']);
        assert.equal(await page.locator('#tab-mitre').evaluate(e => e.classList.contains('active')), true);
        assert.equal(await page.locator('.mitre-tactic-col').count(), 14);
        assert.equal(await page.locator('[data-tactic="initial-access"] [data-technique="T1190"]').count(), 1);
        const card = page.locator('[data-technique="T1046"]');
        assert.ok((await card.innerText()).includes('Network Service Discovery'));
        assert.ok((await card.innerText()).includes('2 detections'));
        assert.deepEqual(await page.locator('[data-technique="T1046"], [data-technique="T1190"], [data-technique="T1071.004"], [data-technique="T1486"], [data-technique="T1498"]').evaluateAll(cards => cards.map(c => c.dataset.heat)), ['2', '1', '3', '5', '4']);
        assert.equal(await page.locator('#mitre-matrix-grid img').count(), 0);
        assert.equal(await page.locator('[data-technique="T9999"] .mitre-frequency').innerText(), 'Detection count unavailable');
        await page.fill('#mitre-search', 'service discovery');
        assert.equal(await page.locator('.mitre-technique-card').count(), 1);
        await card.focus(); await page.keyboard.press('Enter');
        assert.equal(await page.locator('#mitre-detail').evaluate(e => e.open), true);
        assert.ok((await page.locator('#mitre-detail-body').innerText()).includes('25/100'));
        await page.keyboard.press('Escape');
        await page.waitForFunction(() => !document.querySelector('#mitre-detail').open);
        assert.equal(await card.evaluate(e => e === document.activeElement), true);
        const downloadPromise = page.waitForEvent('download');
        await page.click('#mitre-export'); const download = await downloadPromise;
        assert.equal(download.suggestedFilename(), 'mitre-layer-24h.json');
        assert.deepEqual(JSON.parse(fs.readFileSync(await download.path(), 'utf8')), layer);
        await page.fill('#mitre-search', 'nothing-matches');
        assert.equal(await page.locator('.mitre-technique-card').count(), 0);
        await page.fill('#mitre-search', '');
        await page.selectOption('#mitre-hours', '1');
        await page.waitForFunction(() => document.querySelectorAll('.mitre-technique-card').length === 6);
        await page.selectOption('#mitre-hours', '168');
        await page.waitForFunction(() => document.querySelectorAll('.mitre-technique-card').length === 6);
        assert.deepEqual(requests.slice(-2), ['1', '168']);
        for (const lang of ['ko', 'en']) {
            await page.selectOption('#lang-selector', lang);
            await page.waitForFunction(l => window.i18next.language === l, lang);
            assert.equal(await page.locator('#mitre-hours').inputValue(), '168');
            const missing = await page.evaluate(() => [...document.querySelectorAll('#tab-mitre [data-i18n], #tab-mitre [data-i18n-aria-label]')].map(e => e.dataset.i18n || e.dataset.i18nAriaLabel).filter(key => !window.i18next.exists(key)));
            assert.deepEqual(missing, []);
            assert.equal(await card.locator('.mitre-frequency').innerText(), lang === 'ko' ? '탐지 2회' : '2 detections');
        }
        for (const theme of ['operator', 'auditor', 'cinematic']) {
            await page.selectOption('#theme-selector', theme);
            const ratios = await page.evaluate(() => {
                const rgb = color => color.match(/[\d.]+/g).slice(0, 3).map(Number);
                const lum = c => rgb(c).map(v => v / 255).map(v => v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4).reduce((a, v, i) => a + v * [.2126, .7152, .0722][i], 0);
                return [...document.querySelectorAll('.mitre-technique-card, .mitre-frequency, .mitre-tactic-col h4')].map(e => {
                    const style = getComputedStyle(e), a = lum(style.color), b = lum(style.backgroundColor);
                    return (Math.max(a, b) + .05) / (Math.min(a, b) + .05);
                });
            });
            assert.ok(ratios.every(r => r >= 4.5), `${theme}: ${ratios}`);
            assert.equal(new Set(await page.locator('.mitre-technique-card[data-heat]:not([data-heat="0"])').evaluateAll(cards => cards.map(c => getComputedStyle(c).borderLeftColor))).size, 5);
        }
        await page.check('#hud-scanlines-toggle'); await card.click();
        await page.click('#mitre-detail button');
        await page.setViewportSize({ width: 390, height: 844 });
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'page overflow');
        assert.ok(await page.locator('.mitre-matrix-scroll').evaluate(e => e.scrollWidth > e.clientWidth));
        await page.locator('.mitre-matrix-scroll').focus(); await page.keyboard.press('ArrowRight');
        await page.waitForFunction(() => document.querySelector('.mitre-matrix-scroll').scrollLeft > 0);
        await page.setViewportSize({ width: 1440, height: 1000 });
        for (const badMode of ['empty', 'error', 'invalid']) {
            mode = badMode; await page.click('#mitre-refresh');
            await page.waitForFunction(key => document.querySelector('#mitre-state').textContent === window.i18next.t('console.mitre.' + key), badMode === 'empty' ? 'empty' : 'unavailable');
            assert.equal(await page.locator('.mitre-technique-card').count(), 0);
            assert.equal(await page.locator('#mitre-export').isEnabled(), badMode === 'empty');
            assert.equal(await page.locator('#mitre-refresh').isEnabled(), true);
        }
        // A slower earlier range must not replace a later result or restore cleared session data.
        delayOne = true; mode = 'ok';
        await page.selectOption('#mitre-hours', '1');
        await page.waitForFunction(() => document.querySelector('#mitre-matrix-grid').getAttribute('aria-busy') === 'true');
        mode = 'empty'; await page.selectOption('#mitre-hours', '24');
        await page.waitForFunction(() => document.querySelector('#mitre-state').textContent === window.i18next.t('console.mitre.empty'));
        await Promise.all([...pending]);
        assert.equal(await page.locator('.mitre-technique-card').count(), 0);
        mode = 'ok'; await page.click('#mitre-refresh');
        await page.waitForFunction(() => document.querySelectorAll('.mitre-technique-card').length === 6);
        await card.click();
        await page.evaluate(() => window.dispatchEvent(new Event('nw-session-ended')));
        assert.equal(await page.locator('.mitre-technique-card').count(), 0);
        assert.equal(await page.locator('#mitre-export').isEnabled(), false);
        assert.equal(await page.locator('#mitre-detail-body').innerText(), '');
        await page.click('[data-tab="mitre"]');
        await page.waitForFunction(() => document.querySelectorAll('.mitre-technique-card').length === 6);
        await page.selectOption('#mitre-hours', '1');
        await page.evaluate(() => window.dispatchEvent(new Event('nw-session-ended')));
        await Promise.all([...pending]);
        assert.equal(await page.locator('.mitre-technique-card').count(), 0);
        assert.deepEqual(errors, []);
        console.log('PASS: MITRE tab/API, tactic grouping, names/counts/heat, search, keyboard dialog, full JSON export, en/ko, all theme contrasts >=4.5, mobile scroll, failure/recovery, stale responses and session cleanup');
    } finally { await browser.close(); server.close(); }
})().catch(error => { console.error(error); server.close(); process.exitCode = 1; });
