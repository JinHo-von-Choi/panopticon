/** EVE 모드 장치 탭: Suricata가 관측한 내부 주소. 전수 자산 목록이 아니다. */
import { authFetch } from '../core/api.js';
import { featureState } from '../core/capabilities.js';

const PAGE = 100;
let requestId = 0, offset = 0, registered = false;
const t = (key, options) => window.i18next.t(`console.observed_assets.${key}`, options);
const el = id => document.getElementById(`observed-assets-${id}`);

function cell(value) {
    const node = document.createElement('td');
    node.textContent = value ?? '—';
    return node;
}

function evidenceText(evidence) {
    return Object.entries(evidence || {}).sort((a, b) => b[1] - a[1]).map(([kind, count]) => `${kind} ${count}`).join(', ');
}

export async function loadObservedAssets(start = 0) {
    const panel = el('panel');
    panel.hidden = featureState('observed_assets').state !== 'available';
    if (panel.hidden) return;
    const id = ++requestId;
    offset = start;
    el('status').textContent = t('loading');
    const params = new URLSearchParams({ limit: PAGE, offset });
    const search = el('search').value.trim();
    if (search) params.set('search', search);
    try {
        const response = await authFetch('/api/observed-assets?' + params);
        if (response?.status === 422) throw new Error('search');
        if (!response?.ok) throw new Error('unavailable');
        const body = await response.json();
        if (id !== requestId) return;
        el('body').replaceChildren(...body.assets.map(asset => {
            const row = document.createElement('tr');
            row.append(cell(asset.ip), cell(asset.mac), cell(new Date(asset.first_seen).toLocaleString()),
                cell(new Date(asset.last_seen).toLocaleString()), cell(evidenceText(asset.evidence)),
                cell(`${asset.sensor_id}/${asset.source_id}`));
            return row;
        }));
        el('status').textContent = body.total ? t('range', { from: offset + 1, to: offset + body.assets.length, total: body.total })
            : t('empty');
        el('prev').disabled = offset === 0;
        el('next').disabled = offset + body.assets.length >= body.total;
    } catch (error) {
        if (id !== requestId) return;
        el('body').replaceChildren();
        el('status').textContent = t(error.message === 'search' ? 'invalid_search' : 'unavailable');
    }
}

export function registerObservedAssetListeners() {
    if (registered) return;
    registered = true;
    el('refresh').addEventListener('click', () => loadObservedAssets(0));
    el('search').addEventListener('change', () => loadObservedAssets(0));
    el('prev').addEventListener('click', () => loadObservedAssets(Math.max(0, offset - PAGE)));
    el('next').addEventListener('click', () => loadObservedAssets(offset + PAGE));
}
