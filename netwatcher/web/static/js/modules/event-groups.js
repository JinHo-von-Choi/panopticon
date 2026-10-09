import { authFetch } from '../core/api.js';
import { esc, formatTime } from '../core/utils.js';

export async function loadEventGroup(ev, container, offset = 0) {
    if (!container) return;
    container.innerHTML = '<h3>반복 경보</h3><p>불러오는 중…</p>';
    try {
        const response = await authFetch(`/api/events/${ev.id}/group?offset=${offset}`);
        if (!response.ok) throw new Error('load failed');
        const data = await response.json();
        if (!data.available) {
            container.innerHTML = '';
            return;
        }
        container.innerHTML = '<h3>반복 경보</h3>' +
            `<p>${esc(formatTime(data.window.start))}부터 1시간 · ${esc(data.total)}건 · 판정 기록 없음 ${esc(data.without_review)}건 · 미종결 ${esc(data.not_closed)}건</p>` +
            '<p class="scope-note">같은 센서·규칙·주소·MAC 정보·서비스의 경보입니다. MAC 정보가 없으면 같은 장치인지 확인할 수 없습니다. 업무 판정과 담당자는 경보별로 적용됩니다. 기록된 판정의 현재 유효 여부는 해당 경보를 열어 확인하세요.</p>' +
            (!data.addresses_complete ? '<p>주소 정보가 부족해 이 경보만 표시합니다.</p>' : '') +
            data.events.map(event => `<div class="work-schedule-card"><button class="btn" data-group-event="${esc(event.id)}">${esc(formatTime(event.timestamp))} · ${esc(event.severity)} · 경보 #${esc(event.id)}</button><p>${esc(event.owner || '미배정')} · ${esc(({open:'미처리',investigating:'조사 중',closed:'종결'})[event.status] || event.status)} · ${event.recorded_decision ? '판정 기록 있음' : '판정 기록 없음'}</p></div>`).join('') +
            '<div class="review-actions">' +
            (offset > 0 ? '<button class="btn" data-group-prev>이전 경보</button>' : '') +
            (offset + data.events.length < data.total ? '<button class="btn" data-group-next>다음 경보</button>' : '') +
            '<button class="btn" data-group-refresh>새로고침</button></div>';
        container.querySelectorAll('[data-group-event]').forEach(button => button.addEventListener('click', () => window.showEventDetail(Number(button.dataset.groupEvent))));
        container.querySelector('[data-group-prev]')?.addEventListener('click', () => loadEventGroup(ev, container, Math.max(0, offset - 50)));
        container.querySelector('[data-group-next]')?.addEventListener('click', () => loadEventGroup(ev, container, offset + 50));
        container.querySelector('[data-group-refresh]')?.addEventListener('click', () => loadEventGroup(ev, container, offset));
    } catch {
        container.innerHTML = '<h3>반복 경보</h3><p>반복 경보를 불러오지 못했습니다.</p><button class="btn" data-group-refresh>다시 불러오기</button>';
        container.querySelector('[data-group-refresh]').addEventListener('click', () => loadEventGroup(ev, container, offset));
    }
}

let listRequest = 0;
export function initGroupList() {
    const panel = document.getElementById('event-groups-panel');
    if (!panel || panel.dataset.initialized) return;
    panel.dataset.initialized = 'true';
    const end = new Date();
    const start = new Date(end.getTime() - 24*60*60*1000);
    const localInput = date => new Date(date.getTime() - date.getTimezoneOffset()*60000).toISOString().slice(0,16);
    document.getElementById('group-period-start').value = localInput(start);
    document.getElementById('group-period-end').value = localInput(end);
    panel.addEventListener('toggle', () => {
        if (panel.open && !panel.dataset.loaded) loadGroupList();
    });
    document.getElementById('group-period-load').addEventListener('click', () => loadGroupList());
}

async function loadGroupList(offset = 0) {
    const request = ++listRequest;
    const panel = document.getElementById('event-groups-panel');
    const container = document.getElementById('event-group-list');
    panel.dataset.loaded = 'true';
    const start = new Date(document.getElementById('group-period-start').value);
    const end = new Date(document.getElementById('group-period-end').value);
    if (!Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime()) || end <= start || end - start > 7*86400000) {
        container.textContent = '시작과 종료 시각을 지정하세요. 조회 기간은 최대 7일입니다.';
        return;
    }
    container.textContent = '불러오는 중…';
    try {
        const params = new URLSearchParams({start:start.toISOString(),end:end.toISOString(),offset:String(offset)});
        const response = await authFetch('/api/events/groups?' + params);
        if (request !== listRequest) return;
        if (!response.ok) {
            container.textContent = response.status === 413 ? '경보가 50,000건을 넘습니다. 조회 기간을 줄여 주세요.' : '묶음을 불러오지 못했습니다. 묶음 조회를 눌러 다시 확인하세요.';
            return;
        }
        const data = await response.json();
        if (request !== listRequest) return;
        container.innerHTML = `<p>${esc(data.total)}개 묶음 · 보존 경보 ${esc(data.stored_alerts)}건 · ${esc(formatTime(data.snapshot_at))} 기준</p>` +
            '<p class="scope-note">심각도, 판정 기록 없음, 미종결 수 순으로 표시합니다. 저장된 판정의 현재 유효 여부는 개별 경보에서 확인하세요. 목록의 건수는 선택한 기간 기준이고, 상세는 해당 1시간 전체를 보여 줍니다. MAC 정보가 없으면 같은 장치인지 확인할 수 없습니다.</p>' +
            data.groups.map(group => `<div class="work-schedule-card"><button class="btn" data-open-group="${esc(group.representative_id)}">${esc(group.severity)} · ${esc(group.title)}</button><p>${esc(group.scope.src_ip || '주소 없음')} → ${esc(group.scope.dest_ip || '주소 없음')} · ${esc(group.scope.proto || '-')} / ${esc(group.scope.dest_port ?? '-')}</p><p>${esc(formatTime(group.window_start))}부터 1시간 · ${esc(group.occurrences)}건 · 판정 기록 없음 ${esc(group.without_review)}건 · 미종결 ${esc(group.not_closed)}건</p><p>센서 ${esc(group.scope.sensor_id)} · 입력 ${esc(group.scope.source_id)}</p></div>`).join('') +
            (data.total === 0 ? '<p>이 기간에 보존된 EVE 경보가 없습니다.</p>' : '') +
            '<div class="review-actions">' +
            (offset > 0 ? '<button class="btn" data-group-list-prev>이전 묶음</button>' : '') +
            (offset + data.groups.length < data.total ? '<button class="btn" data-group-list-next>다음 묶음</button>' : '') + '</div>';
        container.querySelectorAll('[data-open-group]').forEach(button => button.addEventListener('click', () => window.showEventDetail(Number(button.dataset.openGroup))));
        container.querySelector('[data-group-list-prev]')?.addEventListener('click', () => loadGroupList(Math.max(0, offset - 50)));
        container.querySelector('[data-group-list-next]')?.addEventListener('click', () => loadGroupList(offset + 50));
    } catch {
        if (request === listRequest) container.textContent = '묶음을 불러오지 못했습니다. 묶음 조회를 눌러 다시 확인하세요.';
    }
}

export function initPreviousEvents(ev, container) {
    if (!container) return;
    container.innerHTML = '<details><summary>같은 조건의 이전 경보</summary><div data-previous-events></div></details>';
    const disclosure = container.querySelector('details');
    disclosure.addEventListener('toggle', () => {
        if (disclosure.open && !disclosure.dataset.loaded) {
            disclosure.dataset.loaded = 'true';
            loadPreviousEvents(ev,container.querySelector('[data-previous-events]'));
        }
    });
}

const previousRequests = new WeakMap();
async function loadPreviousEvents(ev, container, offset = 0) {
    const request = (previousRequests.get(container) || 0) + 1;
    previousRequests.set(container, request);
    container.textContent = '불러오는 중…';
    try {
        const response = await authFetch(`/api/events/${ev.id}/similar?offset=${offset}`);
        if (!response.ok) throw new Error('previous unavailable');
        const data = await response.json();
        if (previousRequests.get(container) !== request) return;
        if (!data.available) {
            container.textContent = data.reason === 'addresses_required' ? '주소 정보가 부족해 이전 경보를 비교할 수 없습니다.' : 'EVE 경보에서 이전 경보를 비교할 수 있습니다.';
            return;
        }
        container.innerHTML = `<p>${esc(formatTime(data.window.start))}부터 ${esc(formatTime(data.window.end))} 직전까지 · 보존 경보 ${esc(data.total)}건</p>` +
            '<p class="scope-note">현재 1시간 묶음 이전의 같은 센서·입력·규칙·주소·MAC 정보·서비스를 비교합니다. 이전 판정은 당시 기록이며 현재 경보에 적용되지 않습니다. 보존 중인 기록만 표시합니다.</p>' +
            (!data.scope.src_mac ? '<p>출발 MAC 정보가 없어 같은 장치에서 발생했는지 확인할 수 없습니다.</p>' : '') +
            data.events.map(event => `<div class="work-schedule-card"><button class="btn" data-previous-event="${esc(event.id)}">${esc(formatTime(event.timestamp))} · ${esc(event.severity)} · 경보 #${esc(event.id)}</button><p>${esc(event.owner || '미배정')} · ${esc(window.i18next.t('console.case_workflow.statuses.'+event.status))}</p><p>기록된 판정: ${event.recorded_decision ? esc(window.i18next.t('console.business_review.decisions.'+event.recorded_decision)) : '없음'}</p>${event.review_note ? '<p class="case-note">판정 근거: '+esc(event.review_note)+'</p><p>판정자: '+esc(event.reviewer)+' · '+esc(formatTime(event.reviewed_at))+'</p>' : ''}${event.expires_at ? '<p>기록된 유효 기한: '+esc(formatTime(event.expires_at))+'</p>' : ''}${event.recorded_asset_context?.role ? '<p>판정 당시 장치 역할: '+esc(event.recorded_asset_context.role)+'</p>' : ''}${event.handover_note ? '<p class="case-note">마지막 인계: '+esc(event.handover_note)+'</p>' : ''}</div>`).join('') +
            (data.total === 0 ? '<p>이 기간에 보존된 같은 조건의 이전 경보가 없습니다.</p>' : '') +
            '<div class="review-actions">' + (offset>0 ? '<button class="btn" data-previous-prev>이전 기록</button>' : '') +
            (offset+data.events.length<data.total ? '<button class="btn" data-previous-next>다음 기록</button>' : '') +
            '<button class="btn" data-previous-refresh>이전 경보 새로고침</button></div>';
        container.querySelectorAll('[data-previous-event]').forEach(button=>button.addEventListener('click',()=>window.showEventDetail(Number(button.dataset.previousEvent))));
        container.querySelector('[data-previous-prev]')?.addEventListener('click',()=>loadPreviousEvents(ev,container,Math.max(0,offset-50)));
        container.querySelector('[data-previous-next]')?.addEventListener('click',()=>loadPreviousEvents(ev,container,offset+50));
        container.querySelector('[data-previous-refresh]').addEventListener('click',()=>loadPreviousEvents(ev,container,offset));
    } catch {
        if (previousRequests.get(container) !== request) return;
        container.innerHTML = '<p>이전 경보를 불러오지 못했습니다.</p><button class="btn" data-previous-refresh>이전 경보 다시 조회</button>';
        container.querySelector('[data-previous-refresh]').addEventListener('click',()=>loadPreviousEvents(ev,container,offset));
    }
}
