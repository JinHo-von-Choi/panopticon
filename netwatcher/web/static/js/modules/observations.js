/** 보존 기록의 첫 관측을 장치 신원 확인과 구분한다. */
import { authFetch } from '../core/api.js';
import { esc,formatTime } from '../core/utils.js';
let kind='addresses';
let generation=0;

export async function loadObservedChanges(container,offset=0) {
    if (!container) return;
    const request=++generation;
    const selected=kind;
    container.innerHTML='<h3>보존 기록의 첫 관측</h3><p>불러오는 중…</p>';
    let data=null,error=null;
    try {
        const response=await authFetch(`/api/investigation/observations?kind=${selected}&limit=5&offset=${offset}`);
        if (!response.ok) error=response.status===413?'보존 기록이 250,000건을 넘어 전체 첫 관측을 집계할 수 없습니다.':'첫 관측을 불러오지 못했습니다.';
        else data=await response.json();
    } catch {error='첫 관측을 불러오지 못했습니다.';}
    if (request!==generation || selected!==kind) return;
    container.innerHTML='<h3>보존 기록의 첫 관측</h3><p class="scope-note">보존 중인 전체 EVE 기록에서 최근 24시간에 처음 관측된 항목입니다. 망에 새로 들어온 장치라는 뜻은 아닙니다. 삭제된 과거 기록과 수집하지 않은 트래픽은 비교할 수 없습니다.</p>' +
        '<label for="observation-kind">첫 관측 분류</label><select id="observation-kind"><option value="addresses" '+(selected==='addresses'?'selected':'')+'>주소·MAC 정보</option><option value="peers" '+(selected==='peers'?'selected':'')+'>통신 상대·서비스</option></select>' +
        (error ? `<p>${esc(error)}</p>` : `<p>보존 기록 ${esc(data.baseline.retained_records)}건 · ${esc(data.total)}개 항목 · ${esc(formatTime(data.snapshot_at))} 기준</p>`+
        (data.baseline.oldest_observed_at?`<p>가장 오래된 보존 관측: ${esc(formatTime(data.baseline.oldest_observed_at))}</p>`:'')+
        (data.baseline.future_records?`<p>미래 시각으로 기록된 로그 ${esc(data.baseline.future_records)}건이 있습니다. 입력 시각을 확인하세요.</p>`:'')+
        data.observations.map(item=>{
            const scope=item.scope;
            const identity=selected==='addresses'?`${scope.ip} / ${scope.mac || 'MAC 정보 없음'}`:`${scope.src_ip} → ${scope.dest_ip} / ${scope.proto || '-'} / ${scope.dest_port ?? '-'}`;
            return `<div class="work-schedule-card"><strong>${esc(identity)}</strong><p>첫 관측 ${esc(formatTime(item.first_seen))} · 마지막 관측 ${esc(formatTime(item.last_seen))}</p><p>센서 ${esc(scope.sensor_id)} · 입력 ${esc(scope.source_id)}</p><p>로그에 기록된 주소·MAC 정보입니다. 소유 관계는 장치 확인 기록에서 확인하세요.</p>${item.related_event_id?`<button class="btn" data-observation-event="${esc(item.related_event_id)}">관련 경보 #${esc(item.related_event_id)} 열기</button>`:'<p>연결할 보존 경보가 없습니다.</p>'}</div>`;
        }).join('')+
        (!data.total?'<p>보존 기록 기준 최근 24시간에 처음 관측된 항목이 없습니다.</p>':'')+
        (offset>0?'<button class="btn" data-observation-prev>이전 첫 관측</button>':'')+
        (offset+data.observations.length<data.total?'<button class="btn" data-observation-next>다음 첫 관측</button>':''))+
        '<button class="btn" data-observation-refresh>첫 관측 새로고침</button>';
    container.querySelector('select').addEventListener('change',event=>{kind=event.target.value;loadObservedChanges(container)});
    container.querySelectorAll('[data-observation-event]').forEach(button=>button.addEventListener('click',()=>window.showEventDetail(button.dataset.observationEvent)));
    container.querySelector('[data-observation-prev]')?.addEventListener('click',()=>loadObservedChanges(container,Math.max(0,offset-5)));
    container.querySelector('[data-observation-next]')?.addEventListener('click',()=>loadObservedChanges(container,offset+5));
    container.querySelector('[data-observation-refresh]').addEventListener('click',()=>loadObservedChanges(container,offset));
}
