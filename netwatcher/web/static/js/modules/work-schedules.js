/** 사건에 해당하는 등록 작업과 수동·CSV 입력. */
import { authFetch, canConfigure } from '../core/api.js';
import { esc, formatTime } from '../core/utils.js';
const t = (key,options={}) => window.i18next.t('console.work_schedule.'+key,options);
const fields = ['title','kind','owner','ticket','note','source_ip','source_mac','dest_ip','protocol','dest_port','starts_at','ends_at','max_flow_bytes'];
function localTime(value) {
    const date = new Date(value);
    return new Date(date.getTime()-date.getTimezoneOffset()*60000).toISOString().slice(0,16);
}
function card(job) {
    const body=job.content;
    return `<article class="work-schedule-card"><h4>${esc(body.title)}</h4>
        <p>${esc(t('kinds.'+body.kind))} · ${esc(body.owner)} · ${esc(body.ticket)}</p>
        <p>${esc(formatTime(job.starts_at))} → ${esc(formatTime(job.ends_at))}</p>
        <p>${esc(body.source_ip)}${body.source_mac ? ' / '+esc(body.source_mac) : ''} → ${esc(body.dest_ip)} · ${esc(body.protocol)} / ${esc(body.dest_port ?? t('all_ports'))}</p>
        <p>${esc(t('max_flow_bytes'))}: ${esc(body.max_flow_bytes)}</p>
        <p class="case-note">${esc(body.note)}</p>
        <p class="text-dim">${esc(t('registered'))}: ${esc(job.actor)} · ${esc(formatTime(job.created_at))}${new Date(job.created_at)>new Date(job.starts_at) ? ' · '+esc(t('registered_late')) : ''}</p></article>`;
}

export async function loadWorkSchedules(event,panel,matchOffset=0,onChange=()=>{}) {
    if (!panel?.isConnected)return;
    panel.textContent=t('loading');
    let data;
    try {
        const response=await authFetch(`/api/events/${event.id}/work-schedule?limit=50&offset=${matchOffset}`);
        if (!response?.ok)throw Error('Schedule unavailable');
        data=await response.json();
    } catch {if(panel.isConnected)panel.textContent=t('unavailable');return;}
    if (!panel.isConnected)return;
    panel.innerHTML=`<h3>${esc(t('title'))}</h3><p class="scope-hint">${esc(t('scope'))}</p>
        ${data.current ? `<p role="status">${esc(t('states.'+data.current.state))}</p>${card(data.current.schedule)}` : `<p>${esc(t('unlinked'))}</p>`}
        <button type="button" class="btn" data-work-refresh>${esc(t('refresh'))}</button>
        <h4>${esc(t('matches'))}</h4><div data-work-matches></div><p data-work-result role="status" aria-live="polite"></p>`;
    panel.querySelector('[data-work-refresh]').addEventListener('click',()=>loadWorkSchedules(event,panel,0,onChange));
    const message=panel.querySelector('[data-work-result]');
    async function mutate(path,payload) {
        message.textContent=t('saving');
        panel.querySelectorAll('fieldset,button').forEach(control=>control.disabled=true);
        try {
            const response=await authFetch(path,{method:path.includes('/events/')?'PUT':'POST',
                headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
            if (!response?.ok) {
                const error=await response?.json();
                if(response?.status>=500)await onChange();
                message.textContent=response?.status===409 ? t('reasons.'+error.detail) : response?.status===422 ? t('invalid_input') : t('unknown_result');
                return;
            }
            const outcome=await response.json();
            await onChange();
            await loadWorkSchedules(event,panel,0,onChange);
            if(outcome.created_ids && panel.isConnected)panel.querySelector('[data-work-result]').textContent=t('created_result',{created:outcome.created_ids.length,existing:outcome.existing_count,duplicates:outcome.duplicate_rows});
        } catch {await onChange();if(panel.isConnected)message.textContent=t('unknown_result');}
        finally {if(panel.isConnected)panel.querySelector('[data-work-refresh]').disabled=false;}
    }
    const list=panel.querySelector('[data-work-matches]');
    const candidates=data.matches.filter(job=>job.id!==data.current?.schedule.id);
    if (!candidates.length)list.textContent=t('no_matches');
    for (const job of candidates) {
        const item=document.createElement('div');item.innerHTML=card(job);list.append(item);
        if (canConfigure()) {
            const button=document.createElement('button');button.type='button';button.className='btn';button.textContent=t('link');
            button.addEventListener('click',()=>mutate(`/api/events/${event.id}/work-schedule`,{schedule_id:job.id,expected_version:data.current?.version||0}));item.append(button);
        }
    }
    for(const [label,offset,enabled] of [[t('previous'),matchOffset-50,matchOffset>0],[t('next'),matchOffset+50,matchOffset+50<data.total_matches]]) {
        if(!enabled)continue;
        const button=document.createElement('button');button.type='button';button.className='btn';button.textContent=label;
        button.addEventListener('click',()=>loadWorkSchedules(event,panel,offset,onChange));list.append(button);
    }
    const catalogue=document.createElement('details');catalogue.innerHTML=`<summary>${esc(t('catalogue'))}</summary><div data-work-catalogue></div>`;
    let catalogueLoaded=false;
    async function cataloguePage(offset=0) {
        const content=catalogue.querySelector('[data-work-catalogue]');content.textContent=t('loading');
        try {
            const response=await authFetch(`/api/work-schedules?limit=50&offset=${offset}`);
            if(!response?.ok)throw Error('Catalogue unavailable');
            const page=await response.json();if(!catalogue.isConnected)return;
            content.innerHTML='';
            for(const job of page.schedules) {
                const item=document.createElement('div');item.innerHTML=card(job);
                if(job.revoked_at)item.innerHTML+=`<p>${esc(t('states.revoked'))} · ${esc(job.revocation_note)}</p>`;
                else if(canConfigure()) {
                    const form=document.createElement('form');form.className='business-review-form';
                    form.innerHTML=`<fieldset><legend>${esc(t('revoke'))}</legend><label for="revoke-${esc(job.id)}">${esc(t('revocation_note'))}</label>
                        <textarea id="revoke-${esc(job.id)}" class="input-search" required minlength="3" maxlength="512"></textarea>
                        <button type="submit" class="btn">${esc(t('revoke'))}</button></fieldset>`;
                    form.addEventListener('submit',submit=>{submit.preventDefault();mutate(`/api/work-schedules/${job.id}/revoke`,{expected_version:job.version,note:form.querySelector('textarea').value.trim()});});item.append(form);
                }
                content.append(item);
            }
            for(const [label,target,enabled]of [[t('previous'),offset-50,offset>0],[t('next'),offset+50,offset+50<page.total]]) {
                if(!enabled)continue;const button=document.createElement('button');button.type='button';button.className='btn';button.textContent=label;
                button.addEventListener('click',()=>cataloguePage(target));content.append(button);
            }
            if(!page.schedules.length)content.textContent=t('catalogue_empty');
        } catch {if(catalogue.isConnected)content.textContent=t('unavailable');}
    }
    catalogue.addEventListener('toggle',()=>{if(catalogue.open&&!catalogueLoaded){catalogueLoaded=true;cataloguePage();}});panel.append(catalogue);
    if (!canConfigure())return;
    if(data.current && data.current.state!=='revoked') {
        const form=document.createElement('form');form.className='business-review-form';
        form.innerHTML=`<fieldset><legend>${esc(t('revoke'))}</legend><label for="work-revoke-note">${esc(t('revocation_note'))}</label>
            <textarea id="work-revoke-note" class="input-search" required minlength="3" maxlength="512"></textarea>
            <button type="submit" class="btn">${esc(t('revoke'))}</button></fieldset>`;
        form.addEventListener('submit',submit=>{submit.preventDefault();mutate(`/api/work-schedules/${data.current.schedule.id}/revoke`,
            {expected_version:data.current.schedule.version,note:form.querySelector('textarea').value.trim()});});panel.append(form);
    }
    const details=document.createElement('details');details.innerHTML=`<summary>${esc(t('register'))}</summary>`;
    const form=document.createElement('form');form.className='business-review-form';
    form.innerHTML=`<fieldset><legend>${esc(t('register'))}</legend>${fields.map(field=>{
        const select=field==='kind'||field==='protocol';
        const values=field==='kind'?['backup','vulnerability_scan','deployment','maintenance']:['TCP','UDP'];
        const optional=['source_mac','dest_port'].includes(field);
        let input=select?`<select id="work-${field}" class="input-search">${values.map(value=>`<option value="${value}">${esc(field==='kind'?t('kinds.'+value):value)}</option>`).join('')}</select>`:
            field==='note'?`<textarea id="work-${field}" class="input-search" required minlength="3" maxlength="1024" rows="3"></textarea>`:
            `<input id="work-${field}" class="input-search" ${optional?'':'required'} type="${field.endsWith('_at')?'datetime-local':['dest_port','max_flow_bytes'].includes(field)?'number':'text'}" ${['dest_port','max_flow_bytes'].includes(field)?`min="1" max="${field==='dest_port'?65535:1099511627776}" step="1"`:`maxlength="${field==='source_mac'?17:128}"`}>`;
        return `<div class="form-group"><label for="work-${field}">${esc(t(field==='title'?'title_field':field))}</label>${input}</div>`;
    }).join('')}<button type="submit" class="btn btn-accent">${esc(t('save'))}</button></fieldset>`;
    const defaults={source_ip:event.source_ip||'',source_mac:event.source_mac||'',dest_ip:event.dest_ip||'',protocol:event.metadata?.external_eve?.proto||'TCP',
        dest_port:event.metadata?.external_eve?.dest_port||'',starts_at:localTime(new Date(event.timestamp).getTime()-3600000),ends_at:localTime(new Date(event.timestamp).getTime()+3600000),max_flow_bytes:10485760};
    for(const [key,value]of Object.entries(defaults))form.querySelector(`#work-${key}`).value=value;
    form.addEventListener('submit',submit=>{
        submit.preventDefault();const payload={};
        for(const field of fields) {
            let value=form.querySelector(`#work-${field}`).value.trim();
            if(field.endsWith('_at'))value=new Date(value).toISOString();
            else if(['dest_port','max_flow_bytes'].includes(field))value=value?Number(value):null;
            else if(field==='source_mac')value=value||null;
            payload[field]=value;
        }
        mutate('/api/work-schedules',payload);
    });details.append(form);panel.append(details);
    const csv=document.createElement('details');csv.innerHTML=`<summary>${esc(t('import_title'))}</summary><p>${esc(t('import_scope'))}</p>
        <button type="button" class="btn" data-work-template>${esc(t('template'))}</button>
        <form class="business-review-form"><fieldset><legend>${esc(t('import_title'))}</legend>
            <label for="work-csv-file">${esc(t('csv_file'))}</label><input id="work-csv-file" type="file" accept=".csv,text/csv" required>
            <button type="submit" class="btn">${esc(t('import'))}</button></fieldset></form>`;
    csv.querySelector('[data-work-template]').addEventListener('click',()=>{
        const url=URL.createObjectURL(new Blob([fields.join(',')+'\r\n'],{type:'text/csv;charset=utf-8'}));
        const link=document.createElement('a');link.href=url;link.download='work-schedules-template.csv';document.body.append(link);link.click();link.remove();URL.revokeObjectURL(url);
    });
    csv.querySelector('form').addEventListener('submit',async submit=>{
        submit.preventDefault();const file=csv.querySelector('input').files[0];
        if(!file||file.size>131072){message.textContent=t('invalid_input');return;}
        try {await mutate('/api/work-schedules/import',{csv:await file.text()});}
        catch {message.textContent=t('invalid_input');}
    });panel.append(csv);
}
