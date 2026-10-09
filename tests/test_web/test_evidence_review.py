"""Real HTTP/RBAC/PCAP file checks; no arbitrary path is accepted."""
import time
import httpx
import pytest
from fastapi import FastAPI
from netwatcher.capture.pcap_writer import PCAPWriter
from netwatcher.storage.repositories import EventRepository
from netwatcher.web.routes.events import create_events_router
from netwatcher.web.rbac import Role
from tests.test_web.test_replay_api import _auth_manager, _h


@pytest.mark.asyncio
async def test_evidence_pin_requires_admin_and_file_availability(db, tmp_path):
    repository = EventRepository(db)
    event_id = await repository.insert(engine='port_scan', severity='WARNING', title='Synthetic evidence')
    writer = PCAPWriter(str(tmp_path))
    packet = bytes.fromhex('0200000000200200000000100800') + bytes(80)
    writer.write_snapshot(event_id, ((time.time(), packet, 1),))
    app = FastAPI(); app.state.auth_manager = _auth_manager()
    app.include_router(create_events_router(repository, None, writer), prefix='/api')
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
        body = {'hours': 24, 'reason': 'Review actual stored evidence'}
        endpoint = f'/api/events/{event_id}/evidence/pin'
        for role in (Role.VIEWER, Role.ANALYST):
            assert (await client.post(endpoint, json=body, headers=_h(role))).status_code == 403
        response = await client.post(endpoint, json=body, headers=_h(Role.ADMIN))
        assert response.status_code == 200
        assert response.json()['pin_state'] == 'pinned'
        detail = (await client.get(f'/api/events/{event_id}', headers=_h(Role.VIEWER))).json()['event']
        assert detail['pcap_availability']['state'] == 'available'
        file = await client.get(f'/api/events/{event_id}/evidence/file', headers=_h(Role.VIEWER))
        assert file.status_code == 200
        assert packet in file.content
        assert (await client.post(endpoint, json={**body, 'hours': 25}, headers=_h(Role.ADMIN))).status_code == 422
        assert (await client.post(endpoint, json={**body, 'enabled': False}, headers=_h(Role.ADMIN))).json()['pin_state'] == 'unpinned'
        assert (await client.get('/api/events/999999/evidence/file', headers=_h(Role.ADMIN))).status_code == 404
