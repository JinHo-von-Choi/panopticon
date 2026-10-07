"""실제 앱·DB의 설치 점검 조회와 읽기 전용 설정 계약."""
import json

import pytest
from httpx import ASGITransport, AsyncClient

from netwatcher.alerts.dispatcher import AlertDispatcher
from netwatcher.observability.health import HealthChecker
from netwatcher.storage.repositories import EventRepository, TrafficStatsRepository
from netwatcher.utils.yaml_editor import YamlConfigEditor
from netwatcher.web.server import create_app


@pytest.mark.asyncio
async def test_installation_read_does_not_write_configuration(config, db, device_repo, tmp_path):
    config._data['evidence']={'directory':str(tmp_path), 'max_storage_mb':1}
    config._data['auth']={'enabled':False,'password':'test-value-should-not-appear'}
    yaml=tmp_path/'readonly.yaml';yaml.write_text('netwatcher:\n  engines: {}\n');yaml.chmod(0o444)
    before=yaml.read_bytes()
    events=EventRepository(db);stats=TrafficStatsRepository(db)
    dispatcher=AlertDispatcher(config,events)
    app=create_app(config,events,device_repo,stats,dispatcher,
                   health_checker=HealthChecker(database=db,dispatcher=dispatcher),
                   yaml_editor=YamlConfigEditor(str(yaml)))
    async with AsyncClient(transport=ASGITransport(app=app),base_url='http://test') as client:
        response=await client.get('/api/onboarding')
    assert response.status_code==200
    report=response.json()
    checks={row['name']:row for row in report['checks']}
    assert checks['database']['status']=='pass'
    assert checks['configuration']['reason']=='configuration_readonly'
    assert checks['coverage']['status']=='unknown'
    assert 'test-value-should-not-appear' not in json.dumps(report)
    assert yaml.read_bytes()==before
    assert not list(tmp_path.glob('*.bak'))
