"""설치 점검이 확인 불가능한 관측·메모리를 통과로 표시하지 않는다."""
import json
from pathlib import Path

from netwatcher.services.onboarding import build_report, storage_probe
from netwatcher.utils.config import Config


def test_missing_storage_is_reported_without_creating_it(tmp_path):
    directory = tmp_path / 'missing'
    result = storage_probe(str(directory), 1)
    assert result['reason'] == 'evidence_directory_missing'
    assert not directory.exists()


def test_readonly_storage_remains_readonly(tmp_path):
    tmp_path.chmod(0o555)
    try:
        result = storage_probe(str(tmp_path), 1)
        assert result['status'] == 'attention'
        assert result['reason'] == 'storage_readonly'
        assert result['write_verified'] is False
    finally:
        tmp_path.chmod(0o755)


def test_storage_capacity_budget_is_checked(tmp_path):
    result = storage_probe(str(tmp_path), 10**30)
    assert result['reason'] == 'storage_capacity_low'


def test_live_sensor_does_not_prove_span_coverage():
    config = Config({'web':{'host':'0.0.0.0'}, 'auth':{'password':'must-not-leak'}, 'postgresql':{'password':'db-must-not-leak'}})
    health = {'components':{'sniffer':{'status':'healthy'}, 'database':{'status':'healthy'}}}
    report = build_report(config, health, {'state':'observed'}, storage={'status':'pass','reason':'storage_capacity_checked'}, auth_enabled=False, config_writable=False)
    checks={check['name']:check for check in report['checks']}
    assert checks['capture']['status']=='pass'
    assert checks['coverage']['status']=='unknown'
    assert checks['memory']['status']=='unknown'
    assert checks['management']['reason']=='management_auth_missing'
    assert checks['configuration']['reason']=='configuration_readonly'
    assert report['production_validated'] is False
    assert report['changes_applied'] is False
    assert 'must-not-leak' not in json.dumps(report)


def test_local_management_check_is_not_production_certification():
    report=build_report(Config({'web':{'host':'127.0.0.1'}}),{},None,storage={'status':'unknown','reason':'storage_probe_failed'},auth_enabled=False,config_writable=None)
    management=next(check for check in report['checks'] if check['name']=='management')
    assert management['status']=='pass'
    assert management['facts']['tls_or_proxy_verified'] is False
    assert report['status']=='attention'
