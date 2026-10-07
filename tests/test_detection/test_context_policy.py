"""Narrow business classification fails closed; attacks keep their severity."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import pytest
from netwatcher.detection.models import Alert, Severity
from netwatcher.detection.context_policy import expected_job

NOW = datetime(2026, 10, 8, 12, tzinfo=timezone.utc)


def inputs():
    rule = {'peer_ip': '192.0.2.2', 'peer_mac': '02:00:00:00:00:20',
            'protocol': 'tcp', 'service_port': 445, 'direction': 'outbound',
            'timezone': 'UTC', 'weekdays': [3], 'start_hour': 11, 'end_hour': 14,
            'max_bytes_per_tick': 10000, 'purpose': 'Approved backup job'}
    device = {'mac_address': '02:00:00:00:00:10', 'ip_address': '192.0.2.1',
              'context_version': 1, 'ip_mapping_version': 0,
              'context_profile': {'role': 'backup', 'ip': '192.0.2.1', 'mapping_version': 0,
                  'confirmed_by': 'operator', 'confirmed_at': (NOW-timedelta(hours=1)).isoformat(),
                  'expires_at': (NOW+timedelta(hours=1)).isoformat(), 'expected_flows': [rule]}}
    alert = Alert(engine='traffic_anomaly', severity=Severity.CRITICAL, title='Volume',
                  title_key='engines.traffic_anomaly.alerts.volume.title', source_ip='192.0.2.1',
                  metadata={'bytes': 1000, 'flows_incomplete': False, 'flows': [{
                      'source_mac': device['mac_address'], 'peer_mac': rule['peer_mac'],
                      'peer_ip': rule['peer_ip'], 'protocol': 'tcp', 'service_port': 445,
                      'first_at': NOW.timestamp()-10, 'last_at': NOW.timestamp(), 'bytes': 1000}]})
    return alert, device


def test_confirmed_exact_job_classifies_only_volume_and_preserves_original():
    alert, device = inputs()
    assert expected_job(alert, device, now=NOW)
    assert alert.severity == Severity.INFO
    assert alert.metadata['business_context']['original_severity'] == 'CRITICAL'
    assert alert.metadata['business_context']['model_learning_changed'] is False


@pytest.mark.parametrize('engine', ['arp_spoof','dhcp_spoof','port_scan','lateral_movement','data_exfil','signature'])
def test_attack_engines_are_never_exempt(engine):
    alert, device = inputs(); alert.engine = engine
    assert not expected_job(alert, device, now=NOW)
    assert alert.severity == Severity.CRITICAL


@pytest.mark.parametrize('mutation', ['new_peer','new_port','wrong_mac','expired','shared','overflow',
                                     'excess_volume','time','old_capture','mapping','partial','mixed','overlap'])
def test_incomplete_or_out_of_scope_evidence_retains_severity(mutation):
    alert, device = inputs(); flow = alert.metadata['flows'][0]
    if mutation == 'new_peer': flow['peer_ip'] = '192.0.2.99'
    if mutation == 'new_port': flow['service_port'] = 22
    if mutation == 'wrong_mac': flow['source_mac'] = '02:00:00:00:00:99'
    if mutation == 'expired': device['context_profile']['expires_at'] = (NOW-timedelta(seconds=1)).isoformat()
    if mutation == 'overflow': alert.metadata['flows_incomplete'] = True
    if mutation == 'excess_volume': flow['bytes'] = alert.metadata['bytes'] = 10001
    if mutation == 'time': device['context_profile']['expected_flows'][0]['start_hour'] = 13
    if mutation == 'old_capture': flow['first_at'] = (NOW-timedelta(hours=2)).timestamp()
    if mutation == 'mapping': device['ip_mapping_version'] = 1
    if mutation == 'partial': alert.metadata['bytes'] = 1001
    if mutation == 'mixed':
        other = deepcopy(flow); other['peer_ip'] = '192.0.2.9'
        alert.metadata['flows'].append(other); alert.metadata['bytes'] += 1000
    if mutation == 'overlap': device['context_profile']['expected_flows'] *= 2
    assert not expected_job(alert, device, shared_ip=mutation == 'shared', now=NOW)
    assert alert.severity == Severity.CRITICAL
    assert 'business_context' not in alert.metadata
