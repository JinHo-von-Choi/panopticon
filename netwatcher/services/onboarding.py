"""설치 점검: 현재 확인된 사실과 현장에서 확인할 관측 한계를 분리한다."""
from __future__ import annotations

import os
import resource
import shutil
from pathlib import Path
from ipaddress import ip_address


def storage_probe(directory: str, required_bytes: int) -> dict:
    path = Path(directory)
    if not path.is_dir():
        return {'status': 'attention', 'reason': 'evidence_directory_missing'}
    try:
        writable = (bool(path.stat().st_mode & 0o222)
                    and os.access(path, os.W_OK) and not os.statvfs(path).f_flag & os.ST_RDONLY)
        usage = shutil.disk_usage(path)
    except OSError as error:
        return {'status': 'unknown', 'reason': 'storage_probe_failed', 'error_type': type(error).__name__}
    return {'status': 'pass' if writable and usage.free >= required_bytes else 'attention',
            'reason': 'storage_capacity_checked' if writable and usage.free >= required_bytes else
                      'storage_readonly' if not writable else 'storage_capacity_low',
            'free_bytes': usage.free, 'required_bytes': required_bytes,
            'writable_precheck': writable, 'write_verified': False}


def build_report(config, health: dict, observation: dict | None, *, storage: dict,
                 auth_enabled: bool, config_writable: bool | None) -> dict:
    checks = []
    def add(name, status, reason, **facts):
        checks.append(dict(name=name, status=status, reason=reason, facts=facts))

    capture = health.get('components', {}).get('sniffer', {})
    database = health.get('components', {}).get('database', {})
    add('database', 'pass' if database.get('status') == 'healthy' else 'attention',
        'database_reachable' if database.get('status') == 'healthy' else 'database_unavailable')
    if config.get('input.mode', 'native') == 'eve':
        eve = health.get('components', {}).get('eve', {})
        add('eve', 'pass' if eve.get('status') == 'healthy' else 'attention',
            'eve_connected' if eve.get('status') == 'healthy' else 'eve_unavailable',
            source_count=len(eve.get('sources', [])), packet_capture=False)
    else:
        add('capture', 'pass' if capture.get('status') == 'healthy' else 'attention',
            'capture_running' if capture.get('status') == 'healthy' else 'capture_unavailable',
            configured_interface=config.get('interface') or 'auto', selected_interface=None)
    observed_state = observation.get('state', 'unknown') if observation else 'unknown'
    eve_mode = config.get('input.mode', 'native') == 'eve'
    add('eve_coverage' if eve_mode else 'coverage', 'unknown',
        'eve_coverage_unverified' if eve_mode else 'span_unverified', observation_state=observed_state,
        netflow_configured=bool(config.get('netflow.enabled', False)),
        unsupported_measurements=observation.get('unsupported_measurements', []) if observation else [])
    bind = str(config.get('web.host', '127.0.0.1'))
    try:
        local = ip_address(bind).is_loopback
    except ValueError:
        local = bind == 'localhost'
    add('management', 'pass' if local or auth_enabled else 'attention',
        'management_bound_local' if local else 'management_auth_enabled' if auth_enabled else 'management_auth_missing',
        bind=bind, authentication_enabled=auth_enabled, tls_or_proxy_verified=False)
    add('storage', storage['status'], storage['reason'], **{k: v for k, v in storage.items() if k not in ('status', 'reason')})
    add('memory', 'unknown', 'whole_process_budget_unverified',
        main_process_peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
        workers_total_rss_bytes=None)
    add('configuration', 'pass' if config_writable else 'attention' if config_writable is False else 'unknown',
        'configuration_writable' if config_writable else 'configuration_readonly' if config_writable is False else 'configuration_unavailable')
    return {'status': 'attention' if any(c['status'] == 'attention' for c in checks) else 'unknown',
            'input_mode': config.get('input.mode', 'native'),
            'checks': checks, 'scope': 'read_only_installation_precheck',
            'production_validated': False, 'changes_applied': False}
