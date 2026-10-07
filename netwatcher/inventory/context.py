"""사람이 확인한 현재 자산 역할. 자동 추정이나 탐지 예외와 분리한다."""
from datetime import datetime, timezone


def asset_context(device: dict, *, shared_ip: bool = False, now=None) -> dict:
    profile = device.get('context_profile') or {}
    result = {'status': 'unknown', 'scope': 'current_inventory',
              'version': device.get('context_version', 0), 'reason': 'not_confirmed'}
    if not isinstance(profile, dict) or not profile:
        return result
    result.update(confirmed_at=profile.get('confirmed_at'), expires_at=profile.get('expires_at'))
    if profile.get('role') == 'unknown':
        result['reason'] = 'revoked'
        return result
    if shared_ip:
        result['reason'] = 'shared_ip'
        return result
    if (profile.get('ip') != str(device.get('ip_address') or '') or
            profile.get('mapping_version') != device.get('ip_mapping_version')):
        result['reason'] = 'mapping_changed'
        return result
    try:
        expiry = datetime.fromisoformat(profile['expires_at'])
        if expiry.tzinfo is None:
            raise ValueError('timezone required')
    except (KeyError, TypeError, ValueError):
        result['reason'] = 'invalid_confirmation'
        return result
    if expiry <= (now or datetime.now(timezone.utc)):
        result['reason'] = 'expired'
        return result
    result.update(status='confirmed', reason='human_confirmed', role=profile['role'],
                  confirmed_by=profile.get('confirmed_by'))
    return result
