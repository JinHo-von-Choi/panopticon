"""외부 조치 메시지 변조와 실행기 독립 승인 대조."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json

import pytest

from netwatcher.response.command import ActionAuthorization, ExecutionCommand
from netwatcher.response.lifecycle import LifecycleError

ACTOR = "13a33d72-3667-4a59-84e2-9189070ea6b6"
KEY = "b163b4ec-944c-4715-b5a2-ddf7b12381c9"
NOW = datetime(2026, 10, 8, 0, 0, tzinfo=timezone.utc)


def message(**changes):
    value = dict(version=1, operation="apply", action_id=1, idempotency_key=KEY,
                 actor_id=ACTOR, actor_version=2, ownership_version="v1",
                 target="8.8.8.8", direction="input", ttl_seconds=300,
                 scope={"asset": "router"}, reason="관리자가 확인한 격리 조치",
                 approval_expires_at=(NOW + timedelta(seconds=100)).isoformat())
    value.update(changes)
    return json.dumps(value).encode()


def authorization(command):
    return ActionAuthorization(
        action_id=1, idempotency_key=KEY, approved_hash=command.request().content_hash(),
        approved_at=NOW - timedelta(seconds=10),
        approval_expires_at=NOW + timedelta(seconds=100), actor_id=ACTOR,
        actor_version=2, actor_enabled=True, actor_role="admin", ownership_version="v1",
        mapping_confirmed_at=NOW - timedelta(seconds=60), executable=True,
        reason="관리자가 확인한 격리 조치",
    )


def test_independently_verified_request_and_immutable_scope():
    command = ExecutionCommand.from_bytes(message())
    snapshot = authorization(command)
    result = command.validate_authorization(snapshot, now=NOW)
    assert result.rule_tag == "nw-1"
    result.scope["asset"] = "changed-after-validation"
    assert command.request().scope == {"asset": "router"}
    assert ExecutionCommand.from_bytes(command.to_bytes()) == command


@pytest.mark.parametrize("changes", [
    {"version": True}, {"operation": "shell"}, {"operation": []},
    {"action_id": True}, {"action_id": 0}, {"actor_version": -1},
    {"actor_id": "admin"}, {"idempotency_key": KEY.upper()},
    {"ownership_version": "v1\n"}, {"ownership_version": ""},
    {"target": "8.8.8.8; reboot"}, {"target": 134744072},
    {"target": "8.8.8.0/24"}, {"target": "127.0.0.2"},
    {"target": "::1"}, {"target": "ff02::1"}, {"target": "fe80::1%eth0"},
    {"target": "0.0.0.0"}, {"target": "192.168.1.1"},
    {"ttl_seconds": True}, {"ttl_seconds": 3601}, {"direction": "INPUT"},
    {"scope": {"command": "reboot"}}, {"scope": {"asset": {"x": 1}}},
    {"scope": {"asset": "x" * 129}}, {"scope": {"asset": "x\ny"}},
    {"approved_by": "admin"},
    {"reason": ""}, {"reason": "x\ny"}, {"reason": "x" * 513}, {"reason": 1},
    {"approval_expires_at": "2026-10-08"}, {"approval_expires_at": "2026-10-08T01:00:00+01:00"},
    {"approval_expires_at": "2026-10-08T00:00:00Z"}, {"approval_expires_at": None},
    {"actor_version": 2**63},
])
def test_untrusted_fields_are_rejected(changes):
    with pytest.raises(LifecycleError):
        ExecutionCommand.from_bytes(message(**changes))


@pytest.mark.parametrize("payload", [
    b"", b"x" * 8193, b"\xff", b"[]", b'{"version":1,"version":1}',
    b'{"version":NaN}', b"[" * 2000 + b"]" * 2000,
])
def test_bounded_strict_json(payload):
    with pytest.raises(LifecycleError):
        ExecutionCommand.from_bytes(payload)


@pytest.mark.parametrize("changes", [
    {"action_id": 2}, {"idempotency_key": ACTOR}, {"approved_hash": "0" * 64},
    {"actor_id": KEY}, {"actor_version": 3}, {"actor_enabled": False},
    {"actor_role": "viewer"}, {"ownership_version": "v2"}, {"executable": False},
    {"approved_at": NOW + timedelta(seconds=1)},
    {"approved_at": NOW - timedelta(seconds=301)},
    {"approval_expires_at": NOW},
    {"approval_expires_at": NOW - timedelta(seconds=20)},
    {"mapping_confirmed_at": NOW - timedelta(seconds=901)},
    {"mapping_confirmed_at": NOW + timedelta(seconds=1)},
    {"mapping_confirmed_at": NOW.replace(tzinfo=None)},
    {"reason": "다른 사유"},
])
def test_expired_revoked_changed_or_stale_authorization_refuses_apply(changes):
    command = ExecutionCommand.from_bytes(message())
    with pytest.raises(LifecycleError):
        command.validate_authorization(replace(authorization(command), **changes), now=NOW)


def test_management_network_is_protected_but_removal_can_recover():
    command = ExecutionCommand.from_bytes(message())
    snapshot = authorization(command)
    with pytest.raises(LifecycleError):
        command.validate_authorization(snapshot, now=NOW, protected=("8.8.8.0/24",))
    removal = ExecutionCommand.from_bytes(message(operation="remove"))
    expired = replace(snapshot, executable=False)
    later = NOW + timedelta(seconds=200)
    assert removal.validate_authorization(expired, now=later, protected=("8.8.8.0/24",)).target == "8.8.8.8"
    with pytest.raises(LifecycleError):
        removal.validate_authorization(replace(expired, actor_enabled=False), now=later)


def test_verify_after_approval_expiry_never_renews_ttl():
    command = ExecutionCommand.from_bytes(message(operation="verify"))
    snapshot = authorization(command)
    assert command.validate_authorization(snapshot, now=NOW + timedelta(seconds=200)).ttl_seconds == 300
