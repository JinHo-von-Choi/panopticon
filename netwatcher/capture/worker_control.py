"""부모 센서와 패킷 워커 사이의 설정 명령과 적용 확인."""

from dataclasses import dataclass


@dataclass(frozen=True)
class WorkerEngineChange:
    request_id: str
    engine: str
    config_json: str


@dataclass(frozen=True)
class WorkerWhitelistChange:
    request_id: str
    config_json: str


@dataclass(frozen=True)
class WorkerFeedChange:
    request_id: str
    snapshot_json: str


@dataclass(frozen=True)
class WorkerRulesChange:
    request_id: str
    rules_json: str
    reset_matcher: bool


@dataclass(frozen=True)
class WorkerEngineReceipt:
    request_id: str
    worker_id: int
    applied: bool


class WorkerSynchronizationError(RuntimeError):
    """모든 워커의 같은 설정 적용을 확인하지 못했다."""
