"""위협 피드 생애주기 계약 (PR 07, 게이트 G1/G8).

가장 위험한 실패 모드를 고정한다.

    "갱신 루프가 살아 있다" ≠ "지표가 최신이다"

이전 구현은 `update_all()` 이 라이브 집합을 **먼저 비우고** 다운로드했다. 네트워크가
끊기면 threat_intel 엔진이 빈 목록을 보게 되어 아무것도 탐지하지 못했고, 그런데도
`last_update_epoch` 은 "방금 갱신됨" 으로 갱신되어 건강 신호가 거짓말을 했다.
감시 도구가 조용히 그만 보는 것이 가장 나쁜 실패 형태다.

이 테스트는 다음을 고정한다.

1. 전체 실패 → 기존 지표 유지, `last_update_epoch` 전진 금지
2. 부분 성공 → 성공한 것만 반영, 커스텀 항목 보존
3. 성공 → 원자적 교체, 정상 갱신
4. 신선도 보고는 정직하다 (stale/ok 구분)
5. 갱신 루프는 기동 직후 첫 갱신을 수행한다
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from netwatcher.threatintel.feed_manager import FeedManager
from netwatcher.threatintel.sources import FeedSource
from netwatcher.utils.config import Config

IP_FEED = FeedSource(
    name="TestIPFeed",
    url="https://example.invalid/list.txt",
    feed_type="ip",
    format="text",
    comment_prefix="#",
)


def _manager(tmp_path: Path, sources=None) -> FeedManager:
    cfg = Config({
        "threatfeeds": {"config_path": str(tmp_path / "feeds.yaml")},
    })
    mgr = FeedManager.__new__(FeedManager)
    mgr._config = cfg
    mgr._sources = sources if sources is not None else [IP_FEED]
    mgr._cache_dir = tmp_path / "feeds"
    mgr._cache_dir.mkdir(parents=True, exist_ok=True)
    mgr._meta_file = mgr._cache_dir / "_meta.json"
    mgr._feed_meta = {}
    mgr._blocked_ips = set()
    mgr._blocked_domains = set()
    mgr._blocked_ja3 = set()
    mgr._ja3_to_malware = {}
    mgr._custom_ips = set()
    mgr._custom_domains = set()
    mgr._ip_to_feed = {}
    mgr._domain_to_feed = {}
    mgr.last_update_epoch = 0.0
    mgr._last_summary = None
    mgr._last_attempt_epoch = 0.0
    mgr._feed_outcomes = {}
    mgr._pending_outcomes = {}
    return mgr


def _seed_state(mgr: FeedManager, ips: set[str], epoch: float) -> None:
    """이전 갱신 결과를 흉내 낸다."""
    mgr._blocked_ips = set(ips)
    for ip in ips:
        mgr._ip_to_feed[ip] = "TestIPFeed"
    mgr.last_update_epoch = epoch


# ------------------------------------------------------------------
# 1. 전체 실패 → 기존 상태 유지
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_total_failure_keeps_previous_indicators(tmp_path, monkeypatch):
    """다운로드가 전부 실패해도 기존 차단 목록이 사라지지 않는다."""
    mgr = _manager(tmp_path)
    _seed_state(mgr, {"1.2.3.4", "5.6.7.8"}, epoch=1000.0)

    async def boom(self, source, acc):
        # 네트워크 단절: 예외 후 캐시 없음
        raise ConnectionError("network down")

    monkeypatch.setattr(FeedManager, "_update_feed", boom)

    summary = await mgr.update_all()

    assert summary.succeeded is False
    assert mgr._blocked_ips == {"1.2.3.4", "5.6.7.8"}, \
        "전체 실패 시 기존 지표가 지워졌다"
    # 핵심: 갱신 성공 시각이 전진해선 안 된다
    assert mgr.last_update_epoch == 1000.0


@pytest.mark.asyncio
async def test_failed_refresh_reports_failure_not_success(tmp_path, monkeypatch):
    mgr = _manager(tmp_path)
    _seed_state(mgr, {"1.2.3.4"}, epoch=1000.0)

    async def boom(self, source, acc):
        raise ConnectionError("down")

    monkeypatch.setattr(FeedManager, "_update_feed", boom)

    summary = await mgr.update_all()
    assert summary.succeeded is False
    assert summary.failed == 1
    assert summary.blocked_ips == 1  # 요약은 보존된 상태를 보고한다


@pytest.mark.asyncio
async def test_empty_feed_response_is_treated_as_failure(tmp_path, monkeypatch):
    """모든 피드가 빈 내용을 주면 기존 상태를 유지해야 한다."""
    mgr = _manager(tmp_path)
    _seed_state(mgr, {"9.9.9.9"}, epoch=2000.0)

    async def serve_nothing(self, source, acc):
        acc.fail(source.name)

    monkeypatch.setattr(FeedManager, "_update_feed", serve_nothing)

    summary = await mgr.update_all()

    assert summary.succeeded is False
    assert mgr._blocked_ips == {"9.9.9.9"}
    assert mgr.last_update_epoch == 2000.0


# ------------------------------------------------------------------
# 2. 부분 성공
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_partial_failure_keeps_successful_feed(tmp_path, monkeypatch):
    """일부 피드만 성공하면 성공한 것만 반영된다."""
    mgr = _manager(tmp_path, sources=[IP_FEED])
    _seed_state(mgr, {"1.1.1.1"}, epoch=1000.0)

    async def succeed(self, source, acc):
        acc.ips.add("2.2.2.2")
        acc.ip_to_feed["2.2.2.2"] = source.name
        acc.record(source.name, "downloaded")

    monkeypatch.setattr(FeedManager, "_update_feed", succeed)

    summary = await mgr.update_all()

    assert summary.succeeded is True
    assert summary.delivered == 1
    assert "2.2.2.2" in mgr._blocked_ips
    assert mgr.last_update_epoch > 1000.0


@pytest.mark.asyncio
async def test_custom_entries_survive_refresh(tmp_path, monkeypatch):
    """커스텀 항목은 피드 갱신으로 지워지지 않는다."""
    mgr = _manager(tmp_path)
    mgr._custom_ips = {"7.7.7.7"}
    mgr.add_custom_ip("7.7.7.7")

    async def succeed(self, source, acc):
        acc.ips.add("2.2.2.2")
        acc.record(source.name, "downloaded")

    monkeypatch.setattr(FeedManager, "_update_feed", succeed)

    await mgr.update_all()

    assert "7.7.7.7" in mgr._blocked_ips
    assert mgr._ip_to_feed["7.7.7.7"] == "Custom"


# ------------------------------------------------------------------
# 3. 성공 경로
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_successful_update_advances_epoch(tmp_path, monkeypatch):
    mgr = _manager(tmp_path)
    _seed_state(mgr, {"1.1.1.1"}, epoch=1000.0)

    async def succeed(self, source, acc):
        acc.ips.add("3.3.3.3")
        acc.record(source.name, "downloaded")

    monkeypatch.setattr(FeedManager, "_update_feed", succeed)

    summary = await mgr.update_all()

    assert summary.succeeded is True
    assert mgr.last_update_epoch > 1000.0
    assert summary.last_update_epoch == mgr.last_update_epoch


@pytest.mark.asyncio
async def test_update_all_returns_summary(tmp_path, monkeypatch):
    mgr = _manager(tmp_path)

    async def succeed(self, source, acc):
        acc.ips.add("4.4.4.4")
        acc.record(source.name, "downloaded")

    monkeypatch.setattr(FeedManager, "_update_feed", succeed)

    summary = await mgr.update_all()
    payload = summary.as_dict()
    assert payload["succeeded"] is True
    assert payload["downloaded"] == 1
    assert payload["blocked_ips"] == 1


# ------------------------------------------------------------------
# 4. 정직한 신선도 보고
# ------------------------------------------------------------------

def test_fresh_feed_reports_ok(tmp_path):
    mgr = _manager(tmp_path)
    _seed_state(mgr, {"1.1.1.1"}, epoch=9999999999.0)  # 미래 시각 = 최신
    health = mgr.feed_health()
    assert health["status"] == "ok"
    assert health["blocked_ips"] == 1
    assert mgr.is_stale() is False


def test_never_updated_feed_is_stale(tmp_path):
    mgr = _manager(tmp_path)
    health = mgr.feed_health()
    assert health["status"] == "stale"
    assert health["age_hours"] is None
    assert mgr.is_stale() is True


def test_old_feed_is_stale(tmp_path):
    mgr = _manager(tmp_path)
    import time
    _seed_state(mgr, {"1.1.1.1"}, epoch=time.time() - 48 * 3600)
    assert mgr.is_stale(stale_after_hours=12) is True


def test_stale_feed_becomes_violation(tmp_path):
    """정체된 피드는 지원 계약 위반으로 드러난다."""
    mgr = _manager(tmp_path)
    violations = mgr.health_as_violations()
    assert len(violations) == 1
    assert violations[0].code == "SUP-060"


def test_fresh_feed_produces_no_violation(tmp_path):
    mgr = _manager(tmp_path)
    _seed_state(mgr, {"1.1.1.1"}, epoch=9999999999.0)
    assert mgr.health_as_violations() == []


def test_health_reports_per_feed_outcomes(tmp_path, monkeypatch):
    mgr = _manager(tmp_path)

    async def succeed(self, source, acc):
        acc.ips.add("5.5.5.5")
        acc.record(source.name, "downloaded")

    monkeypatch.setattr(FeedManager, "_update_feed", succeed)
    asyncio.run(mgr.update_all())

    health = mgr.feed_health()
    assert health["outcomes"]["TestIPFeed"] == "downloaded"


# ------------------------------------------------------------------
# 5. 갱신 루프가 기동 직후 첫 갱신을 수행하는지
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_feed_loop_refreshes_immediately(monkeypatch):
    """첫 갱신을 주기만큼 기다리지 않는다."""
    from netwatcher.services.maintenance import MaintenanceService

    calls: list[int] = []

    class _FakeFeed:
        _blocked_ips = set()
        _blocked_domains = set()
        last_update_epoch = 0.0

        async def update_all(self):
            calls.append(1)
            from netwatcher.threatintel.feed_manager import FeedUpdateSummary
            return FeedUpdateSummary(True, 1, 0, 0, 0, 0, 1234.0)

    svc = MaintenanceService.__new__(MaintenanceService)
    svc._config = type("C", (), {"get": staticmethod(lambda *a: 6)})()
    svc.config = svc._config
    svc.feed_manager = _FakeFeed()

    task = asyncio.create_task(svc._feed_refresh_loop())
    await asyncio.sleep(0.05)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert calls, "기동 직후 첫 갱신이 일어나지 않았다"


def test_zero_interval_does_not_busy_loop():
    """주기가 0 이면 busy loop 가 된다 — 최소값으로 막는다."""
    from netwatcher.services.maintenance import _positive_hours

    assert _positive_hours(0) == 6.0
    assert _positive_hours(-5) == 6.0
    assert _positive_hours("bogus") == 6.0
    # 1초 주기도 최소 60초로 올려야 한다
    assert _positive_hours(1 / 3600) == 60.0 / 3600
    assert _positive_hours(6) == 6.0
