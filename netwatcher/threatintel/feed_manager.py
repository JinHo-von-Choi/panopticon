"""위협 인텔리전스 피드 관리자: 다운로드, 파싱, 캐싱."""

from __future__ import annotations

import json
import asyncio
import heapq
import ipaddress
import logging
from pathlib import Path

import aiohttp

from netwatcher.utils.public_http import public_client_session

from netwatcher.threatintel.sources import (
    FeedSource,
    load_feed_sources,
    parse_feed,
    parse_ja3_feed,
    parse_text_feed,
)
from netwatcher.utils.config import Config
from netwatcher.utils.network import validate_outbound_url

logger = logging.getLogger("netwatcher.threatintel.feed_manager")

# 악성 콘텐츠가 호스팅될 수 있지만 최상위 도메인 자체는 악성이 아닌
# 공유 호스팅 / CDN 플랫폼.
# 오탐 방지를 위해 URL 유형 피드에서 필터링된다.
_SHARED_PLATFORM_DOMAINS: set[str] = {
    "github.com", "raw.githubusercontent.com", "githubusercontent.com",
    "gitlab.com", "bitbucket.org",
    "drive.google.com", "docs.google.com", "sites.google.com",
    "storage.googleapis.com", "googleapis.com",
    "dropbox.com", "dl.dropboxusercontent.com",
    "onedrive.live.com", "1drv.ms",
    "amazonaws.com", "s3.amazonaws.com",
    "cloudfront.net", "azureedge.net",
    "blob.core.windows.net", "azure.com",
    "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "pastebin.com", "paste.ee",
    "discord.com", "cdn.discordapp.com", "media.discordapp.net",
    "telegram.org", "t.me",
    "web.archive.org", "archive.org",
}


class FeedUpdateSummary:
    """한 번의 피드 갱신 결과."""

    def __init__(
        self,
        succeeded: bool,
        delivered: int,
        from_cache: int,
        failed: int,
        blocked_ips: int,
        blocked_domains: int,
        last_update_epoch: float,
    ) -> None:
        self.succeeded = succeeded
        self.delivered = delivered
        self.from_cache = from_cache
        self.failed = failed
        self.blocked_ips = blocked_ips
        self.blocked_domains = blocked_domains
        self.last_update_epoch = last_update_epoch

    def as_dict(self) -> dict:
        return {
            "succeeded": self.succeeded,
            "downloaded": self.delivered,
            "from_cache": self.from_cache,
            "failed": self.failed,
            "blocked_ips": self.blocked_ips,
            "blocked_domains": self.blocked_domains,
            "last_update_epoch": self.last_update_epoch,
        }


class _FeedAccumulator:
    """갱신 중인 피드 상태를 담는 임시 집합.

    라이브 집합과 분리해 두고, 갱신이 성공했을 때만 교체한다. 그래야 다운로드가
    전부 실패해도 기존의 유효한 차단 목록이 보존된다.
    """

    def __init__(self) -> None:
        self.ips: set[str] = set()
        self.domains: set[str] = set()
        self.ja3: set[str] = set()
        self.ja3_to_malware: dict[str, str] = {}
        self.ip_to_feed: dict[str, str] = {}
        self.domain_to_feed: dict[str, str] = {}
        # 피드별 결과: "downloaded" | "cached" | "failed"
        self.outcomes: dict[str, str] = {}
        self.validated_cached: set[str] = set()

    def record(self, name: str, outcome: str) -> None:
        self.outcomes[name] = outcome

    def fail(self, name: str) -> None:
        self.outcomes[name] = "failed"


class FeedManager:
    """위협 인텔리전스 피드를 다운로드, 파싱, 캐싱한다."""

    def __init__(self, config: Config) -> None:
        self._config = config
        feed_config_path = config.get("threatfeeds.config_path", "config/threatfeeds.yaml")
        self._sources = load_feed_sources(feed_config_path)
        self._cache_dir = Path("data/threatfeeds")
        self._cache_dir.mkdir(parents=True, exist_ok=True)

        self._meta_file = self._cache_dir / "_meta.json"
        self._feed_meta: dict[str, dict[str, str]] = self._load_meta()

        self._blocked_ips: set[str] = set()
        self._blocked_domains: set[str] = set()

        # 마지막 성공적 업데이트 타임스탬프 (epoch 초)
        self.last_update_epoch: float = 0.0
        self._confirmed_epochs: dict[str, float] = {}

        # JA3 차단 목록 (SSLBL 피드에서 채워짐)
        self._blocked_ja3: set[str] = set()
        self._ja3_to_malware: dict[str, str] = {}

        # 커스텀 항목 (사용자 관리, 피드 업데이트 간 보존)
        self._custom_ips: set[str] = set()
        self._custom_domains: set[str] = set()
        self._custom_networks: dict[int, dict[int, dict[int, set[str]]]] = {4: {}, 6: {}}
        self._custom_domain_names: dict[str, set[str]] = {}

        # 각 지표가 어느 피드에서 왔는지 추적
        self._ip_to_feed: dict[str, str] = {}
        self._domain_to_feed: dict[str, str] = {}
        self._overridden_ip_sources: dict[str, str] = {}
        self._overridden_domain_sources: dict[str, str] = {}
        self._update_lock = asyncio.Lock()
        self._runtime_update_hook = None

        # 마지막 갱신 시도/결과 (정직한 신선도 보고용, PR 07)
        self._last_summary: FeedUpdateSummary | None = None
        self._last_attempt_epoch: float = 0.0
        self._feed_outcomes: dict[str, str] = {}
        self._pending_outcomes: dict[str, str] = {}

    def get_blocked_ips(self) -> set[str]:
        return self._blocked_ips.copy()

    def get_blocked_domains(self) -> set[str]:
        return self._blocked_domains.copy()

    def get_feed_for_ip(self, ip: str) -> str | None:
        """IP가 로드된 피드를 반환한다."""
        return self._ip_to_feed.get(ip)

    def get_feed_for_domain(self, domain: str) -> str | None:
        """도메인이 로드된 피드를 반환한다."""
        return self._domain_to_feed.get(domain)

    def match_ip(self, ip: str) -> dict[str, str] | None:
        """IP가 차단 목록에 있는지 확인하고 피드 정보를 반환한다."""
        feed = self._ip_to_feed.get(ip)
        if feed == "Custom":
            return {"source": feed, "category": "malware"}
        if any(self._custom_networks.values()):
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                logger.debug("Invalid IP supplied for threat-feed matching", exc_info=True)
                return None
            number = int(address)
            for prefix, networks in tuple(self._custom_networks[address.version].items()):
                shift = address.max_prefixlen - prefix
                if (number >> shift) << shift in networks:
                    return {"source": "Custom", "category": "malware"}
        if feed:
            return {"source": feed, "category": "malware"}
        return None

    def match_domain(self, domain: str) -> dict[str, str] | None:
        """도메인이 차단 목록에 있는지 확인하고 피드 정보를 반환한다."""
        try:
            domain = self._domain_name(domain)
        except UnicodeError:
            logger.debug("Invalid domain supplied for threat-feed matching", exc_info=True)
            return None
        if domain in self._custom_domain_names:
            return {"source": "Custom", "category": "malware"}
        feed = self._domain_to_feed.get(domain)
        if feed:
            return {"source": feed, "category": "malware"}
        return None

    def load_custom_entries(self, ips: set[str], domains: set[str]) -> None:
        """시작 시 DB에서 커스텀 항목을 로드하고 라이브 집합에 병합한다."""
        for ip in self._custom_ips - ips:
            self.remove_custom_ip(ip)
        for domain in self._custom_domains - domains:
            self.remove_custom_domain(domain)
        for ip in ips:
            self.add_custom_ip(ip)
        for domain in domains:
            self.add_custom_domain(domain)
        logger.info(
            "Custom entries loaded: %d IPs, %d domains",
            len(ips), len(domains),
        )

    def add_custom_ip(self, ip: str) -> None:
        """라이브 차단 목록에 커스텀 IP를 추가한다."""
        if "/" in ip:
            network = ipaddress.ip_network(ip, strict=False)
            bucket = self._custom_networks[network.version].setdefault(network.prefixlen, {})
            bucket.setdefault(int(network.network_address), set()).add(ip)
        source = self._ip_to_feed.get(ip)
        if source is not None and source != "Custom":
            self._overridden_ip_sources[ip] = source
        self._custom_ips.add(ip)
        self._blocked_ips.add(ip)
        self._ip_to_feed[ip] = "Custom"

    def remove_custom_ip(self, ip: str) -> None:
        """라이브 차단 목록에서 커스텀 IP를 제거한다."""
        if ip not in self._custom_ips:
            return
        if "/" in ip:
            network = ipaddress.ip_network(ip, strict=False)
            prefixes = self._custom_networks[network.version]
            networks = prefixes[network.prefixlen]
            members = networks[int(network.network_address)]
            members.discard(ip)
            if not members:
                del networks[int(network.network_address)]
            if not networks:
                del prefixes[network.prefixlen]
        self._custom_ips.discard(ip)
        source = self._overridden_ip_sources.pop(ip, None)
        if source is not None:
            self._ip_to_feed[ip] = source
        else:
            self._blocked_ips.discard(ip)
            self._ip_to_feed.pop(ip, None)

    def add_custom_domain(self, domain: str) -> None:
        """라이브 차단 목록에 커스텀 도메인을 추가한다."""
        name = self._domain_name(domain)
        self._custom_domain_names.setdefault(name, set()).add(domain)
        source = self._domain_to_feed.get(domain)
        if source is not None and source != "Custom":
            self._overridden_domain_sources[domain] = source
        self._custom_domains.add(domain)
        self._blocked_domains.add(domain)
        self._domain_to_feed[domain] = "Custom"

    def remove_custom_domain(self, domain: str) -> None:
        """라이브 차단 목록에서 커스텀 도메인을 제거한다."""
        if domain not in self._custom_domains:
            return
        name = self._domain_name(domain)
        members = self._custom_domain_names[name]
        members.discard(domain)
        if not members:
            del self._custom_domain_names[name]
        self._custom_domains.discard(domain)
        source = self._overridden_domain_sources.pop(domain, None)
        if source is not None:
            self._domain_to_feed[domain] = source
        else:
            self._blocked_domains.discard(domain)
            self._domain_to_feed.pop(domain, None)

    @staticmethod
    def _domain_name(domain: str) -> str:
        return domain.rstrip(".").encode("idna").decode("ascii").lower()

    def _merge_current_custom_entries(self, acc: _FeedAccumulator) -> None:
        """갱신 완료 시점의 사용자 항목을 피드 원본과 합친다."""
        # 겹친 사용자 항목의 원래 출처만 보존한다. 전체 피드 사본은 추가하지 않는다.
        self._overridden_ip_sources = {ip: acc.ip_to_feed[ip] for ip in self._custom_ips if ip in acc.ip_to_feed}
        self._overridden_domain_sources = {domain: acc.domain_to_feed[domain] for domain in self._custom_domains if domain in acc.domain_to_feed}
        acc.ips.update(self._custom_ips)
        acc.domains.update(self._custom_domains)
        acc.ip_to_feed.update({ip: "Custom" for ip in self._custom_ips})
        acc.domain_to_feed.update({domain: "Custom" for domain in self._custom_domains})
        self._blocked_ips, self._blocked_domains = acc.ips, acc.domains
        self._ip_to_feed, self._domain_to_feed = acc.ip_to_feed, acc.domain_to_feed

    def get_all_entries_paginated(
        self,
        entry_type: str | None = None,
        search: str | None = None,
        source: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        """모든 차단 목록 항목(피드 + 커스텀)의 페이지네이션된 목록을 반환한다."""
        if limit < 0 or offset < 0:
            raise ValueError("Pagination limit and offset must be nonnegative")
        needle = search.lower() if search else None
        total = 0

        def matching_entries():
            nonlocal total
            for kind, mapping in (("ip", self._ip_to_feed), ("domain", self._domain_to_feed)):
                if entry_type in {"ip", "domain"} and entry_type != kind:
                    continue
                for value, feed in mapping.items():
                    custom = feed == "Custom"
                    if source == "custom" and not custom or source == "feed" and custom:
                        continue
                    if needle and needle not in value.lower():
                        continue
                    total += 1
                    yield (not custom, kind, value, feed)

        # 전체 항목의 사본 대신 요청한 페이지까지의 후보만 보관한다.
        candidates = matching_entries()
        if limit == 0:
            for _ in candidates:
                pass
            return [], total
        page = heapq.nsmallest(offset + limit, candidates)
        return [{"type": kind, "value": value, "source": feed}
                for _, kind, value, feed in page[offset:]], total

    def bind_runtime_update(self, callback) -> None:
        if not callable(callback):
            raise ValueError("Feed runtime update callback is required")
        self._runtime_update_hook = callback

    async def update_all(self) -> "FeedUpdateSummary":
        """동시 갱신을 직렬화하고 마지막 완료 시점의 사용자 항목을 반영한다."""
        async with self._update_lock:
            result = await self._update_all()
            if self._runtime_update_hook is not None:
                self._runtime_update_hook(self)
            return result

    async def _update_all(self) -> "FeedUpdateSummary":
        """구성된 모든 피드를 다운로드하고 파싱한다.

        실패해도 기존 차단 목록을 버리지 않는다 (PR 07).

        이전 구현은 갱신 **전에** 라이브 집합을 먼저 비웠다. 그 뒤 모든 다운로드가
        실패하면(네트워크 단절) threat_intel 엔진이 아무 지표도 보지 못해
        **탐지가 전부 멈춘 상태가 되는 대신**, `last_update_epoch` 은 "방금 갱신됨"으로
        갱신되어 건강 신호가 거짓말을 했다. 감시 도구가 조용히 그만 보는 것이
        가장 나쁜 실패 형태이므로 다음을 지킨다.

        1. 새 상태를 별도 집합에 쌓는다 (라이브 집합을 건드리지 않는다)
        2. 실제로 콘텐츠를 받은 피드가 하나라도 있을 때만 원자적으로 교체한다
        3. 하나도 받지 못하면 기존 상태를 유지하고 갱신 실패로 기록한다
        4. ``last_update_epoch`` 은 실제 갱신이 성공했을 때만 전진한다

        Returns:
            갱신 결과 요약.
        """
        import time as _time

        logger.info("Updating %d threat feeds...", len(self._sources))

        acc = _FeedAccumulator()

        async def _safe_update(source: FeedSource) -> None:
            try:
                await self._update_feed(source, acc)
            except Exception as exc:
                logger.warning("Failed to update feed: %s (%s)", source.name, type(exc).__name__)
                acc.fail(source.name)

        await asyncio.gather(*[_safe_update(s) for s in self._sources])

        delivered = [n for n, o in acc.outcomes.items() if o == "downloaded"]
        cached = [n for n, o in acc.outcomes.items() if o == "cached"]

        # 아무 피드도 콘텐츠를 제공하지 못했다면 기존 상태를 유지한다.
        if not delivered and not cached:
            summary = FeedUpdateSummary(
                succeeded=False,
                delivered=0,
                from_cache=0,
                failed=len(self._sources),
                blocked_ips=len(self._blocked_ips),
                blocked_domains=len(self._blocked_domains),
                last_update_epoch=self.last_update_epoch,
            )
            self._pending_outcomes = dict(acc.outcomes)
            self._record_status(summary, ok=False)
            logger.error(
                "모든 위협 피드 갱신 실패 — 기존 차단 목록 %d IP / %d 도메인을 유지한다",
                len(self._blocked_ips), len(self._blocked_domains),
            )
            return summary

        # 원자적 교체: 여기까지는 라이브 집합을 건드리지 않았다
        self._merge_current_custom_entries(acc)
        self._blocked_ja3 = acc.ja3
        self._ja3_to_malware = acc.ja3_to_malware

        if delivered or acc.validated_cached:
            self.last_update_epoch = _time.time()
            for name in set(delivered) | acc.validated_cached:
                self._confirmed_epochs[name] = self.last_update_epoch
        self._save_meta()

        summary = FeedUpdateSummary(
            succeeded=True,
            delivered=len(delivered),
            from_cache=len(cached),
            failed=sum(1 for o in acc.outcomes.values() if o == "failed"),
            blocked_ips=len(self._blocked_ips),
            blocked_domains=len(self._blocked_domains),
            last_update_epoch=self.last_update_epoch,
        )
        self._pending_outcomes = dict(acc.outcomes)
        self._record_status(summary, ok=True)

        logger.info(
            "Threat feeds updated: %d blocked IPs, %d blocked domains, "
            "%d JA3 fingerprints (downloaded=%d, cached=%d, failed=%d)",
            len(self._blocked_ips),
            len(self._blocked_domains),
            len(self._blocked_ja3),
            summary.delivered,
            summary.from_cache,
            summary.failed,
        )
        return summary

    def _record_status(self, summary: "FeedUpdateSummary", ok: bool) -> None:
        """피드 상태를 갱신하고 Prometheus 메트릭에 반영한다."""
        self._last_summary = summary
        self._last_attempt_epoch = summary.last_update_epoch or self._last_attempt_epoch
        self._feed_outcomes = dict(getattr(self, "_pending_outcomes", {}) or {})
        try:
            from netwatcher.web.metrics import feed_last_update
            # 실패한 갱신이므로 이전 성공 시각을 그대로 유지한다
            feed_last_update.set(self.last_update_epoch)
        except ImportError:
            pass

    def feed_health(self, stale_after_hours: float = 12.0) -> dict:
        """피드 신선도를 정직하게 보고한다 (PR 07).

        "갱신 작업은 돌고 있다" 와 "지표가 최신이다" 는 다른 문제다. 실행 중이어도
        모든 다운로드가 실패한 상태일 수 있으므로, 마지막 **성공** 시각과 성공
        여부를 함께 노출한다.
        """
        import time as _time

        now = _time.time()
        age_hours = None
        if self.last_update_epoch:
            age_hours = (now - self.last_update_epoch) / 3600.0
            if age_hours < 0:
                age_hours = None

        stale = age_hours is None or age_hours > stale_after_hours
        summary = self._last_summary
        sources = []
        confirmed = getattr(self, '_confirmed_epochs', {})
        for source in self._sources:
            epoch = confirmed.get(source.name, 0)
            age = (now - epoch) / 3600.0 if epoch else None
            if age is not None and age < 0:
                epoch, age = 0, None
            sources.append({'name': source.name,
                'status': 'unknown' if age is None or age < 0 else 'stale' if age > stale_after_hours else 'ok',
                'last_success_epoch': epoch or None, 'age_hours': round(age, 2) if age is not None else None,
                'outcome': self._feed_outcomes.get(source.name)})
        fresh = sum(source['status'] == 'ok' for source in sources)
        status = ('ok' if fresh == len(sources) else 'degraded' if fresh else 'stale') if sources else ('stale' if stale else 'ok')
        return {
            # 실행 중이어도 데이터가 오래되면 stale 로 보고한다
            "status": status,
            "sources": sources,
            "last_success_epoch": self.last_update_epoch if age_hours is not None else 0.0,
            "age_hours": round(age_hours, 2) if age_hours is not None else None,
            "stale_after_hours": stale_after_hours,
            "blocked_ips": len(self._blocked_ips),
            "blocked_domains": len(self._blocked_domains),
            "blocked_ja3": len(self._blocked_ja3),
            "custom_ips": len(self._custom_ips),
            "last_attempt": summary.as_dict() if summary else None,
            "outcomes": dict(self._feed_outcomes),
        }

    def is_stale(self, stale_after_hours: float = 12.0) -> bool:
        """피드 데이터가 오래되었으면 True."""
        health = self.feed_health(stale_after_hours)
        return health["status"] in ('stale', 'degraded')

    def health_as_violations(self, stale_after_hours: float = 12.0) -> list:
        """피드 상태가 나쁘면 지원 계약 위반 목록으로 바꾼다 (PR 07).

        "갱신 루프가 살아 있다" 와 "지표가 최신이다" 는 다르다. threat_intel 엔진은
        피드가 비면 조용히 아무것도 탐지하지 않으므로, 그 상태를 기동/상태 경로에서
        숨기지 않는다.
        """
        from netwatcher.support import Violation

        health = self.feed_health(stale_after_hours)
        if health["status"] not in ('stale', 'degraded'):
            return []

        age = health["age_hours"]
        if health['status'] == 'degraded':
            message = '일부 위협 피드의 갱신 상태를 확인해야 합니다'
            remediation = '피드별 성공 시각과 캐시·실패 결과를 확인합니다'
        elif age is None:
            message = "위협 피드가 한 번도 성공적으로 갱신된 적이 없다"
            remediation = "threat_intel 엔진을 끄거나, 네트워크·피드 URL 을 점검한다"
        else:
            message = f"위협 피드 데이터가 {age}시간 전 상태로 정체되어 있다"
            remediation = "피드 다운로드 실패 원인(네트워크·인증·URL)을 확인한다"

        return [Violation(
            code="SUP-060",
            path="threatfeeds",
            message=message,
            remediation=remediation,
        )]


    def _load_meta(self) -> dict[str, dict[str, str]]:
        """디스크에서 피드별 HTTP 메타데이터(ETag, Last-Modified)를 로드한다."""
        if self._meta_file.exists():
            try:
                return json.loads(self._meta_file.read_text())
            except (json.JSONDecodeError, OSError):
                logger.warning("피드 메타 파일 손상, 초기화합니다")
        return {}

    def _save_meta(self) -> None:
        """피드별 HTTP 메타데이터를 디스크에 저장한다."""
        try:
            self._meta_file.write_text(json.dumps(self._feed_meta, indent=2))
        except OSError:
            logger.warning("피드 메타 파일 저장 실패")

    async def _update_feed(self, source: FeedSource, acc: _FeedAccumulator) -> None:
        """단일 피드를 다운로드하고 파싱한다 (조건부 요청 지원)."""
        cache_file = self._cache_dir / f"{source.name.replace(' ', '_').lower()}.txt"

        # SSRF 방지: 내부/사설 URL 거부
        safe_url = validate_outbound_url(source.url)
        if safe_url is None:
            logger.error("피드 URL이 내부 주소를 대상으로 하여 차단됨: %s", source.name)
            self._load_from_cache(source, cache_file, acc)
            return

        # 이전 메타데이터에서 조건부 요청 헤더 구성
        headers: dict[str, str] = {}
        meta = self._feed_meta.get(source.name, {})
        if cache_file.exists():
            if meta.get("etag"):
                headers["If-None-Match"] = meta["etag"]
            if meta.get("last_modified"):
                headers["If-Modified-Since"] = meta["last_modified"]

        try:
            async with public_client_session() as session:
                async with session.get(
                    safe_url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 304:
                        logger.info("Feed %s: not modified (304), using cache", source.name)
                        self._load_from_cache(source, cache_file, acc)
                        if headers and acc.outcomes.get(source.name) == 'cached':
                            acc.validated_cached.add(source.name)
                        return

                    if resp.status != 200:
                        logger.warning(
                            "Feed %s returned HTTP %d", source.name, resp.status
                        )
                        self._load_from_cache(source, cache_file, acc)
                        return

                    content = await resp.text()

                    # 다음 조건부 요청을 위해 ETag / Last-Modified 저장
                    new_meta: dict[str, str] = {}
                    if resp.headers.get("ETag"):
                        new_meta["etag"] = resp.headers["ETag"]
                    if resp.headers.get("Last-Modified"):
                        new_meta["last_modified"] = resp.headers["Last-Modified"]
                    if new_meta:
                        self._feed_meta[source.name] = new_meta

            cache_file.write_text(content)

        except (aiohttp.ClientError, OSError, TimeoutError, UnicodeError) as exc:
            logger.warning("Failed to download feed %s (%s), using cache", source.name, type(exc).__name__)
            self._load_from_cache(source, cache_file, acc)
            return

        self._parse_and_store(source, content, acc)

    def _load_from_cache(
        self, source: FeedSource, cache_file: Path, acc: _FeedAccumulator,
    ) -> None:
        """로컬 캐시 파일에서 피드를 로드한다."""
        if cache_file.exists():
            try:
                content = cache_file.read_text()
            except OSError:
                logger.warning("캐시 읽기 실패: %s", source.name)
                acc.fail(source.name)
                return
            self._parse_and_store(source, content, acc)
            acc.record(source.name, "cached")
        else:
            logger.warning("No cache available for feed: %s", source.name)
            acc.fail(source.name)

    def _parse_and_store(
        self, source: FeedSource, content: str, acc: _FeedAccumulator,
    ) -> None:
        """피드 콘텐츠를 파싱하고 피드 출처와 함께 차단 목록에 추가한다."""
        # JA3 피드는 악성코드 매핑을 위한 별도 처리 필요
        if source.feed_type == "ja3":
            ja3_set, ja3_map = parse_ja3_feed(content, source.comment_prefix)
            acc.ja3.update(ja3_set)
            acc.ja3_to_malware.update(ja3_map)
            acc.record(source.name, "downloaded")
            logger.info(
                "Feed %s: loaded %d JA3 fingerprints", source.name, len(ja3_set)
            )
            return

        entries = parse_feed(content, source)

        if source.feed_type == "ip":
            acc.ips.update(entries)
            for ip in entries:
                acc.ip_to_feed[ip] = source.name
            acc.record(source.name, "downloaded")
            logger.info("Feed %s: loaded %d IPs", source.name, len(entries))
        elif source.feed_type in ("domain", "url"):
            # URL 유형 피드에서 공유 호스팅 플랫폼을 필터링한다.
            # 이 피드에는 정상 플랫폼에 호스팅된 악성 콘텐츠의 전체 URL이 포함되어 있다
            # (예: github.com/user/malware). 전체 도메인을 차단하면 오탐이 발생한다.
            if source.feed_type == "url":
                filtered = set()
                for domain in entries:
                    if self._is_shared_platform(domain):
                        continue
                    filtered.add(domain)
                removed = len(entries) - len(filtered)
                if removed:
                    logger.info(
                        "Feed %s: filtered %d shared platform domains",
                        source.name, removed,
                    )
                entries = filtered

            acc.domains.update(entries)
            for domain in entries:
                acc.domain_to_feed[domain] = source.name
            acc.record(source.name, "downloaded")
            logger.info("Feed %s: loaded %d domains", source.name, len(entries))

    @staticmethod
    def _is_shared_platform(domain: str) -> bool:
        """도메인이 알려진 공유 호스팅 플랫폼에 속하는지 확인한다."""
        lower = domain.lower()
        for platform in _SHARED_PLATFORM_DOMAINS:
            if lower == platform or lower.endswith("." + platform):
                return True
        return False
