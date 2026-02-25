"""위협 인텔리전스 피드 관리자: 다운로드, 파싱, 캐싱."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import aiohttp

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

        # JA3 차단 목록 (SSLBL 피드에서 채워짐)
        self._blocked_ja3: set[str] = set()
        self._ja3_to_malware: dict[str, str] = {}

        # 커스텀 항목 (사용자 관리, 피드 업데이트 간 보존)
        self._custom_ips: set[str] = set()
        self._custom_domains: set[str] = set()

        # 각 지표가 어느 피드에서 왔는지 추적
        self._ip_to_feed: dict[str, str] = {}
        self._domain_to_feed: dict[str, str] = {}

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

    def load_custom_entries(self, ips: set[str], domains: set[str]) -> None:
        """시작 시 DB에서 커스텀 항목을 로드하고 라이브 집합에 병합한다."""
        self._custom_ips = set(ips)
        self._custom_domains = set(domains)
        self._blocked_ips.update(ips)
        self._blocked_domains.update(domains)
        for ip in ips:
            self._ip_to_feed[ip] = "Custom"
        for domain in domains:
            self._domain_to_feed[domain] = "Custom"
        logger.info(
            "Custom entries loaded: %d IPs, %d domains",
            len(ips), len(domains),
        )

    def add_custom_ip(self, ip: str) -> None:
        """라이브 차단 목록에 커스텀 IP를 추가한다."""
        self._custom_ips.add(ip)
        self._blocked_ips.add(ip)
        self._ip_to_feed[ip] = "Custom"

    def remove_custom_ip(self, ip: str) -> None:
        """라이브 차단 목록에서 커스텀 IP를 제거한다."""
        self._custom_ips.discard(ip)
        self._blocked_ips.discard(ip)
        self._ip_to_feed.pop(ip, None)

    def add_custom_domain(self, domain: str) -> None:
        """라이브 차단 목록에 커스텀 도메인을 추가한다."""
        self._custom_domains.add(domain)
        self._blocked_domains.add(domain)
        self._domain_to_feed[domain] = "Custom"

    def remove_custom_domain(self, domain: str) -> None:
        """라이브 차단 목록에서 커스텀 도메인을 제거한다."""
        self._custom_domains.discard(domain)
        self._blocked_domains.discard(domain)
        self._domain_to_feed.pop(domain, None)

    def get_all_entries_paginated(
        self,
        entry_type: str | None = None,
        search: str | None = None,
        source: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict], int]:
        """모든 차단 목록 항목(피드 + 커스텀)의 페이지네이션된 목록을 반환한다."""
        entries: list[dict] = []

        if entry_type != "domain":
            for ip, feed in self._ip_to_feed.items():
                entries.append({"entry_type": "ip", "value": ip, "source": feed})

        if entry_type != "ip":
            for domain, feed in self._domain_to_feed.items():
                entries.append({"entry_type": "domain", "value": domain, "source": feed})

        # 소스별 필터링
        if source == "custom":
            entries = [e for e in entries if e["source"] == "Custom"]
        elif source == "feed":
            entries = [e for e in entries if e["source"] != "Custom"]

        # 검색어별 필터링
        if search:
            s = search.lower()
            entries = [e for e in entries if s in e["value"].lower()]

        total = len(entries)
        entries.sort(key=lambda e: (e["source"] != "Custom", e["entry_type"], e["value"]))
        return entries[offset:offset + limit], total

    async def update_all(self) -> None:
        """구성된 모든 피드를 다운로드하고 파싱한다."""
        import time as _time

        logger.info("Updating %d threat feeds...", len(self._sources))

        # 피드 재로드 전 커스텀 전용으로 초기화 (in-place 변형으로 참조 보존)
        self._blocked_ips.clear()
        self._blocked_ips.update(self._custom_ips)
        self._blocked_domains.clear()
        self._blocked_domains.update(self._custom_domains)
        self._blocked_ja3.clear()
        self._ja3_to_malware.clear()
        self._ip_to_feed.clear()
        self._ip_to_feed.update({ip: "Custom" for ip in self._custom_ips})
        self._domain_to_feed.clear()
        self._domain_to_feed.update({d: "Custom" for d in self._custom_domains})

        import asyncio

        async def _safe_update(source: FeedSource) -> None:
            try:
                await self._update_feed(source)
            except Exception:
                logger.exception("Failed to update feed: %s", source.name)

        await asyncio.gather(*[_safe_update(s) for s in self._sources])

        self.last_update_epoch = _time.time()
        self._save_meta()

        logger.info(
            "Threat feeds updated: %d blocked IPs, %d blocked domains, "
            "%d JA3 fingerprints",
            len(self._blocked_ips),
            len(self._blocked_domains),
            len(self._blocked_ja3),
        )

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

    async def _update_feed(self, source: FeedSource) -> None:
        """단일 피드를 다운로드하고 파싱한다 (조건부 요청 지원)."""
        cache_file = self._cache_dir / f"{source.name.replace(' ', '_').lower()}.txt"

        # SSRF 방지: 내부/사설 URL 거부
        safe_url = validate_outbound_url(source.url)
        if safe_url is None:
            logger.error(
                "피드 URL이 내부 주소를 대상으로 하여 차단됨: %s (%s)",
                source.name, source.url,
            )
            self._load_from_cache(source, cache_file)
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
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    safe_url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 304:
                        logger.info("Feed %s: not modified (304), using cache", source.name)
                        self._load_from_cache(source, cache_file)
                        return

                    if resp.status != 200:
                        logger.warning(
                            "Feed %s returned HTTP %d", source.name, resp.status
                        )
                        self._load_from_cache(source, cache_file)
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

        except Exception:
            logger.warning("Failed to download feed %s, using cache", source.name)
            self._load_from_cache(source, cache_file)
            return

        self._parse_and_store(source, content)

    def _load_from_cache(self, source: FeedSource, cache_file: Path) -> None:
        """로컬 캐시 파일에서 피드를 로드한다."""
        if cache_file.exists():
            content = cache_file.read_text()
            self._parse_and_store(source, content)
        else:
            logger.warning("No cache available for feed: %s", source.name)

    def _parse_and_store(self, source: FeedSource, content: str) -> None:
        """피드 콘텐츠를 파싱하고 피드 출처와 함께 차단 목록에 추가한다."""
        # JA3 피드는 악성코드 매핑을 위한 별도 처리 필요
        if source.feed_type == "ja3":
            ja3_set, ja3_map = parse_ja3_feed(content, source.comment_prefix)
            self._blocked_ja3.update(ja3_set)
            self._ja3_to_malware.update(ja3_map)
            logger.info(
                "Feed %s: loaded %d JA3 fingerprints", source.name, len(ja3_set)
            )
            return

        entries = parse_feed(content, source)

        if source.feed_type == "ip":
            self._blocked_ips.update(entries)
            for ip in entries:
                self._ip_to_feed[ip] = source.name
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

            self._blocked_domains.update(entries)
            for domain in entries:
                self._domain_to_feed[domain] = source.name
            logger.info("Feed %s: loaded %d domains", source.name, len(entries))

    @staticmethod
    def _is_shared_platform(domain: str) -> bool:
        """도메인이 알려진 공유 호스팅 플랫폼에 속하는지 확인한다."""
        lower = domain.lower()
        for platform in _SHARED_PLATFORM_DOMAINS:
            if lower == platform or lower.endswith("." + platform):
                return True
        return False
