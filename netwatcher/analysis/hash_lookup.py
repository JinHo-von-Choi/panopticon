"""파일 해시 평판 조회 클라이언트 (VirusTotal, MalwareBazaar).

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass, field

logger = logging.getLogger("netwatcher.analysis.hash_lookup")

try:
    import aiohttp
    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False
    logger.warning("aiohttp not installed -- hash lookup disabled")


@dataclass
class HashResult:
    """해시 조회 결과."""
    sha256: str
    known_malicious: bool
    vt_positives: int = 0
    vt_total: int = 0
    malware_family: str = ""
    source: str = ""  # "virustotal", "malwarebazaar", "cache", "unavailable"
    timestamp: float = field(default_factory=time.time)


class _LRUCache:
    """최대 크기를 가진 LRU 캐시."""

    __slots__ = ("_data", "_maxlen")

    def __init__(self, maxlen: int = 10_000) -> None:
        self._data: OrderedDict[str, HashResult] = OrderedDict()
        self._maxlen = max(16, maxlen)

    def get(self, key: str) -> HashResult | None:
        if key in self._data:
            self._data.move_to_end(key)
            return self._data[key]
        return None

    def put(self, key: str, value: HashResult) -> None:
        if key in self._data:
            self._data.move_to_end(key)
        self._data[key] = value
        while len(self._data) > self._maxlen:
            self._data.popitem(last=False)

    def __len__(self) -> int:
        return len(self._data)


class HashLookupClient:
    """VirusTotal 및 MalwareBazaar 비동기 해시 조회 클라이언트."""

    _VT_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
    _MB_URL = "https://mb-api.abuse.ch/api/v1/"

    def __init__(
        self,
        vt_api_key: str = "",
        mb_enabled: bool = True,
        cache_size: int = 10_000,
    ) -> None:
        self._vt_api_key = vt_api_key
        self._mb_enabled = mb_enabled
        self._cache      = _LRUCache(maxlen=cache_size)
        self._session: aiohttp.ClientSession | None = None  # type: ignore[name-defined]
        # VT 무료 티어: 분당 4회. Semaphore + 최소 간격으로 제어
        self._vt_semaphore = asyncio.Semaphore(1)
        self._vt_last_call = 0.0
        self._mb_semaphore = asyncio.Semaphore(1)
        self._mb_last_call = 0.0

    @property
    def available(self) -> bool:
        """aiohttp가 설치되어 있고 하나 이상의 소스가 활성화되어 있는지 반환한다."""
        return _HAS_AIOHTTP and (bool(self._vt_api_key) or self._mb_enabled)

    async def lookup(self, sha256: str) -> HashResult:
        """파일 해시를 조회한다. 캐시된 결과가 있으면 우선 반환한다."""
        cached = self._cache.get(sha256)
        if cached is not None:
            return HashResult(
                sha256=cached.sha256,
                known_malicious=cached.known_malicious,
                vt_positives=cached.vt_positives,
                vt_total=cached.vt_total,
                malware_family=cached.malware_family,
                source="cache",
                timestamp=cached.timestamp,
            )

        if not _HAS_AIOHTTP:
            return HashResult(sha256=sha256, known_malicious=False, source="unavailable")

        # VirusTotal 우선 조회
        if self._vt_api_key:
            result = await self._lookup_virustotal(sha256)
            if result is not None:
                self._cache.put(sha256, result)
                return result

        # MalwareBazaar 폴백
        if self._mb_enabled:
            result = await self._lookup_malwarebazaar(sha256)
            if result is not None:
                self._cache.put(sha256, result)
                return result

        # 조회 실패
        result = HashResult(sha256=sha256, known_malicious=False, source="unavailable")
        self._cache.put(sha256, result)
        return result

    async def close(self) -> None:
        """HTTP 세션을 닫는다."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    # ------------------------------------------------------------------
    # 내부: VirusTotal
    # ------------------------------------------------------------------

    async def _lookup_virustotal(self, sha256: str) -> HashResult | None:
        """VirusTotal API v3으로 해시를 조회한다."""
        async with self._vt_semaphore:
            # 분당 4회 제한 -> 최소 15초 간격
            elapsed = time.monotonic() - self._vt_last_call
            if elapsed < 15.0:
                await asyncio.sleep(15.0 - elapsed)

            session = await self._get_session()
            url     = self._VT_URL.format(sha256=sha256)
            headers = {"x-apikey": self._vt_api_key}

            try:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    self._vt_last_call = time.monotonic()

                    if resp.status == 404:
                        return None
                    if resp.status == 429:
                        logger.warning("VirusTotal rate limit hit")
                        return None
                    if resp.status != 200:
                        logger.warning("VirusTotal returned status %d", resp.status)
                        return None

                    data  = await resp.json()
                    attrs = data.get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
                    total     = sum(stats.values()) if stats else 0

                    family = ""
                    popular = attrs.get("popular_threat_classification", {})
                    if popular:
                        label = popular.get("suggested_threat_label", "")
                        family = label

                    return HashResult(
                        sha256=sha256,
                        known_malicious=positives > 0,
                        vt_positives=positives,
                        vt_total=total,
                        malware_family=family,
                        source="virustotal",
                    )
            except Exception as exc:
                logger.error("VirusTotal lookup failed: %s", exc)
                return None

    # ------------------------------------------------------------------
    # 내부: MalwareBazaar
    # ------------------------------------------------------------------

    async def _lookup_malwarebazaar(self, sha256: str) -> HashResult | None:
        """MalwareBazaar API로 해시를 조회한다."""
        async with self._mb_semaphore:
            # 초당 1회 제한
            elapsed = time.monotonic() - self._mb_last_call
            if elapsed < 1.0:
                await asyncio.sleep(1.0 - elapsed)

            session = await self._get_session()
            payload = {"query": "get_info", "hash": sha256}

            try:
                async with session.post(
                    self._MB_URL,
                    data=payload,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    self._mb_last_call = time.monotonic()

                    if resp.status != 200:
                        logger.warning("MalwareBazaar returned status %d", resp.status)
                        return None

                    data = await resp.json()
                    status = data.get("query_status", "")

                    if status != "ok":
                        return None

                    info   = data.get("data", [{}])[0] if data.get("data") else {}
                    family = info.get("signature", "") or ""

                    return HashResult(
                        sha256=sha256,
                        known_malicious=True,
                        malware_family=family,
                        source="malwarebazaar",
                    )
            except Exception as exc:
                logger.error("MalwareBazaar lookup failed: %s", exc)
                return None

    # ------------------------------------------------------------------
    # 세션 관리
    # ------------------------------------------------------------------

    async def _get_session(self) -> aiohttp.ClientSession:  # type: ignore[name-defined]
        """공유 aiohttp 세션을 반환하거나 생성한다."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session
