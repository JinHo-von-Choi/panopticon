"""Tests for HashLookupClient.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from netwatcher.analysis.hash_lookup import HashLookupClient, HashResult, _LRUCache


# ---------------------------------------------------------------------------
# _LRUCache 테스트
# ---------------------------------------------------------------------------

class TestLRUCache:
    """LRU 캐시 테스트."""

    def test_put_and_get(self):
        cache = _LRUCache(maxlen=100)
        result = HashResult(sha256="abc", known_malicious=False)
        cache.put("abc", result)
        assert cache.get("abc") is result

    def test_miss_returns_none(self):
        cache = _LRUCache(maxlen=100)
        assert cache.get("nonexistent") is None

    def test_eviction_on_capacity(self):
        cache = _LRUCache(maxlen=20)
        for i in range(25):
            cache.put(f"key_{i}", HashResult(sha256=f"key_{i}", known_malicious=False))
        assert len(cache) == 20
        # 가장 오래된 항목이 제거됨
        assert cache.get("key_0") is None
        assert cache.get("key_24") is not None

    def test_access_refreshes_order(self):
        cache = _LRUCache(maxlen=20)
        for i in range(20):
            cache.put(f"key_{i}", HashResult(sha256=f"key_{i}", known_malicious=False))
        # key_0에 접근하여 갱신
        cache.get("key_0")
        # 5개 더 추가 -> key_1 ~ key_4 가 제거됨
        for i in range(20, 25):
            cache.put(f"key_{i}", HashResult(sha256=f"key_{i}", known_malicious=False))
        # key_0은 최근 접근했으므로 살아있어야 함
        assert cache.get("key_0") is not None


# ---------------------------------------------------------------------------
# HashLookupClient 테스트
# ---------------------------------------------------------------------------

class TestHashLookupClient:
    """HashLookupClient 테스트."""

    def test_not_available_without_keys(self):
        client = HashLookupClient(vt_api_key="", mb_enabled=False)
        assert not client.available

    def test_available_with_vt_key(self):
        client = HashLookupClient(vt_api_key="test_key")
        assert client.available

    def test_available_with_mb_only(self):
        client = HashLookupClient(vt_api_key="", mb_enabled=True)
        assert client.available

    @pytest.mark.asyncio
    async def test_cache_hit(self):
        """캐시에 있는 해시는 네트워크 호출 없이 반환한다."""
        client = HashLookupClient(vt_api_key="key")
        # 수동으로 캐시에 삽입
        cached = HashResult(sha256="abc123", known_malicious=True, vt_positives=5, source="virustotal")
        client._cache.put("abc123", cached)

        result = await client.lookup("abc123")
        assert result.source == "cache"
        assert result.known_malicious
        assert result.vt_positives == 5
        await client.close()

    @pytest.mark.asyncio
    async def test_unavailable_returns_result(self):
        """소스가 없으면 unavailable 결과를 반환한다."""
        client = HashLookupClient(vt_api_key="", mb_enabled=False)
        result = await client.lookup("deadbeef" * 8)
        assert result.source == "unavailable"
        assert not result.known_malicious
        await client.close()

    @pytest.mark.asyncio
    async def test_vt_success(self):
        """VirusTotal 조회 성공 시나리오."""
        client = HashLookupClient(vt_api_key="test_key", mb_enabled=False)

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value={
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 10,
                        "suspicious": 2,
                        "undetected": 50,
                        "harmless": 5,
                    },
                    "popular_threat_classification": {
                        "suggested_threat_label": "trojan.generic",
                    },
                },
            },
        })
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_resp)
        mock_session.closed = False
        client._session = mock_session

        result = await client.lookup("a" * 64)
        assert result.known_malicious
        assert result.vt_positives == 12
        assert result.vt_total == 67
        assert result.malware_family == "trojan.generic"
        assert result.source == "virustotal"
        await client.close()

    @pytest.mark.asyncio
    async def test_vt_404_falls_to_mb(self):
        """VT에서 404이면 MalwareBazaar로 폴백한다."""
        client = HashLookupClient(vt_api_key="test_key", mb_enabled=True)

        # VT: 404
        vt_resp = AsyncMock()
        vt_resp.status = 404
        vt_resp.__aenter__ = AsyncMock(return_value=vt_resp)
        vt_resp.__aexit__ = AsyncMock(return_value=False)

        # MB: success
        mb_resp = AsyncMock()
        mb_resp.status = 200
        mb_resp.json = AsyncMock(return_value={
            "query_status": "ok",
            "data": [{"signature": "Emotet"}],
        })
        mb_resp.__aenter__ = AsyncMock(return_value=mb_resp)
        mb_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=vt_resp)
        mock_session.post = MagicMock(return_value=mb_resp)
        mock_session.closed = False
        client._session = mock_session

        result = await client.lookup("b" * 64)
        assert result.known_malicious
        assert result.malware_family == "Emotet"
        assert result.source == "malwarebazaar"
        await client.close()

    @pytest.mark.asyncio
    async def test_both_fail_returns_unavailable(self):
        """VT와 MB 모두 실패하면 unavailable을 반환한다."""
        client = HashLookupClient(vt_api_key="test_key", mb_enabled=True)

        vt_resp = AsyncMock()
        vt_resp.status = 500
        vt_resp.__aenter__ = AsyncMock(return_value=vt_resp)
        vt_resp.__aexit__ = AsyncMock(return_value=False)

        mb_resp = AsyncMock()
        mb_resp.status = 500
        mb_resp.__aenter__ = AsyncMock(return_value=mb_resp)
        mb_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=vt_resp)
        mock_session.post = MagicMock(return_value=mb_resp)
        mock_session.closed = False
        client._session = mock_session

        result = await client.lookup("c" * 64)
        assert result.source == "unavailable"
        assert not result.known_malicious
        await client.close()
