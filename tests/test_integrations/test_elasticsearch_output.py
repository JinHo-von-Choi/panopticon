"""Elasticsearch 출력 채널 단위 테스트."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from netwatcher.detection.models import Alert, Severity
from netwatcher.integrations.elasticsearch_output import (
    ElasticsearchChannel,
    _FLUSH_INTERVAL_SECONDS,
    _MAX_BATCH_SIZE,
)


def _make_alert(**overrides) -> Alert:
    defaults = dict(
        engine="dns_anomaly",
        severity=Severity.WARNING,
        title="DGA Domain Detected",
        description="Suspicious domain: xk3jm2n.example.com",
        source_ip="10.0.0.50",
        dest_ip="8.8.8.8",
        confidence=0.78,
        mitre_attack_id="T1071.004",
    )
    defaults.update(overrides)
    return Alert(**defaults)


def _make_channel(**overrides) -> ElasticsearchChannel:
    defaults = {
        "enabled": True,
        "hosts": ["http://localhost:9200"],
        "index_prefix": "netwatcher-events",
        "api_key": "",
        "min_severity": "INFO",
    }
    defaults.update(overrides)
    return ElasticsearchChannel(defaults)


class TestElasticsearchChannel:
    def test_init(self):
        ch = _make_channel(api_key="test-key")
        assert ch._hosts == ["http://localhost:9200"]
        assert ch._api_key == "test-key"
        assert ch._index_prefix == "netwatcher-events"

    def test_index_name_format(self):
        ch   = _make_channel()
        name = ch._get_index_name()
        assert name.startswith("netwatcher-events-")
        # YYYY.MM 형식
        parts = name.split("-")[-1]
        year, month = parts.split(".")
        assert len(year) == 4
        assert len(month) == 2

    def test_build_headers_with_api_key(self):
        ch      = _make_channel(api_key="my-api-key")
        headers = ch._build_headers()
        assert headers["Authorization"] == "ApiKey my-api-key"

    def test_build_headers_without_api_key(self):
        ch      = _make_channel()
        headers = ch._build_headers()
        assert "Authorization" not in headers

    def test_build_auth(self):
        ch   = _make_channel(username="elastic", password="secret")
        auth = ch._build_auth()
        assert auth is not None
        assert auth.login == "elastic"

    def test_build_auth_none(self):
        ch   = _make_channel()
        auth = ch._build_auth()
        assert auth is None

    def test_build_bulk_body(self):
        ch  = _make_channel()
        doc = {"@timestamp": "2025-01-01T00:00:00Z", "message": "test"}
        body = ch._build_bulk_body([doc], "test-index")

        lines = body.strip().split("\n")
        assert len(lines) == 2
        action = json.loads(lines[0])
        assert action["index"]["_index"] == "test-index"
        payload = json.loads(lines[1])
        assert payload["message"] == "test"

    @pytest.mark.asyncio
    async def test_send_buffers_alert(self):
        ch    = _make_channel()
        alert = _make_alert()

        result = await ch.send(alert)

        assert result is True
        assert len(ch._buffer) == 1
        assert ch._buffer[0]["message"] == "DGA Domain Detected"

    @pytest.mark.asyncio
    async def test_flush_empty_buffer(self):
        ch     = _make_channel()
        result = await ch.flush()
        assert result is True

    @pytest.mark.asyncio
    async def test_flush_calls_bulk(self):
        ch    = _make_channel()
        alert = _make_alert()
        await ch.send(alert)

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json   = AsyncMock(return_value={"errors": False, "items": [{}]})

        mock_session_ctx = AsyncMock()
        mock_session_ctx.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_session_ctx.__aexit__  = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.post = MagicMock(return_value=mock_session_ctx)

        mock_session_factory = AsyncMock()
        mock_session_factory.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_factory.__aexit__  = AsyncMock(return_value=False)

        with patch("netwatcher.integrations.elasticsearch_output.aiohttp.ClientSession", return_value=mock_session_factory):
            result = await ch.flush()

        assert result is True
        assert len(ch._buffer) == 0

    @pytest.mark.asyncio
    async def test_send_triggers_flush_at_max_batch(self):
        ch = _make_channel()
        ch._flush_locked = AsyncMock(return_value=True)

        for i in range(_MAX_BATCH_SIZE):
            await ch.send(_make_alert(title=f"Alert {i}"))

        ch._flush_locked.assert_called()

    @pytest.mark.asyncio
    async def test_stop_flushes_remaining(self):
        ch    = _make_channel()
        alert = _make_alert()
        await ch.send(alert)

        ch._flush_locked = AsyncMock(return_value=True)
        # flush()는 _flush_locked를 직접 호출하므로 flush를 mock
        original_flush = ch.flush
        ch.flush = AsyncMock(return_value=True)

        await ch.stop()
        ch.flush.assert_called_once()
