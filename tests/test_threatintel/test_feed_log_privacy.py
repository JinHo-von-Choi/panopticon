"""피드 연결 실패가 URL 인증값을 로그에 남기지 않고 캐시를 보존한다."""

import aiohttp
import pytest
from multidict import CIMultiDict, CIMultiDictProxy
from yarl import URL

import netwatcher.threatintel.feed_manager as feeds
from netwatcher.threatintel.sources import FeedSource
from netwatcher.utils.config import Config


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["redirect", "blocked"])
async def test_failed_feed_preserves_cache_without_logging_url_credentials(tmp_path, monkeypatch, caplog, failure):
    monkeypatch.chdir(tmp_path)
    manager = feeds.FeedManager(Config({"threatfeeds": {"config_path": str(tmp_path / "unused.yaml")}}))
    marker = "synthetic-feed-credential-marker"
    host = "127.0.0.1" if failure == "blocked" else "feed.example.invalid"
    address = f"https://{host}/feed?api_key={marker}"
    source = FeedSource("Privacy fixture", address, "ip", "text", "#")
    (manager._cache_dir / "privacy_fixture.txt").write_text("203.0.113.7\n")
    accumulator = feeds._FeedAccumulator()
    request = aiohttp.RequestInfo(URL(address), "GET", CIMultiDictProxy(CIMultiDict()), URL(address))

    class Response:
        async def __aenter__(self):
            raise aiohttp.TooManyRedirects(request, ())

        async def __aexit__(self, *arguments):
            return False

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *arguments):
            return False

        def get(self, *arguments, **options):
            return Response()

    if failure == "redirect":
        monkeypatch.setattr(feeds, "validate_outbound_url", lambda value: value)
        monkeypatch.setattr(feeds, "public_client_session", Session)
    else:
        def forbid_connection():
            raise AssertionError("Blocked address must not create an HTTP session")
        monkeypatch.setattr(feeds, "public_client_session", forbid_connection)

    with caplog.at_level("WARNING", logger=feeds.logger.name):
        await manager._update_feed(source, accumulator)
    assert marker not in caplog.text
    assert address not in caplog.text
    assert accumulator.ips == {"203.0.113.7"}
    assert accumulator.outcomes[source.name] == "cached"
    assert source.name not in accumulator.validated_cached
    assert source.name in caplog.text
    if failure == "redirect":
        assert "TooManyRedirects" in caplog.text


@pytest.mark.asyncio
async def test_unexpected_failure_keeps_live_feed_without_logging_exception_contents(tmp_path, monkeypatch, caplog):
    monkeypatch.chdir(tmp_path)
    manager = feeds.FeedManager(Config({"threatfeeds": {"config_path": str(tmp_path / "unused.yaml")}}))
    marker = "synthetic-unexpected-feed-credential"
    address = f"https://feed.example.invalid/?api_key={marker}"
    source = FeedSource("Unexpected fixture", address, "ip", "text", "#")
    manager._sources = [source]
    manager._blocked_ips = {"203.0.113.7"}

    async def fail(source, accumulator):
        raise ValueError(source.url)

    monkeypatch.setattr(manager, "_update_feed", fail)
    with caplog.at_level("WARNING", logger=feeds.logger.name):
        result = await manager.update_all()
    assert not result.succeeded
    assert result.failed == 1
    assert manager._blocked_ips == {"203.0.113.7"}
    assert manager.last_update_epoch == 0
    assert marker not in caplog.text
    assert address not in caplog.text
    assert "ValueError" in caplog.text
