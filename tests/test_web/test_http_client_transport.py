"""고정된 aiohttp의 실제 연결·시간 제한·스트림·프록시·TLS 동작."""

import asyncio
import ssl
import subprocess

import aiohttp
from aiohttp import web
import pytest
import pytest_asyncio


@pytest_asyncio.fixture
async def http_endpoint():
    app = web.Application()
    async def handler(request):
        if request.path == "/slow":
            await asyncio.sleep(0.2)
        if request.path == "/stream":
            response = web.StreamResponse()
            await response.prepare(request)
            await response.write(b"first\n")
            await response.write(b"second\n")
            await response.write_eof()
            return response
        return web.json_response({"path": request.raw_path, "method": request.method})
    app.router.add_route("*", "/{tail:.*}", handler)
    runner = web.AppRunner(app, shutdown_timeout=0.3)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    address = runner.addresses[0]
    try:
        yield f"http://127.0.0.1:{address[1]}"
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_reusable_connection_stream_and_session_shutdown(http_endpoint):
    session = aiohttp.ClientSession()
    connector = session.connector
    async with session:
        async with session.get(http_endpoint + "/stream") as response:
            assert await response.content.readline() == b"first\n"
            assert await response.read() == b"second\n"
        async with session.post(http_endpoint + "/notify", json={"message": "test"}) as response:
            assert response.status == 200
            assert (await response.json())["method"] == "POST"
    assert session.closed
    assert connector.closed


@pytest.mark.asyncio
async def test_timeout_releases_connection_for_next_request(http_endpoint):
    async with aiohttp.ClientSession() as session:
        with pytest.raises(TimeoutError):
            await session.get(http_endpoint + "/slow", timeout=aiohttp.ClientTimeout(total=0.02))
        async with session.get(http_endpoint + "/ready") as response:
            assert response.status == 200


@pytest.mark.asyncio
async def test_http_proxy_receives_original_destination(http_endpoint):
    async with aiohttp.ClientSession() as session:
        async with session.get("http://example.invalid/feed", proxy=http_endpoint) as response:
            assert response.status == 200
            assert (await response.json())["path"] == "http://example.invalid/feed"


@pytest.mark.asyncio
async def test_tls_rejects_unknown_certificate_and_accepts_explicit_ca(tmp_path):
    cert = tmp_path / "server.crt"
    key = tmp_path / "server.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-days", "1", "-subj", "/CN=localhost", "-addext",
                    "subjectAltName=DNS:localhost,IP:127.0.0.1", "-keyout", str(key),
                    "-out", str(cert)], check=True, capture_output=True)
    key.chmod(0o600)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    app = web.Application()
    async def ready(request):
        return web.Response(text="ready")
    app.router.add_get("/", ready)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=context)
    await site.start()
    url = f"https://127.0.0.1:{runner.addresses[0][1]}/"
    try:
        async with aiohttp.ClientSession() as session:
            with pytest.raises(aiohttp.ClientConnectorCertificateError):
                await session.get(url)
            trusted = ssl.create_default_context(cafile=str(cert))
            async with session.get(url, ssl=trusted) as response:
                assert await response.text() == "ready"
    finally:
        await runner.cleanup()
