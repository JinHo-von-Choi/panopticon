"""DB에 전달하는 SSL 설정의 실제 CA·호스트 검증."""

import asyncio
import ssl
import subprocess

import pytest

from netwatcher.storage.database import Database
from netwatcher.utils.config import Config


def database(mode, ca=""):
    return Database(Config({"postgresql": {
        "host": "localhost", "port": 5432, "database": "test", "username": "test",
        "password": "", "ssl_mode": mode, "ssl_ca_file": ca,
    }}))


@pytest.fixture
def certificate(tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
        "-keyout", str(key), "-out", str(cert),
    ], check=True, capture_output=True)
    return cert, key


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,host,trusted,allowed", [
    ("verify-full", "localhost", True, True),
    ("verify-full", "127.0.0.1", True, False),
    ("verify-ca", "127.0.0.1", True, True),
    ("verify-ca", "localhost", False, False),
    ("verify-full", "localhost", False, False),
    ("require", "127.0.0.1", False, True),
])
async def test_actual_certificate_handshake(certificate, mode, host, trusted, allowed):
    cert, key = certificate
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    async def handler(reader, writer):
        writer.write(b"verified")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
    server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=server_context)
    context = database(mode, str(cert) if trusted else "")._ssl
    port = server.sockets[0].getsockname()[1]
    try:
        if not allowed:
            with pytest.raises(ssl.SSLCertVerificationError):
                await asyncio.open_connection(host, port, ssl=context)
        else:
            reader, writer = await asyncio.open_connection(host, port, ssl=context)
            assert await reader.read() == b"verified"
            writer.close()
            await writer.wait_closed()
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_asyncpg_rejects_server_without_tls():
    import asyncpg
    attempts = []
    async def handler(reader, writer):
        attempts.append(await reader.readexactly(8))
        writer.write(b"N")  # PostgreSQL SSLRequest에 TLS 미지원 응답
        await writer.drain()
        writer.close()
        await writer.wait_closed()
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    try:
        with pytest.raises(ConnectionError):
            await asyncpg.connect(host="127.0.0.1", port=server.sockets[0].getsockname()[1],
                                  user="test", database="test", ssl=database("require")._ssl)
        assert len(attempts) == 1
        assert attempts[0] == b"\x00\x00\x00\x08\x04\xd2\x16\x2f"
    finally:
        server.close()
        await server.wait_closed()


def test_disable_and_invalid_modes():
    assert database("disable")._ssl is False
    with pytest.raises(ValueError):
        database("invalid")
