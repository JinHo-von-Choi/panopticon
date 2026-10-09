"""DNS 변경과 직접 내부 IP가 실제 소켓 연결 전에 거절되는지 확인한다."""

import asyncio
import socket

import aiohttp
from aiohttp.abc import AbstractResolver
import pytest

from netwatcher.utils.public_http import PublicTCPConnector, public_address, public_client_session


class ChangingResolver(AbstractResolver):
    def __init__(self, replies):
        self.replies = iter(replies)

    async def resolve(self, host, port=0, family=socket.AF_INET):
        return [{'hostname': host, 'host': address, 'port': port, 'family': socket.AF_INET,
                 'proto': 0, 'flags': 0} for address in next(self.replies)]

    async def close(self):
        return None


@pytest.mark.parametrize('address', ['127.0.0.1', '10.0.0.1', '169.254.169.254',
    '::1', '::ffff:127.0.0.1', '224.0.0.1', 'ff02::1', '2002:7f00:1::', 'bad-address'])
def test_internal_and_invalid_addresses_are_not_public(address):
    assert not public_address(address)


@pytest.mark.asyncio
async def test_changed_dns_is_rechecked_and_mixed_results_are_rejected():
    resolver = ChangingResolver([['8.8.8.8'], ['8.8.8.8', '127.0.0.1'], []])
    async with PublicTCPConnector(resolver=resolver, use_dns_cache=False) as connector:
        assert (await connector._resolve_host('webhook.example', 443))[0]['host'] == '8.8.8.8'
        with pytest.raises(OSError):
            await connector._resolve_host('webhook.example', 443)
        with pytest.raises(OSError):
            await connector._resolve_host('webhook.example', 443)


@pytest.mark.asyncio
async def test_real_loopback_http_connection_is_never_opened():
    accepted = []
    async def connected(reader, writer):
        accepted.append(True)
        writer.close()
        await writer.wait_closed()
    server = await asyncio.start_server(connected, '127.0.0.1', 0)
    try:
        port = server.sockets[0].getsockname()[1]
        async with public_client_session() as session:
            assert session.trust_env is False
            with pytest.raises(aiohttp.ClientConnectorError):
                await session.get(f'http://127.0.0.1:{port}', timeout=aiohttp.ClientTimeout(total=1))
        await asyncio.sleep(0)
        assert accepted == []
    finally:
        server.close()
        await server.wait_closed()
