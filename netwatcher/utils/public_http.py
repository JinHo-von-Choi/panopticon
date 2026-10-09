"""외부 webhook·피드 연결의 실제 DNS 결과를 확인한다."""

from __future__ import annotations

import ipaddress

import aiohttp


def public_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if not address.is_global or address.is_multicast or getattr(address, 'scope_id', None):
        return False
    if isinstance(address, ipaddress.IPv6Address):
        embedded = address.ipv4_mapped or address.sixtofour
        if embedded is not None and not public_address(str(embedded)):
            return False
        if address.teredo and not all(public_address(str(part)) for part in address.teredo):
            return False
    return True


class PublicTCPConnector(aiohttp.TCPConnector):
    """고정된 aiohttp 버전의 연결 단계에서 literal IP와 DNS 결과를 함께 검사한다."""

    async def _resolve_host(self, host: str, port: int, traces=None):
        addresses = await super()._resolve_host(host, port, traces)
        if not addresses or any(not public_address(item['host']) for item in addresses):
            raise OSError('Outbound destination is not a public address')
        return addresses


def public_client_session() -> aiohttp.ClientSession:
    # 연결에 쓰는 동일한 DNS 결과를 검사한다. 별도 선행 DNS 조회에 의존하지 않는다.
    return aiohttp.ClientSession(connector=PublicTCPConnector(use_dns_cache=False), trust_env=False)
