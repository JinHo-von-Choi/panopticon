"""네트워크 인터페이스 탐색 헬퍼."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse

from scapy.all import conf, get_if_list

logger = logging.getLogger("netwatcher.utils.network")

# IEEE OUI 프리픽스 -> 벤더명 (주요 항목; 런타임에 캐시로 확장)
_OUI_DB: dict[str, str] = {
    "00:50:56": "VMware", "00:0c:29": "VMware", "00:1c:42": "Parallels",
    "08:00:27": "VirtualBox", "0a:00:27": "VirtualBox",
    "00:15:5d": "Hyper-V",
    "dc:a6:32": "Raspberry Pi", "b8:27:eb": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    "aa:bb:cc": "Test/Private",
    "00:1a:79": "Dell", "f8:bc:12": "Dell", "24:6e:96": "Dell",
    "3c:22:fb": "Apple", "a4:83:e7": "Apple", "f0:18:98": "Apple",
    "ac:de:48": "Apple", "00:1b:63": "Apple", "00:03:93": "Apple",
    "00:1e:c2": "Apple", "00:25:00": "Apple", "14:10:9f": "Apple",
    "28:cf:da": "Apple", "34:36:3b": "Apple", "40:b3:95": "Apple",
    "54:26:96": "Apple", "68:5b:35": "Apple", "78:31:c1": "Apple",
    "88:66:a5": "Apple", "98:01:a7": "Apple", "a8:86:dd": "Apple",
    "bc:52:b7": "Apple", "c8:69:cd": "Apple", "d0:03:4b": "Apple",
    "e0:b5:2d": "Apple", "f0:d1:a9": "Apple",
    "00:50:b6": "Apple",
    "30:b5:c2": "TP-Link", "50:c7:bf": "TP-Link", "60:32:b1": "TP-Link",
    "c0:25:e9": "TP-Link", "ec:08:6b": "TP-Link",
    "00:24:b2": "Netgear", "20:0c:c8": "Netgear", "44:94:fc": "Netgear",
    "a4:2b:8c": "Netgear", "e0:91:f5": "Netgear",
    "00:18:0a": "Cisco", "00:1b:d4": "Cisco", "00:26:0b": "Cisco",
    "58:97:1e": "Cisco", "f0:29:29": "Cisco",
    "00:0e:c6": "ASUS", "1c:87:2c": "ASUS", "2c:56:dc": "ASUS",
    "50:46:5d": "ASUS", "ac:22:0b": "ASUS",
    "00:e0:4c": "Realtek", "00:1f:1f": "Edimax",
    "b0:be:76": "TP-Link",
    "00:1a:a0": "Dell", "b0:83:fe": "Dell",
    "00:21:5a": "HP", "3c:d9:2b": "HP", "94:57:a5": "HP",
    "b4:b5:2f": "HP", "ec:b1:d7": "HP",
    "00:0d:3a": "Microsoft", "00:12:5a": "Microsoft", "00:17:fa": "Microsoft",
    "28:18:78": "Microsoft", "7c:1e:52": "Microsoft",
    "00:04:4b": "Nvidia", "04:cf:4b": "Nvidia",
    "34:97:f6": "ASUS", "04:d4:c4": "ASUS",
    "00:16:3e": "Xen",
    "52:54:00": "QEMU/KVM",
    "a0:36:9f": "Intel", "3c:97:0e": "Intel", "68:05:ca": "Intel",
    "8c:ec:4b": "Intel", "f8:63:3f": "Intel",
    "00:25:90": "Super Micro",
    "d8:3a:dd": "Raspberry Pi",
    "7c:10:c9": "Apple",
    "b4:69:21": "Intel",
    "e8:6a:64": "TP-Link",
    "9c:a5:25": "Apple",
    "20:47:da": "Dell",
    "48:2c:a0": "Xiaomi", "64:cc:2e": "Xiaomi", "78:11:dc": "Xiaomi",
    "28:6c:07": "Xiaomi", "f8:a4:5f": "Xiaomi",
    "cc:50:e3": "LG", "00:e0:91": "LG",
    "00:1c:b3": "Apple", "10:dd:b1": "Apple",
    "8c:85:90": "Apple", "04:0c:ce": "Apple",
    "00:1e:65": "Intel", "a0:88:b4": "Intel",
    "b8:ae:ed": "Samsung", "00:21:19": "Samsung", "08:37:3d": "Samsung",
    "18:22:7e": "Samsung", "30:96:fb": "Samsung", "50:01:bb": "Samsung",
    "84:25:19": "Samsung", "94:35:0a": "Samsung", "a8:06:00": "Samsung",
    "c0:bd:d1": "Samsung", "e4:7c:f9": "Samsung", "f0:25:b7": "Samsung",
    "78:47:1d": "Samsung", "6c:c7:ec": "Samsung",
    "88:36:6c": "Google", "f4:f5:d8": "Google", "54:60:09": "Google",
    "a4:77:33": "Google",
}


@lru_cache(maxsize=4096)
def mac_vendor_lookup(mac: str) -> str:
    """OUI 프리픽스로 MAC 벤더를 조회한다. 벤더명 또는 'Unknown'을 반환한다."""
    if not mac or len(mac) < 8:
        return "Unknown"
    prefix = mac[:8].lower()
    return _OUI_DB.get(prefix, "Unknown")


@lru_cache(maxsize=2048)
def reverse_dns(ip: str) -> str | None:
    """동기 역방향 DNS 조회. 호스트명 또는 None을 반환한다. 캐시됨.

    참고: 하위 호환성을 위해 유지되는 동기 버전이다.
    논블로킹 해석에는 AsyncDNSResolver 사용을 권장한다.
    """
    if not ip or ip.startswith("0.") or ip == "255.255.255.255":
        return None
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


class AsyncDNSResolver:
    """이벤트 루프를 차단하지 않고 백그라운드에서 IP를 해석하는
    비동기 DNS 리졸버.

    IP는 해석 큐에 추가되고 run_in_executor를 통해 해석된다.
    결과는 캐시되어 조회에 사용 가능하다.
    """

    def __init__(self, max_cache: int = 4096, max_pending: int = 500) -> None:
        self._cache: dict[str, str | None] = {}
        self._pending: set[str] = set()
        self._max_cache = max_cache
        self._max_pending = max_pending
        self._task: asyncio.Task | None = None
        self._queue: asyncio.Queue[str] = asyncio.Queue(maxsize=1000)

    def lookup(self, ip: str) -> str | None:
        """논블로킹 캐시 조회. 캐시된 호스트명 또는 None을 반환한다.

        아직 해석되지 않은 IP는 비동기 해석 큐에 추가한다.
        """
        if ip in self._cache:
            return self._cache[ip]

        # 비동기 해석 큐에 추가 (논블로킹)
        if ip not in self._pending and len(self._pending) < self._max_pending:
            self._pending.add(ip)
            try:
                self._queue.put_nowait(ip)
            except asyncio.QueueFull:
                self._pending.discard(ip)

        return None

    async def start(self) -> None:
        """백그라운드 해석 태스크를 시작한다."""
        self._task = asyncio.create_task(self._resolver_loop())

    async def stop(self) -> None:
        """백그라운드 해석 태스크를 중지한다."""
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _resolver_loop(self) -> None:
        """큐에 쌓인 IP를 해석하는 백그라운드 루프."""
        loop = asyncio.get_running_loop()
        while True:
            ip = await self._queue.get()
            try:
                hostname = await loop.run_in_executor(
                    None, self._resolve_sync, ip
                )
                # 캐시가 가득 차면 가장 오래된 항목 제거
                if len(self._cache) >= self._max_cache:
                    # 전체 항목의 10%를 제거
                    keys = list(self._cache.keys())
                    for k in keys[:len(keys) // 10]:
                        del self._cache[k]
                self._cache[ip] = hostname
            except Exception:
                self._cache[ip] = None
            finally:
                self._pending.discard(ip)

    @staticmethod
    def _resolve_sync(ip: str) -> str | None:
        """동기 DNS 해석 (executor 스레드에서 실행)."""
        if not ip or ip.startswith("0.") or ip == "255.255.255.255":
            return None
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return None


def get_default_interface() -> str:
    """스니핑에 가장 적합한 네트워크 인터페이스를 반환한다."""
    try:
        iface = conf.iface
        if iface and str(iface) not in ("lo", "localhost"):
            return str(iface)
    except Exception:
        pass

    for iface in get_if_list():
        if iface not in ("lo", "localhost"):
            return iface

    return "eth0"


def get_local_ip() -> str:
    """현재 머신의 로컬 IP 주소를 반환한다."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def get_local_mac(iface: str | None = None) -> str | None:
    """네트워크 인터페이스의 MAC 주소를 반환한다."""
    try:
        from scapy.all import get_if_hwaddr
        return get_if_hwaddr(iface or get_default_interface())
    except Exception:
        return None


# ---------------------------------------------------------------------------
# SSRF 방어
# ---------------------------------------------------------------------------

def validate_outbound_url(url: str) -> str | None:
    """아웃바운드 HTTP 요청에 안전한 URL인지 검증한다 (SSRF 방어).

    안전하면 URL을 그대로 반환하고, 내부/사설 주소를 대상으로 하면
    ``None``을 반환한다. 리터럴 호스트명과 DNS 해석 결과 모두를
    내부 주소 범위와 대조 검사한다.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return None

    if parsed.scheme not in ("http", "https"):
        return None

    hostname = parsed.hostname
    if not hostname:
        return None

    # IP 리터럴 직접 검사
    try:
        addr = ipaddress.ip_address(hostname)
        if _is_internal_addr(addr):
            logger.warning("SSRF 차단: 내부 주소 대상 URL 거부: %s", url)
            return None
        return url
    except ValueError:
        pass  # 호스트명이 도메인 이름이므로 DNS 해석 진행

    # DNS 해석 결과 검사
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, _, _, _, sockaddr in infos:
            ip_str = sockaddr[0]
            try:
                addr = ipaddress.ip_address(ip_str)
                if _is_internal_addr(addr):
                    logger.warning(
                        "SSRF 차단: %s이(가) 내부 주소 %s로 해석됨", hostname, ip_str,
                    )
                    return None
            except ValueError:
                continue
    except socket.gaierror:
        # DNS 해석 실패 -- 허용 (HTTP 요청 자체에서 실패할 것임)
        pass

    return url


def _is_internal_addr(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """사설, 루프백, 링크-로컬, 또는 예약된 주소이면 True를 반환한다."""
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_unspecified
    )
