"""BlockManager: iptables/nftables를 통한 OS 수준 반응형 IP 차단.

호스트 방화벽에 적용된 활성 차단 규칙 집합을 관리한다.
시간 기반 만료, 화이트리스트 우회, 리소스 고갈 방지를 위한
최대 차단 수 제한을 지원한다.

작성자: 최진호
작성일: 2026-02-20
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import math
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("netwatcher.response.blocker")


@dataclass
class BlockEntry:
    """단일 활성 IP 차단 규칙을 나타낸다."""

    ip: str
    reason: str
    duration: int  # seconds; 0 = permanent
    created_at: float = field(default_factory=time.time)
    alert_id: int | None = None
    active: bool = True

    @property
    def expires_at(self) -> float:
        """절대 만료 타임스탬프. duration이 0(영구)이면 ``inf``."""
        if self.duration == 0:
            return math.inf
        return self.created_at + self.duration

    @property
    def is_expired(self) -> bool:
        """차단이 지정 기간을 초과하면 True."""
        if self.duration == 0:
            return False
        return time.time() >= self.expires_at


def _validate_ip(ip: str) -> bool:
    """*ip*가 올바른 형식의 IPv4 또는 IPv6 주소인지 검증한다.

    ``ipaddress`` 표준 라이브러리 모듈을 사용하여 수동 정규식이 불필요하며
    사용자 입력이 사전 검증 없이 쉘 명령에 도달하지 않도록 한다.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _is_safe_to_block(ip: str) -> bool:
    """*ip*를 방화벽 DROP 규칙으로 추가해도 안전한 경우에만 True를 반환한다.

    broadcast, multicast, loopback, link-local, reserved, unspecified
    주소를 거부한다 -- 이들을 차단하면 네트워크 장애 또는 시스템 오작동이 발생한다.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    if addr.is_loopback:          # 127.0.0.0/8, ::1
        return False
    if addr.is_multicast:         # 224.0.0.0/4, ff00::/8
        return False
    if addr.is_reserved:          # 240.0.0.0/4, IETF reserved
        return False
    if addr.is_link_local:        # 169.254.0.0/16, fe80::/10
        return False
    if addr.is_unspecified:       # 0.0.0.0, ::
        return False

    # IPv4 브로드캐스트
    if isinstance(addr, ipaddress.IPv4Address):
        if ip == "255.255.255.255":
            return False

    return True


class BlockManager:
    """iptables / nftables / mock 백엔드를 통한 반응형 IP 차단을 관리한다.

    Parameters
    ----------
    enabled : bool
        마스터 스위치. ``False``이면 모든 block/unblock 호출이 무시된다.
    backend : str
        ``"iptables"``, ``"nftables"``, ``"mock"`` 중 하나.
    chain_name : str
        NetWatcher 규칙을 격리하기 위한 iptables 체인 이름.
    whitelist : list[str]
        절대 차단되어서는 안 되는 IP 목록.
    max_blocks : int
        동시 차단 상한 (리소스 고갈 방지).
    default_duration : int
        기본 차단 기간 초 단위 (0 = 영구).
    """

    SUPPORTED_BACKENDS = ("iptables", "nftables", "mock")

    def __init__(
        self,
        enabled: bool = True,
        backend: str = "iptables",
        chain_name: str = "NETWATCHER_BLOCK",
        whitelist: list[str] | None = None,
        max_blocks: int = 1000,
        default_duration: int = 3600,
    ) -> None:
        """BlockManager를 초기화한다. 백엔드, 체인 이름, 화이트리스트 등을 설정한다."""
        if backend not in self.SUPPORTED_BACKENDS:
            raise ValueError(
                f"Unsupported backend {backend!r}. "
                f"Must be one of {self.SUPPORTED_BACKENDS}"
            )

        self._enabled: bool          = enabled
        self._backend: str           = backend
        self._chain_name: str        = chain_name
        self._max_blocks: int        = max_blocks
        self._default_duration: int  = default_duration

        # 화이트리스트 IP 검증 및 저장
        self._whitelist: set[str] = set()
        for ip in (whitelist or []):
            if _validate_ip(ip):
                self._whitelist.add(ip)
            else:
                logger.warning("무효한 화이트리스트 IP 무시: %s", ip)

        # IP를 키로 하는 활성 차단 목록
        self._blocks: dict[str, BlockEntry] = {}

    # ------------------------------------------------------------------
    # 속성
    # ------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        """BlockManager가 차단을 능동적으로 적용하고 있는지 여부."""
        return self._enabled

    # ------------------------------------------------------------------
    # 공개 API
    # ------------------------------------------------------------------

    def is_blocked(self, ip: str) -> bool:
        """*ip*에 활성, 미만료 차단이 있으면 ``True``를 반환한다."""
        entry = self._blocks.get(ip)
        if entry is None or not entry.active:
            return False
        if entry.is_expired:
            return False
        return True

    async def block(
        self,
        ip: str,
        reason: str,
        duration: int | None = None,
        alert_id: int | None = None,
    ) -> bool:
        """*ip*에 대한 차단 규칙을 추가한다.

        차단이 성공적으로 적용되면 ``True``, 그렇지 않으면 ``False``를
        반환한다 (비활성화, 화이트리스트 해당, 검증 실패 등).
        """
        if not self._enabled:
            logger.debug("BlockManager 비활성화 상태 - 차단 무시: %s", ip)
            return False

        # IP 형식 검증 (보안: 인젝션 방지)
        if not _validate_ip(ip):
            logger.warning("무효한 IP 형식으로 차단 거부: %s", ip)
            return False

        # 특수 주소 거부 (broadcast, multicast, loopback 등)
        if not _is_safe_to_block(ip):
            logger.warning(
                "특수 주소(broadcast/multicast/loopback/link-local) 차단 거부: %s", ip,
            )
            return False

        # 화이트리스트 확인
        if ip in self._whitelist:
            logger.info("화이트리스트 IP 차단 거부: %s", ip)
            return False

        # 이미 차단 여부 확인
        if self.is_blocked(ip):
            logger.debug("이미 차단된 IP: %s", ip)
            return False

        # 최대 차단 수 제한
        active_count = sum(
            1 for e in self._blocks.values()
            if e.active and not e.is_expired
        )
        if active_count >= self._max_blocks:
            logger.warning(
                "최대 차단 수 도달 (%d) - 차단 거부: %s",
                self._max_blocks,
                ip,
            )
            return False

        effective_duration = duration if duration is not None else self._default_duration

        entry = BlockEntry(
            ip=ip,
            reason=reason,
            duration=effective_duration,
            alert_id=alert_id,
        )

        # 방화벽 규칙 적용 (mock 백엔드는 건너뜀)
        if self._backend != "mock":
            success = await self._apply_block(ip)
            if not success:
                logger.error("방화벽 차단 규칙 적용 실패: %s", ip)
                return False

        self._blocks[ip] = entry
        logger.info(
            "IP 차단 적용: %s (사유: %s, 기간: %s초, alert_id: %s)",
            ip,
            reason,
            effective_duration or "영구",
            alert_id,
        )
        return True

    async def unblock(self, ip: str) -> bool:
        """*ip*에 대한 차단 규칙을 제거한다.

        차단이 성공적으로 제거되면 ``True``를 반환한다.
        """
        if ip not in self._blocks:
            logger.debug("차단 목록에 없는 IP 해제 요청: %s", ip)
            return False

        # 방화벽 규칙 제거 (mock 백엔드는 건너뜀)
        if self._backend != "mock":
            success = await self._remove_block(ip)
            if not success:
                logger.error("방화벽 차단 규칙 제거 실패: %s", ip)
                return False

        entry = self._blocks.pop(ip)
        logger.info("IP 차단 해제: %s (원래 사유: %s)", ip, entry.reason)
        return True

    def cleanup_expired(self) -> list[str]:
        """만료된 모든 차단을 제거하고 해당 IP를 반환한다.

        참고: 이 메서드는 ``_remove_block()``을 호출하지 않는다. 만료된 규칙은
        호출자를 통해 비동기적으로 iptables에서 정리되어야 한다.
        mock 백엔드에서는 해당하지 않는다.
        """
        expired_ips: list[str] = []
        for ip, entry in list(self._blocks.items()):
            if entry.is_expired:
                expired_ips.append(ip)
                del self._blocks[ip]
                logger.info("만료된 차단 정리: %s", ip)
        return expired_ips

    def get_active_blocks(self) -> list[dict[str, Any]]:
        """모든 활성(미만료) 차단의 JSON 직렬화 가능 목록을 반환한다."""
        result: list[dict[str, Any]] = []
        for ip, entry in self._blocks.items():
            if not entry.active or entry.is_expired:
                continue
            result.append({
                "ip": entry.ip,
                "reason": entry.reason,
                "duration": entry.duration,
                "created_at": entry.created_at,
                "expires_at": entry.expires_at if entry.duration > 0 else None,
                "alert_id": entry.alert_id,
            })
        return result

    # ------------------------------------------------------------------
    # 방화벽 백엔드 헬퍼
    # ------------------------------------------------------------------

    async def _apply_block(self, ip: str) -> bool:
        """*ip*를 차단하는 방화벽 명령을 실행한다.

        ``asyncio.create_subprocess_exec``를 사용하여 쉘 해석이
        발생하지 않도록 한다 (명령 인젝션 방지).
        """
        if self._backend == "iptables":
            return await self._exec_iptables("-A", self._chain_name, "-s", ip, "-j", "DROP")
        elif self._backend == "nftables":
            return await self._exec_nftables_add(ip)
        return False

    async def _remove_block(self, ip: str) -> bool:
        """*ip* 차단을 해제하는 방화벽 명령을 실행한다."""
        if self._backend == "iptables":
            return await self._exec_iptables("-D", self._chain_name, "-s", ip, "-j", "DROP")
        elif self._backend == "nftables":
            return await self._exec_nftables_delete(ip)
        return False

    async def init_chain(self) -> None:
        """전용 체인을 생성하고 INPUT에서 점프 규칙을 삽입한다.

        멱등: 체인이 이미 존재하면 조용히 성공한다.
        iptables 백엔드에만 적용된다.
        """
        if self._backend == "mock":
            logger.debug("Mock 백엔드 - 체인 초기화 생략")
            return

        if self._backend == "iptables":
            # 체인 생성 (이미 존재하면 오류 무시)
            await self._exec_iptables("-N", self._chain_name, ignore_error=True)
            # 아직 없으면 INPUT에서 점프 규칙 삽입 (위치 1)
            # 중복 방지를 위해 먼저 확인
            check_ok = await self._exec_iptables(
                "-C", "INPUT", "-j", self._chain_name, ignore_error=True
            )
            if not check_ok:
                await self._exec_iptables("-I", "INPUT", "1", "-j", self._chain_name)
            logger.info("iptables 체인 초기화 완료: %s", self._chain_name)

        elif self._backend == "nftables":
            # nftables 체인 초기화 (향후 구현 예정)
            logger.warning("nftables 체인 초기화는 아직 미구현")

    # ------------------------------------------------------------------
    # 저수준 명령 실행
    # ------------------------------------------------------------------

    async def _exec_iptables(self, *args: str, ignore_error: bool = False) -> bool:
        """주어진 인수로 iptables 명령을 실행한다.

        모든 인수가 ``create_subprocess_exec``에 위치 인수로 전달되므로
        쉘 확장이 발생하지 않으며 IP 값이 인젝션될 수 없다.
        """
        cmd = ("iptables", *args)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                if not ignore_error:
                    logger.error(
                        "iptables 명령 실패 (rc=%d): %s | stderr: %s",
                        proc.returncode,
                        " ".join(cmd),
                        stderr.decode().strip(),
                    )
                return False
            return True
        except FileNotFoundError:
            logger.error("iptables 바이너리를 찾을 수 없음")
            return False
        except Exception:
            logger.exception("iptables 명령 실행 중 예외 발생: %s", " ".join(cmd))
            return False

    async def _exec_nftables_add(self, ip: str) -> bool:
        """nftables 차단 규칙을 추가한다 (향후 구현을 위한 플레이스홀더)."""
        logger.warning("nftables add 미구현: %s", ip)
        return False

    async def _exec_nftables_delete(self, ip: str) -> bool:
        """nftables 차단 규칙을 삭제한다 (향후 구현을 위한 플레이스홀더)."""
        logger.warning("nftables delete 미구현: %s", ip)
        return False
