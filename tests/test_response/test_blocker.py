"""Tests for BlockManager and BlockEntry (mock backend only)."""

from __future__ import annotations

import math
import time

import pytest
import pytest_asyncio

from netwatcher.response.blocker import BlockEntry, BlockManager, _validate_ip


# =====================================================================
# BlockEntry unit tests
# =====================================================================

class TestBlockEntry:
    def test_expires_at_finite(self):
        """duration > 0 인 경우 expires_at = created_at + duration."""
        entry = BlockEntry(ip="10.0.0.1", reason="test", duration=300, created_at=1000.0)
        assert entry.expires_at == 1300.0

    def test_expires_at_permanent(self):
        """duration == 0 인 경우 expires_at 은 inf."""
        entry = BlockEntry(ip="10.0.0.1", reason="test", duration=0, created_at=1000.0)
        assert entry.expires_at == math.inf

    def test_is_expired_false_within_window(self):
        """아직 만료되지 않은 항목."""
        entry = BlockEntry(
            ip="10.0.0.1", reason="test", duration=9999,
            created_at=time.time(),
        )
        assert entry.is_expired is False

    def test_is_expired_true(self):
        """과거에 생성된 짧은 duration 항목은 만료 상태."""
        entry = BlockEntry(
            ip="10.0.0.1", reason="test", duration=1,
            created_at=time.time() - 10,
        )
        assert entry.is_expired is True

    def test_is_expired_permanent_never_expires(self):
        """영구 차단(duration=0)은 절대 만료되지 않음."""
        entry = BlockEntry(
            ip="10.0.0.1", reason="test", duration=0,
            created_at=1.0,  # 아주 오래 전
        )
        assert entry.is_expired is False

    def test_default_values(self):
        """기본값 검증: created_at 자동 할당, active=True, alert_id=None."""
        before = time.time()
        entry = BlockEntry(ip="10.0.0.1", reason="test", duration=60)
        after = time.time()

        assert before <= entry.created_at <= after
        assert entry.active is True
        assert entry.alert_id is None

    def test_alert_id_preserved(self):
        """alert_id 가 올바르게 저장됨."""
        entry = BlockEntry(ip="10.0.0.1", reason="alert", duration=60, alert_id=42)
        assert entry.alert_id == 42


# =====================================================================
# _validate_ip unit tests
# =====================================================================

class TestValidateIP:
    def test_valid_ipv4(self):
        assert _validate_ip("192.168.1.1") is True

    def test_valid_ipv6(self):
        assert _validate_ip("::1") is True
        assert _validate_ip("2001:db8::1") is True

    def test_invalid_ip(self):
        assert _validate_ip("not-an-ip") is False

    def test_ip_with_cidr_rejected(self):
        """CIDR 표기는 단일 IP가 아니므로 거부."""
        assert _validate_ip("192.168.1.0/24") is False

    def test_empty_string(self):
        assert _validate_ip("") is False

    def test_command_injection_attempt(self):
        """셸 주입 시도 문자열은 반드시 거부."""
        assert _validate_ip("10.0.0.1; rm -rf /") is False
        assert _validate_ip("$(whoami)") is False
        assert _validate_ip("10.0.0.1 && echo pwned") is False


# =====================================================================
# BlockManager unit tests (mock backend)
# =====================================================================

class TestBlockManager:
    def setup_method(self):
        self.mgr = BlockManager(
            enabled=True,
            backend="mock",
            chain_name="TEST_CHAIN",
            whitelist=["192.168.1.1", "10.0.0.254"],
            max_blocks=5,
            default_duration=3600,
        )

    # ---- basic block / unblock ----

    @pytest.mark.asyncio
    async def test_block_success(self):
        result = await self.mgr.block("10.0.0.1", "port scan detected")
        assert result is True
        assert self.mgr.is_blocked("10.0.0.1")

    @pytest.mark.asyncio
    async def test_block_returns_entry_in_active_blocks(self):
        await self.mgr.block("10.0.0.1", "test reason", alert_id=7)
        blocks = self.mgr.get_active_blocks()
        assert len(blocks) == 1
        assert blocks[0]["ip"] == "10.0.0.1"
        assert blocks[0]["reason"] == "test reason"
        assert blocks[0]["alert_id"] == 7

    @pytest.mark.asyncio
    async def test_unblock_success(self):
        await self.mgr.block("10.0.0.1", "test")
        assert self.mgr.is_blocked("10.0.0.1")

        result = await self.mgr.unblock("10.0.0.1")
        assert result is True
        assert not self.mgr.is_blocked("10.0.0.1")

    @pytest.mark.asyncio
    async def test_unblock_nonexistent_ip(self):
        result = await self.mgr.unblock("99.99.99.99")
        assert result is False

    # ---- disabled manager ----

    @pytest.mark.asyncio
    async def test_block_when_disabled(self):
        mgr = BlockManager(enabled=False, backend="mock")
        result = await mgr.block("10.0.0.1", "test")
        assert result is False
        assert not mgr.is_blocked("10.0.0.1")

    # ---- whitelist ----

    @pytest.mark.asyncio
    async def test_whitelist_blocks_rejected(self):
        result = await self.mgr.block("192.168.1.1", "should be rejected")
        assert result is False
        assert not self.mgr.is_blocked("192.168.1.1")

    @pytest.mark.asyncio
    async def test_whitelist_second_ip(self):
        result = await self.mgr.block("10.0.0.254", "also rejected")
        assert result is False

    # ---- invalid IP ----

    @pytest.mark.asyncio
    async def test_block_invalid_ip_rejected(self):
        result = await self.mgr.block("not-an-ip", "test")
        assert result is False

    @pytest.mark.asyncio
    async def test_block_injection_attempt_rejected(self):
        result = await self.mgr.block("10.0.0.1; rm -rf /", "injection")
        assert result is False

    # ---- duplicate block ----

    @pytest.mark.asyncio
    async def test_duplicate_block_rejected(self):
        await self.mgr.block("10.0.0.1", "first")
        result = await self.mgr.block("10.0.0.1", "second")
        assert result is False

    # ---- max blocks ----

    @pytest.mark.asyncio
    async def test_max_blocks_enforced(self):
        for i in range(5):
            ok = await self.mgr.block(f"10.0.0.{i + 1}", f"reason {i}")
            assert ok is True

        # 6th block should fail
        result = await self.mgr.block("10.0.0.100", "overflow")
        assert result is False

    @pytest.mark.asyncio
    async def test_max_blocks_allows_after_unblock(self):
        """해제 후 다시 차단 가능."""
        for i in range(5):
            await self.mgr.block(f"10.0.0.{i + 1}", "fill")

        await self.mgr.unblock("10.0.0.1")
        result = await self.mgr.block("10.0.0.100", "new block")
        assert result is True

    # ---- custom duration ----

    @pytest.mark.asyncio
    async def test_custom_duration(self):
        await self.mgr.block("10.0.0.1", "test", duration=120)
        blocks = self.mgr.get_active_blocks()
        assert blocks[0]["duration"] == 120

    @pytest.mark.asyncio
    async def test_permanent_block(self):
        await self.mgr.block("10.0.0.1", "permanent", duration=0)
        blocks = self.mgr.get_active_blocks()
        assert blocks[0]["duration"] == 0
        assert blocks[0]["expires_at"] is None

    # ---- expiry ----

    @pytest.mark.asyncio
    async def test_expired_block_not_counted_as_blocked(self):
        """만료된 차단은 is_blocked() 에서 False 반환."""
        await self.mgr.block("10.0.0.1", "test", duration=1)
        # 직접 created_at 조작으로 만료 시뮬레이션
        self.mgr._blocks["10.0.0.1"].created_at = time.time() - 10
        assert not self.mgr.is_blocked("10.0.0.1")

    @pytest.mark.asyncio
    async def test_cleanup_expired(self):
        await self.mgr.block("10.0.0.1", "short", duration=1)
        await self.mgr.block("10.0.0.2", "permanent", duration=0)
        await self.mgr.block("10.0.0.3", "short", duration=1)

        # 만료 시뮬레이션
        self.mgr._blocks["10.0.0.1"].created_at = time.time() - 10
        self.mgr._blocks["10.0.0.3"].created_at = time.time() - 10

        expired = self.mgr.cleanup_expired()
        assert sorted(expired) == ["10.0.0.1", "10.0.0.3"]
        assert "10.0.0.2" in self.mgr._blocks  # 영구 차단은 유지
        assert "10.0.0.1" not in self.mgr._blocks
        assert "10.0.0.3" not in self.mgr._blocks

    @pytest.mark.asyncio
    async def test_cleanup_empty_when_no_expired(self):
        await self.mgr.block("10.0.0.1", "test", duration=9999)
        expired = self.mgr.cleanup_expired()
        assert expired == []

    @pytest.mark.asyncio
    async def test_expired_blocks_dont_count_toward_max(self):
        """만료된 차단은 max_blocks 카운트에 포함되지 않음."""
        for i in range(5):
            await self.mgr.block(f"10.0.0.{i + 1}", "fill", duration=1)

        # 모두 만료 시뮬레이션
        for entry in self.mgr._blocks.values():
            entry.created_at = time.time() - 10

        # max_blocks에 도달했지만 모두 만료 -> 새 차단 가능
        result = await self.mgr.block("10.0.0.100", "after expiry")
        assert result is True

    # ---- get_active_blocks ----

    @pytest.mark.asyncio
    async def test_get_active_blocks_excludes_expired(self):
        await self.mgr.block("10.0.0.1", "expired", duration=1)
        await self.mgr.block("10.0.0.2", "active", duration=9999)

        self.mgr._blocks["10.0.0.1"].created_at = time.time() - 10

        blocks = self.mgr.get_active_blocks()
        assert len(blocks) == 1
        assert blocks[0]["ip"] == "10.0.0.2"

    @pytest.mark.asyncio
    async def test_get_active_blocks_empty(self):
        assert self.mgr.get_active_blocks() == []

    # ---- is_blocked edge cases ----

    def test_is_blocked_unknown_ip(self):
        assert not self.mgr.is_blocked("99.99.99.99")

    @pytest.mark.asyncio
    async def test_is_blocked_after_unblock(self):
        await self.mgr.block("10.0.0.1", "test")
        await self.mgr.unblock("10.0.0.1")
        assert not self.mgr.is_blocked("10.0.0.1")

    # ---- enabled property ----

    def test_enabled_property(self):
        mgr = BlockManager(enabled=True, backend="mock")
        assert mgr.enabled is True

        mgr2 = BlockManager(enabled=False, backend="mock")
        assert mgr2.enabled is False

    # ---- init_chain mock ----

    @pytest.mark.asyncio
    async def test_init_chain_mock_no_error(self):
        """Mock 백엔드에서 init_chain 은 에러 없이 완료."""
        await self.mgr.init_chain()

    # ---- constructor validation ----

    def test_unsupported_backend_raises(self):
        with pytest.raises(ValueError, match="Unsupported backend"):
            BlockManager(backend="firewalld")

    def test_invalid_whitelist_ip_ignored(self):
        """무효한 화이트리스트 IP는 조용히 무시."""
        mgr = BlockManager(
            backend="mock",
            whitelist=["192.168.1.1", "bad-ip", "10.0.0.1"],
        )
        assert "192.168.1.1" in mgr._whitelist
        assert "10.0.0.1" in mgr._whitelist
        assert "bad-ip" not in mgr._whitelist

    def test_default_whitelist_empty(self):
        mgr = BlockManager(backend="mock")
        assert mgr._whitelist == set()

    # ---- IPv6 support ----

    @pytest.mark.asyncio
    async def test_block_ipv6(self):
        result = await self.mgr.block("2001:db8::1", "ipv6 test")
        assert result is True
        assert self.mgr.is_blocked("2001:db8::1")

    @pytest.mark.asyncio
    async def test_block_ipv6_loopback(self):
        mgr = BlockManager(backend="mock", whitelist=["::1"])
        result = await mgr.block("::1", "loopback")
        assert result is False

    # ---- block then re-block after unblock ----

    @pytest.mark.asyncio
    async def test_reblock_after_unblock(self):
        """해제 후 같은 IP를 다시 차단할 수 있음."""
        await self.mgr.block("10.0.0.1", "first")
        await self.mgr.unblock("10.0.0.1")
        result = await self.mgr.block("10.0.0.1", "second")
        assert result is True
        assert self.mgr.is_blocked("10.0.0.1")

    # ---- block with default duration ----

    @pytest.mark.asyncio
    async def test_default_duration_applied(self):
        await self.mgr.block("10.0.0.1", "test")
        blocks = self.mgr.get_active_blocks()
        assert blocks[0]["duration"] == 3600  # default_duration
