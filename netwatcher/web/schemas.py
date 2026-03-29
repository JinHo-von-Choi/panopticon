"""API 요청/응답 Pydantic v2 모델.

엄격한 입력 검증을 제공한다. 기존 라우트에서 opt-in으로 사용 가능.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class LoginRequest(BaseModel):
    """JWT 로그인 요청."""
    model_config = ConfigDict(strict=True)

    username: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=1, max_length=200)


class WhitelistAddRequest(BaseModel):
    """화이트리스트 항목 추가 요청."""
    model_config = ConfigDict(strict=True)

    type: str = Field(..., pattern=r"^(ip|mac|domain|ip_range)$")
    value: str = Field(..., min_length=1, max_length=512)

    @field_validator("value")
    @classmethod
    def validate_value(cls, v: str, info: Any) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Value cannot be empty")
        return v


class BlockAddRequest(BaseModel):
    """차단 목록 항목 추가 요청."""
    model_config = ConfigDict(strict=True)

    value: str  = Field(..., min_length=1, max_length=512)
    notes: str  = Field(default="", max_length=2000)

    @field_validator("value")
    @classmethod
    def validate_value(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Value cannot be empty")
        # IP 또는 도메인 형식 중 하나여야 함
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            pass
        try:
            ipaddress.ip_network(v, strict=False)
            return v
        except ValueError:
            pass
        # 도메인 형식 검증
        domain_re = re.compile(
            r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
        )
        if domain_re.match(v):
            return v
        raise ValueError(f"Invalid IP address, CIDR, or domain: {v}")


class EngineConfigUpdate(BaseModel):
    """엔진 설정 업데이트 요청."""
    model_config = ConfigDict(strict=True)

    config: dict[str, Any] = Field(..., min_length=1)

    @field_validator("config")
    @classmethod
    def validate_config(cls, v: dict[str, Any]) -> dict[str, Any]:
        if not v:
            raise ValueError("Config cannot be empty")
        return v


class EventQuery(BaseModel):
    """이벤트 조회 쿼리 파라미터."""

    limit: int       = Field(default=50, ge=1, le=1000)
    offset: int      = Field(default=0, ge=0)
    engine: str | None    = Field(default=None, max_length=64)
    severity: str | None  = Field(default=None, pattern=r"^(INFO|WARNING|CRITICAL)$")
    source_ip: str | None = Field(default=None, max_length=45)

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, v: str | None) -> str | None:
        if v is None:
            return None
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v


class PortRange(BaseModel):
    """포트 범위 검증."""
    model_config = ConfigDict(strict=True)

    start: int = Field(..., ge=1, le=65535)
    end: int   = Field(..., ge=1, le=65535)

    @field_validator("end")
    @classmethod
    def validate_range(cls, v: int, info: Any) -> int:
        start = info.data.get("start")
        if start is not None and v < start:
            raise ValueError(f"End port ({v}) must be >= start port ({start})")
        return v
