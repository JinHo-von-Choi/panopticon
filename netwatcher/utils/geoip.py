"""IP 주소 지리적 위치 조회를 위한 GeoIP 유틸리티."""

from __future__ import annotations

import ipaddress
import logging
from functools import lru_cache
from typing import Any

logger = logging.getLogger("netwatcher.utils.geoip")

_geoip_reader = None


def _init_geoip() -> bool:
    """GeoIP2 리더 초기화를 시도한다. 성공 시 True를 반환한다."""
    global _geoip_reader
    if _geoip_reader is not None:
        return True
    try:
        import geoip2.database
        from pathlib import Path

        # 일반적인 GeoLite2 데이터베이스 위치
        db_paths = [
            Path("data/GeoLite2-City.mmdb"),
            Path("/usr/share/GeoIP/GeoLite2-City.mmdb"),
            Path("/var/lib/GeoIP/GeoLite2-City.mmdb"),
            Path.home() / ".local/share/GeoIP/GeoLite2-City.mmdb",
        ]

        for db_path in db_paths:
            if db_path.exists():
                _geoip_reader = geoip2.database.Reader(str(db_path))
                logger.info("GeoIP database loaded: %s", db_path)
                return True

        logger.info("GeoIP database not found, geolocation disabled")
        return False
    except ImportError:
        logger.info("geoip2 package not installed, geolocation disabled")
        return False
    except Exception:
        logger.warning("GeoIP initialization failed", exc_info=True)
        return False


def _is_private_ip(ip: str) -> bool:
    """IP가 사설/예약 주소인지 확인한다."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_reserved or addr.is_loopback
    except ValueError:
        return True


@lru_cache(maxsize=4096)
def lookup_ip(ip: str) -> dict[str, Any] | None:
    """IP 주소의 지리적 위치를 조회한다.

    국가, 도시, 위도, 경도, ASN 정보가 포함된 dict를 반환한다.
    사설 IP이거나 GeoIP를 사용할 수 없으면 None을 반환한다.
    """
    if _is_private_ip(ip):
        return None

    if not _init_geoip():
        return None

    try:
        response = _geoip_reader.city(ip)
        result: dict[str, Any] = {
            "country": response.country.iso_code,
            "country_name": response.country.name,
        }
        if response.city.name:
            result["city"] = response.city.name
        if response.location.latitude and response.location.longitude:
            result["latitude"] = response.location.latitude
            result["longitude"] = response.location.longitude
        return result
    except Exception:
        return None


def enrich_alert_metadata(
    metadata: dict[str, Any],
    source_ip: str | None,
    dest_ip: str | None,
) -> dict[str, Any]:
    """알림 메타데이터에 GeoIP 정보를 추가한다."""
    if source_ip:
        geo = lookup_ip(source_ip)
        if geo:
            metadata["geo_src"] = geo

    if dest_ip:
        geo = lookup_ip(dest_ip)
        if geo:
            metadata["geo_dst"] = geo

    return metadata
