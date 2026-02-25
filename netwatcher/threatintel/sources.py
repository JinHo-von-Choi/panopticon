"""위협 피드 URL 정의 및 파서."""

from __future__ import annotations

import csv
import io
import json
import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import yaml

logger = logging.getLogger("netwatcher.threatintel.sources")


@dataclass
class FeedSource:
    """단일 위협 인텔리전스 피드 소스."""
    name: str
    url: str
    feed_type: str      # "ip", "domain", "url", "ja3" 중 하나
    format: str         # "text", "csv", "json", "hostfile" 중 하나
    comment_prefix: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FeedSource:
        """딕셔너리로부터 FeedSource 인스턴스를 생성한다."""
        return cls(
            name=data["name"],
            url=data["url"],
            feed_type=data.get("type", "ip"),
            format=data.get("format", "text"),
            comment_prefix=data.get("comment_prefix", "#"),
        )


def load_feed_sources(config_path: str) -> list[FeedSource]:
    """YAML 설정 파일에서 피드 소스를 로드한다."""
    try:
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
        feeds = data.get("feeds", [])
        return [FeedSource.from_dict(feed) for feed in feeds]
    except FileNotFoundError:
        logger.warning("Feed config not found: %s", config_path)
        return []
    except Exception:
        logger.exception("Failed to load feed sources")
        return []


def parse_feed(content: str, source: FeedSource) -> set[str]:
    """소스의 형식(format)과 유형(type)에 따라 피드 콘텐츠를 파싱한다.

    JA3 피드의 경우 JA3 MD5 해시 집합을 반환한다. JA3-악성코드 매핑도
    함께 얻으려면 parse_ja3_feed()를 직접 호출한다.
    """
    if source.feed_type == "ja3":
        ja3_set, _ = parse_ja3_feed(content, source.comment_prefix)
        return ja3_set
    if source.format == "csv":
        return _parse_csv_feed(content, source.feed_type)
    elif source.format == "json":
        return _parse_json_feed(content, source.feed_type)
    elif source.format == "hostfile":
        return _parse_hostfile_feed(content)
    else:
        return parse_text_feed(content, source.comment_prefix, source.feed_type)


def parse_text_feed(content: str, comment_prefix: str, feed_type: str) -> set[str]:
    """텍스트 기반 피드를 파싱한다 (줄당 하나의 항목)."""
    entries: set[str] = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(comment_prefix):
            continue

        if feed_type == "ip":
            # IP 추출 (포트 등 부가 정보가 포함될 수 있음)
            parts = line.split()
            ip_candidate = parts[0].split(":")[0].split(",")[0]
            # 기본 IP 유효성 검증
            octets = ip_candidate.split(".")
            if len(octets) == 4:
                try:
                    if all(0 <= int(o) <= 255 for o in octets):
                        entries.add(ip_candidate)
                except ValueError:
                    pass

        elif feed_type == "domain":
            # URL 또는 일반 도메인에서 도메인 추출
            if line.startswith("http"):
                try:
                    parsed = urlparse(line)
                    if parsed.hostname:
                        entries.add(parsed.hostname.lower())
                except Exception:
                    pass
            else:
                domain = line.split()[0].split("/")[0].lower()
                if "." in domain:
                    entries.add(domain)

        elif feed_type == "url":
            if line.startswith("http"):
                try:
                    parsed = urlparse(line)
                    if parsed.hostname:
                        entries.add(parsed.hostname.lower())
                except Exception:
                    pass

    return entries


def _parse_csv_feed(content: str, feed_type: str) -> set[str]:
    """CSV 피드를 파싱한다. 첫 번째 열에 지표(indicator)가 있어야 한다."""
    entries: set[str] = set()
    reader = csv.reader(io.StringIO(content))
    for row in reader:
        if not row:
            continue
        value = row[0].strip()
        if value.startswith("#") or not value:
            continue

        if feed_type == "ip":
            ip_candidate = value.split(":")[0]
            octets = ip_candidate.split(".")
            if len(octets) == 4:
                try:
                    if all(0 <= int(o) <= 255 for o in octets):
                        entries.add(ip_candidate)
                except ValueError:
                    pass
        elif feed_type in ("domain", "url"):
            if value.startswith("http"):
                try:
                    parsed = urlparse(value)
                    if parsed.hostname:
                        entries.add(parsed.hostname.lower())
                except Exception:
                    pass
            elif "." in value:
                entries.add(value.lower())

    return entries


def _parse_json_feed(content: str, feed_type: str) -> set[str]:
    """JSON 피드를 파싱한다. 'ioc' 또는 'indicator' 필드를 가진 객체 배열을 기대한다."""
    entries: set[str] = set()
    try:
        data = json.loads(content)
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            # 일반적인 JSON 구조 시도
            items = data.get("data", data.get("items", data.get("results", [])))
        else:
            return entries

        for item in items:
            if isinstance(item, str):
                value = item
            elif isinstance(item, dict):
                value = (
                    item.get("ioc")
                    or item.get("indicator")
                    or item.get("ip")
                    or item.get("domain")
                    or item.get("value")
                    or ""
                )
            else:
                continue

            if not value:
                continue

            if feed_type == "ip":
                octets = value.split(".")
                if len(octets) == 4:
                    try:
                        if all(0 <= int(o) <= 255 for o in octets):
                            entries.add(value)
                    except ValueError:
                        pass
            elif feed_type in ("domain", "url"):
                if "." in value:
                    entries.add(value.lower())

    except (json.JSONDecodeError, TypeError):
        logger.warning("Failed to parse JSON feed")

    return entries


def _parse_hostfile_feed(content: str) -> set[str]:
    """호스트파일 형식을 파싱한다 (예: '127.0.0.1 malware.com')."""
    entries: set[str] = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            domain = parts[1].lower()
            if "." in domain and domain not in ("localhost", "localhost.localdomain"):
                entries.add(domain)
    return entries


def parse_ja3_feed(
    content: str, comment_prefix: str = "#"
) -> tuple[set[str], dict[str, str]]:
    """SSLBL JA3 CSV 피드를 파싱한다.

    CSV 형식: ja3_md5,first_seen,last_seen,ja3,malware,listing_reason
    (JA3 MD5 해시 집합, JA3 MD5 -> 악성코드 이름 매핑 딕셔너리) 튜플을 반환한다.
    """
    ja3_set: set[str] = set()
    ja3_to_malware: dict[str, str] = {}

    reader = csv.reader(io.StringIO(content))
    for row in reader:
        if not row:
            continue
        first_col = row[0].strip()
        if not first_col or first_col.startswith(comment_prefix):
            continue

        ja3_md5 = first_col.lower()
        # 기본 MD5 유효성 검증: 32자리 16진수
        if len(ja3_md5) != 32:
            continue
        try:
            int(ja3_md5, 16)
        except ValueError:
            continue

        ja3_set.add(ja3_md5)

        # 4번째 열(인덱스 4) = 악성코드 이름
        if len(row) > 4 and row[4].strip():
            ja3_to_malware[ja3_md5] = row[4].strip()

    return ja3_set, ja3_to_malware
