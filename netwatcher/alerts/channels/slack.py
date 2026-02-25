"""수신 webhook을 통한 Slack 알림 채널."""

from __future__ import annotations

import logging
from typing import Any

import aiohttp

from netwatcher.alerts.channels.base import NotificationChannel
from netwatcher.detection.models import Alert
from netwatcher.utils.network import validate_outbound_url

logger = logging.getLogger("netwatcher.alerts.channels.slack")


class SlackChannel(NotificationChannel):
    name = "slack"

    def __init__(self, config: dict[str, Any]) -> None:
        """Slack webhook URL과 대시보드 링크를 설정에서 로드한다."""
        super().__init__(config)
        raw_url = config.get("webhook_url", "")
        self._webhook_url = validate_outbound_url(raw_url) or "" if raw_url else ""
        if raw_url and not self._webhook_url:
            logger.error("Slack webhook URL이 내부 주소를 대상으로 하여 차단됨: %s", raw_url)
        self._dashboard_url = config.get("dashboard_url", "")

    async def send(self, alert: Alert) -> bool:
        """Slack Incoming Webhook으로 알림을 전송한다."""
        if not self._webhook_url:
            logger.warning("Slack not configured (missing webhook_url)")
            return False

        if alert.severity.value == "CRITICAL":
            payload = self._build_critical_payload(alert)
        else:
            payload = self._build_standard_payload(alert)

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self._webhook_url, json=payload,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        logger.debug("Slack alert sent: %s", alert.title)
                        return True
                    else:
                        body = await resp.text()
                        logger.error("Slack webhook error %d: %s", resp.status, body)
                        return False
        except Exception:
            logger.exception("Failed to send Slack alert")
            return False

    def _build_standard_payload(self, alert: Alert) -> dict:
        """일반 심각도 알림용 Slack attachment 페이로드를 구성한다."""
        color = {
            "CRITICAL": "#FF0000",
            "WARNING": "#FFA500",
            "INFO": "#36A2EB",
        }.get(alert.severity.value, "#808080")

        return {
            "attachments": [
                {
                    "color": color,
                    "title": f"[{alert.severity.value}] {alert.title}",
                    "text": alert.description,
                    "fields": [
                        {"title": "Engine", "value": alert.engine, "short": True},
                        {"title": "Source IP", "value": alert.source_ip or "N/A", "short": True},
                        {"title": "Source MAC", "value": alert.source_mac or "N/A", "short": True},
                        {"title": "Time", "value": alert.timestamp, "short": True},
                    ],
                }
            ]
        }

    def _build_critical_payload(self, alert: Alert) -> dict:
        """CRITICAL 알림용 상세 Slack 메시지를 구성한다."""
        pkt = alert.packet_info or {}

        # 헤더 블록
        blocks: list[dict] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"\u26a0\ufe0f CRITICAL: {alert.title}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": alert.description,
                },
            },
            {"type": "divider"},
        ]

        # 네트워크 정보
        net_lines = []
        net_lines.append(f"*Engine:* `{alert.engine}`")
        net_lines.append(f"*Time:* {alert.timestamp}")
        if alert.source_ip:
            net_lines.append(f"*Source IP:* `{alert.source_ip}`")
        if alert.source_mac:
            net_lines.append(f"*Source MAC:* `{alert.source_mac}`")
        if alert.dest_ip:
            net_lines.append(f"*Dest IP:* `{alert.dest_ip}`")
        if alert.dest_mac:
            net_lines.append(f"*Dest MAC:* `{alert.dest_mac}`")

        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "\n".join(net_lines)},
        })

        # 패킷 상세
        pkt_lines = []
        if pkt.get("layers"):
            pkt_lines.append(f"*Layers:* {' > '.join(pkt['layers'])}")
        if pkt.get("length"):
            pkt_lines.append(f"*Packet Size:* {pkt['length']} bytes")
        if pkt.get("src_port") is not None:
            pkt_lines.append(f"*Src Port:* {pkt['src_port']}")
        if pkt.get("dst_port") is not None:
            pkt_lines.append(f"*Dst Port:* {pkt['dst_port']}")
        if pkt.get("tcp_flags_list"):
            pkt_lines.append(f"*TCP Flags:* {', '.join(pkt['tcp_flags_list'])}")
        if pkt.get("dns_qname"):
            pkt_lines.append(f"*DNS Query:* `{pkt['dns_qname']}`")
        if pkt.get("arp_op"):
            pkt_lines.append(f"*ARP:* {pkt['arp_op']} ({pkt.get('arp_psrc', '?')} -> {pkt.get('arp_pdst', '?')})")
        if pkt.get("http_host"):
            pkt_lines.append(f"*HTTP Host:* `{pkt['http_host']}`")
        if pkt.get("http_user_agent"):
            ua = pkt["http_user_agent"][:100]
            pkt_lines.append(f"*User-Agent:* `{ua}`")

        if pkt_lines:
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*Packet Detail*\n" + "\n".join(pkt_lines)},
            })

        # 메타데이터
        meta = alert.metadata
        if meta:
            meta_lines = [f"*{k}:* {v}" for k, v in meta.items()]
            if meta_lines:
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": "*Engine Metadata*\n" + "\n".join(meta_lines[:10])},
                })

        # 대시보드 링크
        if self._dashboard_url:
            blocks.append({
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"<{self._dashboard_url}|Dashboard \u2192>"},
                ],
            })

        return {"blocks": blocks}
