"""NetWatcher용 Prometheus 메트릭 정의."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, generate_latest

# --- 패킷 파이프라인 ---
packets_total   = Counter("netwatcher_packets_total", "Total packets processed")
packets_dropped = Counter("netwatcher_packets_dropped", "Packets dropped by backpressure")

# --- 알림 ---
alerts_total        = Counter("netwatcher_alerts_total", "Alerts generated", ["engine", "severity"])
alerts_rate_limited = Counter("netwatcher_alerts_rate_limited", "Rate-limited alerts")
alerts_queue_depth  = Gauge("netwatcher_alerts_queue_depth", "Current alert queue depth")

# --- 웹훅 ---
webhook_duration = Histogram(
    "netwatcher_webhook_duration_seconds",
    "Webhook send duration",
    ["channel"],
)

# --- 데이터베이스 ---
db_query_duration = Histogram(
    "netwatcher_db_query_duration_seconds",
    "DB query duration",
    ["operation"],
)

# --- 탐지 엔진 ---
engine_analyze_duration = Histogram(
    "netwatcher_engine_analyze_seconds",
    "Engine analyze() duration",
    ["engine"],
)

# --- 디바이스 ---
active_devices = Gauge("netwatcher_active_devices", "Currently tracked devices")

# --- 위협 피드 ---
feed_last_update = Gauge(
    "netwatcher_feed_last_update_epoch",
    "Last threat feed update timestamp (epoch seconds)",
)


def get_metrics_output() -> bytes:
    """Prometheus 텍스트 노출 형식을 생성한다."""
    return generate_latest()
