"""관측 대시보드 패널 정의.

패널마다 고정된 SQL과 지원 모드를 둔다. 요청은 등록된 패널 ID와 기간만 고를 수 있고,
임의 쿼리는 받지 않는다. 시계열 버킷 폭은 서버가 기간에서 정한다.
"""

from __future__ import annotations

from dataclasses import dataclass

# 기간(초) 상한별 버킷 폭(초). 패널당 점 수를 수백 개 안으로 묶는다.
BUCKETS = ((3600, 60), (6 * 3600, 300), (24 * 3600, 900), (7 * 86400, 3600), (31 * 86400, 21600), (92 * 86400, 86400))
MAX_RANGE_SECONDS = 92 * 86400
TOP_N = 10


def bucket_seconds(range_seconds: float) -> int:
    for limit, width in BUCKETS:
        if range_seconds <= limit:
            return width
    raise ValueError("range too long")


@dataclass(frozen=True)
class Panel:
    kind: str            # timeseries | bar | heatmap | histogram
    sql: str             # $n은 args 순서를 따른다
    modes: frozenset     # 지원 입력 모드
    unit: str
    args: tuple = ("from", "to")  # from·to·bucket·tz 중 쿼리가 쓰는 값과 순서


_BOTH = frozenset({"eve", "native"})
_NATIVE = frozenset({"native"})
_EVE = frozenset({"eve"})
_SERIES = ("from", "to", "bucket")

PANELS: dict[str, Panel] = {
    "alerts_by_severity": Panel("timeseries", """
        SELECT date_bin(make_interval(secs => $3), timestamp, $1) AS bucket, severity AS series, count(*) AS value
        FROM events WHERE timestamp >= $1 AND timestamp < $2 GROUP BY 1, 2 ORDER BY 1""", _BOTH, "alerts", _SERIES),
    "alerts_by_engine": Panel("bar", f"""
        SELECT engine AS label, count(*) AS value FROM events
        WHERE timestamp >= $1 AND timestamp < $2 GROUP BY 1 ORDER BY 2 DESC LIMIT {TOP_N}""", _NATIVE, "alerts"),
    "alert_heatmap": Panel("heatmap", """
        SELECT extract(isodow FROM timestamp AT TIME ZONE $3)::int AS x, extract(hour FROM timestamp AT TIME ZONE $3)::int AS y,
               count(*) AS value
        FROM events WHERE timestamp >= $1 AND timestamp < $2 GROUP BY 1, 2""", _BOTH, "alerts", ("from", "to", "tz")),
    "top_sources": Panel("bar", f"""
        SELECT host(source_ip) AS label, count(*) AS value FROM events
        WHERE timestamp >= $1 AND timestamp < $2 AND source_ip IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT {TOP_N}""", _BOTH, "alerts"),
    "top_destinations": Panel("bar", f"""
        SELECT host(dest_ip) AS label, count(*) AS value FROM events
        WHERE timestamp >= $1 AND timestamp < $2 AND dest_ip IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT {TOP_N}""", _BOTH, "alerts"),
    "top_techniques": Panel("bar", f"""
        SELECT mitre_attack_id AS label, count(*) AS value FROM events
        WHERE timestamp >= $1 AND timestamp < $2 AND mitre_attack_id IS NOT NULL AND mitre_attack_id <> ''
        GROUP BY 1 ORDER BY 2 DESC LIMIT {TOP_N}""", _BOTH, "alerts"),
    "eve_event_types": Panel("timeseries", """
        SELECT date_bin(make_interval(secs => $3), observed_at, $1) AS bucket, event_type AS series, count(*) AS value
        FROM eve_records WHERE observed_at >= $1 AND observed_at < $2 GROUP BY 1, 2 ORDER BY 1""", _EVE, "records", _SERIES),
    "eve_ingest_delay": Panel("histogram", """
        SELECT CASE WHEN d < 1 THEN '<1s' WHEN d < 5 THEN '1-5s' WHEN d < 30 THEN '5-30s'
                    WHEN d < 300 THEN '30s-5m' ELSE '>=5m' END AS label, count(*) AS value
        FROM (SELECT extract(epoch FROM received_at - observed_at) AS d FROM eve_records
              WHERE observed_at >= $1 AND observed_at < $2) s GROUP BY 1""", _EVE, "records"),
    "eve_top_signatures": Panel("bar", f"""
        SELECT record->'details'->>'signature' AS label, count(*) AS value FROM eve_records
        WHERE event_type = 'alert' AND observed_at >= $1 AND observed_at < $2
          AND record->'details'->>'signature' IS NOT NULL
        GROUP BY 1 ORDER BY 2 DESC LIMIT {TOP_N}""", _EVE, "alerts"),
    "eve_feed_matches": Panel("timeseries", """
        SELECT date_bin(make_interval(secs => $3), observed_at, $1) AS bucket, event_type AS series, count(*) AS value
        FROM eve_records WHERE observed_at >= $1 AND observed_at < $2 AND record ? 'feed_match'
        GROUP BY 1, 2 ORDER BY 1""", _EVE, "records", _SERIES),
    "eve_feed_indicators": Panel("bar", f"""
        SELECT m->>'indicator' AS label, count(*) AS value
        FROM eve_records, jsonb_array_elements(record->'feed_match') AS m
        WHERE observed_at >= $1 AND observed_at < $2 AND record ? 'feed_match'
        GROUP BY 1 ORDER BY 2 DESC LIMIT {TOP_N}""", _EVE, "records"),
    "traffic_throughput": Panel("timeseries", """
        SELECT date_bin(make_interval(secs => $3), timestamp, $1) AS bucket, s.series,
               (CASE s.series WHEN 'pps' THEN sum(total_packets) ELSE sum(total_bytes) * 8 END)::float8 / $3 AS value
        FROM traffic_stats CROSS JOIN (VALUES ('pps'), ('bps')) AS s(series)
        WHERE timestamp >= $1 AND timestamp < $2 GROUP BY 1, 2 ORDER BY 1""", _NATIVE, "per_second", _SERIES),
    "protocol_counts": Panel("bar", """
        SELECT s.label, s.value FROM (
            SELECT sum(tcp_count) AS tcp, sum(udp_count) AS udp, sum(arp_count) AS arp, sum(dns_count) AS dns
            FROM traffic_stats WHERE timestamp >= $1 AND timestamp < $2) t
        CROSS JOIN LATERAL (VALUES ('TCP', t.tcp), ('UDP', t.udp), ('ARP', t.arp), ('DNS', t.dns)) AS s(label, value)
        WHERE s.value IS NOT NULL""", _NATIVE, "packets"),
    "open_incidents": Panel("histogram", """
        SELECT CASE WHEN age < interval '1 hour' THEN '<1h' WHEN age < interval '1 day' THEN '1h-1d'
                    WHEN age < interval '7 days' THEN '1-7d' ELSE '>=7d' END AS label, count(*) AS value
        FROM (SELECT $1::timestamptz - created_at AS age FROM incidents
              WHERE NOT resolved AND created_at < $1) s GROUP BY 1""", _BOTH, "incidents", ("to",)),
    "case_status": Panel("bar", """
        SELECT COALESCE(w.status, 'open') AS label, count(*) AS value FROM events e
        LEFT JOIN case_workflows w ON w.event_id = e.id
        WHERE e.timestamp >= $1 AND e.timestamp < $2 GROUP BY 1 ORDER BY 2 DESC""", _BOTH, "events"),
    "proposal_status": Panel("bar", """
        SELECT status AS label, count(*) AS value FROM config_proposals
        WHERE created_at >= $1 AND created_at < $2 GROUP BY 1 ORDER BY 2 DESC""", _NATIVE, "proposals"),
    "sensor_latency": Panel("timeseries", """
        SELECT date_bin(make_interval(secs => $3), sampled_at, $1) AS bucket, s.series,
               max(CASE s.series WHEN 'loop_lag_ms' THEN loop_lag_ms ELSE lease_publish_ms END)::float8 AS value
        FROM sensor_samples CROSS JOIN (VALUES ('loop_lag_ms'), ('lease_publish_ms')) AS s(series)
        WHERE sampled_at >= $1 AND sampled_at < $2 GROUP BY 1, 2 ORDER BY 1""", _NATIVE, "ms", _SERIES),
    "sensor_memory": Panel("timeseries", """
        SELECT date_bin(make_interval(secs => $3), sampled_at, $1) AS bucket, 'memory_mib' AS series,
               max(memory_current)::float8 / 1048576 AS value
        FROM sensor_samples WHERE sampled_at >= $1 AND sampled_at < $2 AND memory_current IS NOT NULL
        GROUP BY 1 ORDER BY 1""", _NATIVE, "mib", _SERIES),
    # 누적 계수는 같은 기동(boot_id) 안의 최대-최소로 증분을 구해 재시작에서 음수가 나오지 않게 한다.
    "sensor_cpu": Panel("timeseries", """
        SELECT bucket, s.series, sum(CASE s.series WHEN 'cpu_used_s' THEN used WHEN 'cpu_throttled_s' THEN throttled
                                    ELSE high END)::float8 AS value
        FROM (SELECT date_bin(make_interval(secs => $3), sampled_at, $1) AS bucket, boot_id,
                     (max(cpu_usage_usec) - min(cpu_usage_usec)) / 1e6 AS used,
                     (max(cpu_throttled_usec) - min(cpu_throttled_usec)) / 1e6 AS throttled,
                     max(memory_high_events) - min(memory_high_events) AS high
              FROM sensor_samples WHERE sampled_at >= $1 AND sampled_at < $2 GROUP BY 1, 2) d
        CROSS JOIN (VALUES ('cpu_used_s'), ('cpu_throttled_s'), ('memory_high_events')) AS s(series)
        GROUP BY 1, 2 ORDER BY 1""", _NATIVE, "count", _SERIES),
    "new_devices": Panel("timeseries", """
        SELECT date_bin(make_interval(secs => $3), first_seen, $1) AS bucket, 'new' AS series, count(*) AS value
        FROM devices WHERE first_seen >= $1 AND first_seen < $2 GROUP BY 1 ORDER BY 1""", _NATIVE, "devices", _SERIES),
}
