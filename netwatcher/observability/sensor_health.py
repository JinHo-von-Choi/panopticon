"""독립 콘솔에서 DB로 전달받은 센서 상태와 사건 전달 연결을 점검한다."""

import asyncio
from copy import deepcopy

from netwatcher.observability.health import HealthChecker


class SeparatedSensorHealthChecker(HealthChecker):
    sensor_components = ("sniffer", "engines", "alert_queue", "stats_flush")

    def __init__(self, database, observation, event_stream, *, timeout_seconds=2, observation_reader=None):
        super().__init__(database=database, observation=observation, timeout_seconds=timeout_seconds)
        self._event_stream = event_stream
        self._read_lock = asyncio.Lock()
        self._observation_reader = observation_reader

    async def check_all(self):
        # 한 요청의 실패가 뒤에 성공한 조회의 캐시를 덮지 않게 한다.
        async with self._read_lock:
            result = await super().check_all()
            components = result["components"]
            try:
                async with asyncio.timeout(self._timeout_seconds):
                    await self._observation.refresh()
                snapshot = self._observation.snapshot()
            except Exception as exc:
                snapshot = {"state": "unknown", "reasons": ["센서 상태를 조회하지 못했습니다."]}
                components["sensor_state"] = {"status": "unknown", "reason": type(exc).__name__}
            else:
                heartbeat = snapshot.get("sensor_heartbeat", {})
                confirmed = heartbeat.get("confirmed") is True
                components["sensor_state"] = {
                    "status": "healthy" if confirmed else "unknown",
                    "heartbeat_age_seconds": heartbeat.get("age_seconds"),
                    "scope": "separate_sensor",
                }
            state = snapshot.get("state")
            if state not in ("observed", "partial", "unknown", "stale"):
                state = "unknown"
            reasons = snapshot.get("reasons")
            if not isinstance(reasons, list) or not reasons or any(not isinstance(reason, str) or not reason.strip() for reason in reasons):
                state = "unknown"
                reasons = ["센서의 관측 판정 근거를 확인할 수 없습니다."]
            fresh = components["sensor_state"]["status"] == "healthy" and state in ("observed", "partial")
            runtime = snapshot.get("runtime", {})
            if not isinstance(runtime, dict):
                runtime = {}
            reported = runtime.get("health_components", {})
            if not isinstance(reported, dict):
                reported = {}
            for name in self.sensor_components:
                component = reported.get(name) if fresh else None
                if (not isinstance(component, dict)
                        or component.get("status") not in {"healthy", "degraded", "unhealthy", "unknown", "unconfigured"}):
                    components[name] = {"status": "unknown", "scope": "separate_sensor"}
                else:
                    components[name] = {**deepcopy(component), "scope": "separate_sensor"}
            if runtime.get("capture_running") is not True:
                components["sniffer"] = {"status": "unknown", "scope": "separate_sensor"}
            components["observation"] = {
                "status": "healthy" if fresh and state == "observed" else "degraded",
                "state": state, "reasons": reasons,
            }
            try:
                stream = self._event_stream.status()
                if not isinstance(stream, dict) or stream.get("status") not in {"healthy", "degraded", "unhealthy"}:
                    raise ValueError("Invalid event stream state")
                components["event_stream"] = deepcopy(stream)
            except Exception as exc:
                components["event_stream"] = {"status": "unknown", "reason": type(exc).__name__}
            required = ("database", "sensor_state", "event_stream", "observation", *self.sensor_components)
            if self._observation_reader is not None:
                try:
                    components["observation_reader"] = self._observation_reader.status()
                except Exception as exc:
                    components["observation_reader"] = {"status": "unknown", "reason": type(exc).__name__}
                required += ("observation_reader",)
            result["ready"] = all(components[name]["status"] == "healthy" for name in required)
            statuses = [component["status"] for component in components.values()]
            result["overall_status"] = ("unhealthy" if "unhealthy" in statuses else
                                        "healthy" if result["ready"] else "degraded")
            return result

    async def readiness(self):
        return await self.check_all()
