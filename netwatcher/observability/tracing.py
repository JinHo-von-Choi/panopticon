"""OpenTelemetry 분산 추적 (선택적 의존성).

opentelemetry 패키지가 설치되지 않은 경우 no-op 트레이서로 대체된다.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import functools
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, Callable, Generator, TypeVar

if TYPE_CHECKING:
    from netwatcher.utils.config import Config

F = TypeVar("F", bound=Callable[..., Any])

_HAS_OTEL = False
_tracer_provider: Any = None

try:
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.sdk.trace.sampling import TraceIdRatioBased

    _HAS_OTEL = True
except ImportError:
    pass


class _NoOpSpan:
    """OpenTelemetry 미설치 시 사용되는 no-op 스팬."""

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def set_status(self, status: Any) -> None:
        pass

    def record_exception(self, exception: BaseException) -> None:
        pass

    def __enter__(self) -> _NoOpSpan:
        return self

    def __exit__(self, *args: Any) -> None:
        pass


class _NoOpTracer:
    """OpenTelemetry 미설치 시 사용되는 no-op 트레이서."""

    def start_as_current_span(self, name: str, **kwargs: Any) -> _NoOpSpan:
        return _NoOpSpan()

    @contextmanager
    def start_span(self, name: str, **kwargs: Any) -> Generator[_NoOpSpan, None, None]:
        yield _NoOpSpan()


_noop_tracer = _NoOpTracer()


def setup_tracing(config: Config) -> None:
    """OpenTelemetry TracerProvider를 초기화한다.

    Args:
        config: NetWatcher 설정 객체. observability.tracing 섹션을 참조한다.
    """
    global _tracer_provider

    if not _HAS_OTEL:
        return

    tracing_cfg  = config.get("observability.tracing", {}) or {}
    enabled      = tracing_cfg.get("enabled", False)

    if not enabled:
        return

    endpoint     = tracing_cfg.get("endpoint", "http://localhost:4317")
    service_name = tracing_cfg.get("service_name", "netwatcher")
    sample_rate  = tracing_cfg.get("sample_rate", 0.01)

    resource = Resource.create({"service.name": service_name})
    sampler  = TraceIdRatioBased(sample_rate)

    _tracer_provider = TracerProvider(resource=resource, sampler=sampler)
    exporter         = OTLPSpanExporter(endpoint=endpoint, insecure=True)
    _tracer_provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(_tracer_provider)


def get_tracer(name: str) -> Any:
    """트레이서 인스턴스를 반환한다.

    OpenTelemetry가 설치되어 있고 활성화된 경우 실제 트레이서를 반환하고,
    그렇지 않으면 no-op 트레이서를 반환한다.

    Args:
        name: 트레이서 이름 (예: "netwatcher.detection").

    Returns:
        Tracer 또는 _NoOpTracer.
    """
    if _HAS_OTEL and _tracer_provider is not None:
        return trace.get_tracer(name)
    return _noop_tracer


def traced(name: str | None = None) -> Callable[[F], F]:
    """함수를 OpenTelemetry 스팬으로 래핑하는 데코레이터.

    Args:
        name: 스팬 이름. None이면 함수의 정규화된 이름을 사용한다.

    Returns:
        데코레이터.
    """

    def decorator(func: F) -> F:
        span_name = name or f"{func.__module__}.{func.__qualname__}"

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            tracer = get_tracer(func.__module__)
            with tracer.start_as_current_span(span_name):
                return func(*args, **kwargs)

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            tracer = get_tracer(func.__module__)
            with tracer.start_as_current_span(span_name):
                return await func(*args, **kwargs)

        import asyncio

        if asyncio.iscoroutinefunction(func):
            return async_wrapper  # type: ignore[return-value]
        return sync_wrapper  # type: ignore[return-value]

    return decorator
