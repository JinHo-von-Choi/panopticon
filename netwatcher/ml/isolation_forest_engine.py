"""Isolation Forest 기반 ML 이상 탐지 엔진.

scikit-learn이 설치되지 않은 환경에서는 엔진이 자동으로 비활성화된다.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations

import logging
import time
from typing import Any

from scapy.all import IP, TCP, UDP, Packet

from netwatcher.detection.base import DetectionEngine
from netwatcher.detection.models import Alert, Severity
from netwatcher.ml.adaptive_threshold import AdaptiveThreshold
from netwatcher.ml.feature_extractor import FeatureExtractor
from netwatcher.ml.model_manager import ModelManager

logger = logging.getLogger("netwatcher.ml.isolation_forest_engine")

try:
    from sklearn.ensemble import IsolationForest as _IsolationForest

    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False
    logger.info("scikit-learn not installed — ml_anomaly engine disabled")


class IsolationForestEngine(DetectionEngine):
    """Isolation Forest 알고리즘을 활용한 호스트별 이상 행동 탐지 엔진.

    동작 흐름:
    1. baseline 수집 기간 (기본 24시간): 패킷을 수집하여 특징 벡터 샘플 축적
    2. baseline 완료 후: IsolationForest 모델 학습
    3. 이후 on_tick마다: 특징 추출 -> 이상 점수 계산 -> 임계값 초과 시 알림

    scikit-learn이 없으면 enabled=False로 자동 전환되어 파이프라인에 영향을 주지 않는다.
    """

    name        = "ml_anomaly"
    description = "Isolation Forest 기반 ML 호스트 행동 이상 탐지."
    description_key = "engines.ml_anomaly.description"
    engine_type = "cpu"
    mitre_attack_ids = ["T1071", "T1041"]

    tick_interval = 60  # 1분 간격

    config_schema = {
        "baseline_hours": {
            "type": int, "default": 24, "min": 1, "max": 720,
            "label": "베이스라인 수집 기간(시간)",
        },
        "anomaly_threshold": {
            "type": float, "default": 0.7, "min": 0.1, "max": 0.99,
            "label": "이상 점수 임계값",
        },
        "retrain_interval_hours": {
            "type": int, "default": 168, "min": 1, "max": 8760,
            "label": "재학습 주기(시간)",
        },
        "contamination": {
            "type": float, "default": 0.01, "min": 0.001, "max": 0.5,
            "label": "IsolationForest contamination 파라미터",
        },
        "n_estimators": {
            "type": int, "default": 100, "min": 10, "max": 1000,
            "label": "IsolationForest 트리 개수",
        },
    }

    def __init__(self, config: dict[str, Any]) -> None:
        """엔진을 초기화한다."""
        super().__init__(config)

        # sklearn 미설치 시 비활성화
        if not _SKLEARN_AVAILABLE:
            self.enabled = False
            logger.warning("ml_anomaly engine disabled: scikit-learn not installed")

        self._baseline_hours     = config.get("baseline_hours", 24)
        self._anomaly_threshold  = config.get("anomaly_threshold", 0.7)
        self._retrain_hours      = config.get("retrain_interval_hours", 168)
        self._contamination      = config.get("contamination", 0.01)
        self._n_estimators       = config.get("n_estimators", 100)

        self._feature_extractor  = FeatureExtractor(window_seconds=60)
        self._model: Any         = None   # IsolationForest instance
        self._baseline_samples: list[list[float]] = []
        self._baseline_complete  = False
        self._start_time         = time.time()
        self._last_train_time    = 0.0

        self._threshold = AdaptiveThreshold(
            initial=self._anomaly_threshold,
            min_val=0.3,
            max_val=0.95,
        )

        self._model_manager = ModelManager()

        # 저장된 모델이 있으면 로드
        if self.enabled:
            self._try_load_model()

    def _try_load_model(self) -> None:
        """디스크에서 기존 학습 모델을 로드한다."""
        result = self._model_manager.load(self.name)
        if result is not None:
            self._model, meta = result
            self._baseline_complete = True
            self._last_train_time = meta.get("trained_at_epoch", time.time())
            logger.info(
                "Loaded pre-trained model '%s' (trained at: %s)",
                self.name,
                meta.get("saved_at", "unknown"),
            )

    def _fit_model(self) -> None:
        """수집된 베이스라인 샘플로 IsolationForest를 학습한다."""
        if not _SKLEARN_AVAILABLE or len(self._baseline_samples) < 10:
            return

        self._model = _IsolationForest(
            n_estimators=self._n_estimators,
            contamination=self._contamination,
            random_state=42,
            n_jobs=1,
        )
        self._model.fit(self._baseline_samples)
        self._baseline_complete = True
        self._last_train_time = time.time()

        # 디스크에 저장
        self._model_manager.save(
            self.name,
            self._model,
            {
                "n_samples": len(self._baseline_samples),
                "n_features": len(FeatureExtractor.FEATURE_NAMES),
                "feature_names": FeatureExtractor.FEATURE_NAMES,
                "contamination": self._contamination,
                "n_estimators": self._n_estimators,
                "trained_at_epoch": self._last_train_time,
            },
        )
        logger.info(
            "IsolationForest trained with %d samples, %d features",
            len(self._baseline_samples),
            len(FeatureExtractor.FEATURE_NAMES),
        )

    def analyze(self, packet: Packet) -> Alert | None:
        """패킷을 특징 추출기에 공급한다. 패킷 단위 알림은 생성하지 않는다."""
        if not self.enabled:
            return None

        if not packet.haslayer(IP):
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        size   = len(packet)

        if packet.haslayer(TCP):
            protocol = "tcp"
            port     = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "udp"
            port     = packet[UDP].dport
        else:
            protocol = "other"
            port     = 0

        self._feature_extractor.feed_packet(src_ip, dst_ip, protocol, size, port)
        return None

    def on_tick(self, timestamp: float) -> list[Alert]:
        """특징 추출, 모델 스코어링, 이상 알림 생성을 수행한다."""
        if not self.enabled:
            return []

        all_features = self._feature_extractor.extract_all()
        self._feature_extractor.reset()

        if not all_features:
            return []

        elapsed_hours = (time.time() - self._start_time) / 3600.0

        # 베이스라인 수집 단계
        if not self._baseline_complete:
            for features in all_features.values():
                self._baseline_samples.append(features)

            if elapsed_hours >= self._baseline_hours:
                self._fit_model()

            return []

        # 재학습 주기 확인
        if self._last_train_time > 0:
            hours_since_train = (time.time() - self._last_train_time) / 3600.0
            if hours_since_train >= self._retrain_hours:
                for features in all_features.values():
                    self._baseline_samples.append(features)
                # 최근 샘플로 제한 (메모리 관리)
                max_samples = 10000
                if len(self._baseline_samples) > max_samples:
                    self._baseline_samples = self._baseline_samples[-max_samples:]
                self._fit_model()

        # 스코어링
        alerts: list[Alert] = []
        if self._model is None:
            return alerts

        for src_ip, features in all_features.items():
            if self.is_whitelisted(source_ip=src_ip):
                continue

            try:
                # decision_function: 음수 = 이상, 양수 = 정상
                # score_samples: 음수가 더 이상
                raw_score = self._model.decision_function([features])[0]
                # 0~1 범위 이상 점수로 변환 (낮을수록 이상)
                # decision_function 범위는 대략 -0.5 ~ 0.5
                anomaly_score = max(0.0, min(1.0, 0.5 - raw_score))
            except Exception:
                logger.debug("Scoring failed for %s", src_ip, exc_info=True)
                continue

            if anomaly_score >= self._threshold.current:
                severity = (
                    Severity.CRITICAL if anomaly_score > 0.9
                    else Severity.WARNING
                )
                confidence = min(0.95, anomaly_score)

                alerts.append(Alert(
                    engine=self.name,
                    severity=severity,
                    title="ML Anomaly Detected",
                    title_key="engines.ml_anomaly.alerts.anomaly.title",
                    description=(
                        f"Host {src_ip} shows anomalous behavior "
                        f"(score={anomaly_score:.3f}, "
                        f"threshold={self._threshold.current:.3f})."
                    ),
                    description_key="engines.ml_anomaly.alerts.anomaly.description",
                    source_ip=src_ip,
                    confidence=confidence,
                    metadata={
                        "anomaly_score": round(anomaly_score, 4),
                        "threshold": round(self._threshold.current, 4),
                        "raw_score": round(raw_score, 4),
                        "feature_names": FeatureExtractor.FEATURE_NAMES,
                        "feature_values": [round(v, 4) for v in features],
                    },
                ))

        return alerts

    def report_feedback(self, is_false_positive: bool) -> None:
        """외부 피드백으로 적응형 임계값을 조정한다.

        Args:
            is_false_positive: True면 오탐, False면 정탐.
        """
        self._threshold.adjust(is_false_positive)
        logger.info(
            "Threshold adjusted: is_fp=%s, new_threshold=%.4f",
            is_false_positive,
            self._threshold.current,
        )

    def shutdown(self) -> None:
        """엔진 상태를 정리한다."""
        self._feature_extractor.reset()
        self._baseline_samples.clear()
