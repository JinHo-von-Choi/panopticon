"""피드백 기반 동적 이상 탐지 임계값 조정 모듈.

작성자: 최진호
작성일: 2026-03-29
"""

from __future__ import annotations


class AdaptiveThreshold:
    """관찰된 FP/TP 피드백에 따라 이상 탐지 임계값을 동적으로 조정한다.

    오탐(FP)이 보고되면 임계값을 올려 민감도를 낮추고,
    정탐(TP)이 보고되면 임계값을 내려 민감도를 높인다.
    """

    def __init__(
        self,
        initial: float = 0.7,
        min_val: float = 0.3,
        max_val: float = 0.95,
        step: float = 0.02,
    ) -> None:
        """동적 임계값을 초기화한다.

        Args:
            initial: 초기 임계값.
            min_val: 허용 최저 임계값.
            max_val: 허용 최고 임계값.
            step:    한 번의 조정 폭.
        """
        self._value   = initial
        self._min_val = min_val
        self._max_val = max_val
        self._step    = step

    def adjust(self, is_false_positive: bool) -> None:
        """피드백에 따라 임계값을 조정한다.

        Args:
            is_false_positive: True면 오탐(임계값 상향), False면 정탐(임계값 하향).
        """
        if is_false_positive:
            self._value = min(self._max_val, self._value + self._step)
        else:
            self._value = max(self._min_val, self._value - self._step)

    @property
    def current(self) -> float:
        """현재 임계값을 반환한다."""
        return self._value
