"""엔진 공통 메모리 관리 유틸리티.

작성자: 최진호
작성일: 2026-03-13
"""

from __future__ import annotations

import time
from collections import OrderedDict
from typing import Any, Callable


class BoundedDefaultDict(dict):
    """최대 키 수를 초과하면 가장 오래된 키를 제거하는 dict.

    defaultdict처럼 동작하되, max_keys를 초과하면
    가장 오래된 항목의 25%를 일괄 제거한다.
    """

    __slots__ = ("_factory", "_max_keys", "_access_order")

    def __init__(self, factory: Callable[[], Any], max_keys: int = 10_000):
        super().__init__()
        self._factory = factory
        self._max_keys = max(16, max_keys)
        self._access_order: dict[Any, float] = {}

    def __missing__(self, key: Any) -> Any:
        if len(self) >= self._max_keys:
            self._evict()
        value = self._factory()
        self[key] = value
        self._access_order[key] = time.monotonic()
        return value

    def __getitem__(self, key: Any) -> Any:
        value = super().__getitem__(key)
        self._access_order[key] = time.monotonic()
        return value

    def __delitem__(self, key: Any) -> None:
        super().__delitem__(key)
        self._access_order.pop(key, None)

    def pop(self, key: Any, *args: Any) -> Any:
        self._access_order.pop(key, None)
        return super().pop(key, *args)

    def _evict(self) -> None:
        n_remove = max(1, len(self) // 4)
        oldest = sorted(self._access_order, key=self._access_order.get)[:n_remove]
        for k in oldest:
            super().pop(k, None)
            self._access_order.pop(k, None)

    def clear(self) -> None:
        super().clear()
        self._access_order.clear()


class LRUSet:
    """최대 크기를 가진 LRU 기반 set.

    maxlen 초과 시 가장 오래 접근된 항목부터 제거한다.
    """

    __slots__ = ("_data", "_maxlen")

    def __init__(self, maxlen: int = 10_000):
        self._data: OrderedDict[Any, None] = OrderedDict()
        self._maxlen = max(16, maxlen)

    def add(self, item: Any) -> None:
        if item in self._data:
            self._data.move_to_end(item)
        else:
            self._data[item] = None
            if len(self._data) > self._maxlen:
                self._data.popitem(last=False)

    def __contains__(self, item: Any) -> bool:
        return item in self._data

    def __len__(self) -> int:
        return len(self._data)

    def __bool__(self) -> bool:
        return bool(self._data)

    def discard(self, item: Any) -> None:
        self._data.pop(item, None)

    def clear(self) -> None:
        self._data.clear()


def prune_empty_keys(d: dict) -> int:
    """빈 deque/list/set/dict 값을 가진 키를 삭제한다. 삭제된 수 반환."""
    empty = [k for k, v in d.items() if hasattr(v, "__len__") and len(v) == 0]
    for k in empty:
        del d[k]
    return len(empty)


def prune_expired_entries(d: dict[Any, float], max_age: float,
                          now: float | None = None) -> int:
    """값이 float(timestamp)이고 max_age보다 오래된 항목을 삭제한다."""
    now = now or time.time()
    cutoff = now - max_age
    expired = [k for k, v in d.items() if v < cutoff]
    for k in expired:
        del d[k]
    return len(expired)
