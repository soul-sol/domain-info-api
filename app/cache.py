"""Small, dependency-free in-process TTL cache."""

from __future__ import annotations

from collections import OrderedDict
from copy import deepcopy
from threading import Lock
from time import monotonic
from typing import Generic, TypeVar


T = TypeVar("T")


class TTLCache(Generic[T]):
    """Thread-safe bounded cache with monotonic expirations."""

    def __init__(self, ttl_seconds: float, max_size: int = 1024) -> None:
        self._ttl_seconds = ttl_seconds
        self._max_size = max_size
        self._items: OrderedDict[str, tuple[float, T]] = OrderedDict()
        self._lock = Lock()

    def get(self, key: str) -> T | None:
        now = monotonic()
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return None
            expires_at, value = item
            if expires_at <= now:
                del self._items[key]
                return None
            self._items.move_to_end(key)
            return deepcopy(value)

    def set(self, key: str, value: T) -> None:
        expires_at = monotonic() + self._ttl_seconds
        with self._lock:
            self._items[key] = (expires_at, deepcopy(value))
            self._items.move_to_end(key)
            while len(self._items) > self._max_size:
                self._items.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
