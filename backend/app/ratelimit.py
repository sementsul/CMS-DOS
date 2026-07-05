"""Простой in-memory rate-limit (для защиты /api/login от перебора).

Ключ — обычно IP. Разрешаем не больше max_events неудач за window секунд.
В памяти процесса (при рестарте сбрасывается) — для нашего масштаба достаточно.
"""
import time

_events: dict[str, list[float]] = {}


def allowed(key: str, max_events: int = 5, window: int = 300) -> bool:
    now = time.time()
    _events[key] = [t for t in _events.get(key, []) if now - t < window]
    return len(_events[key]) < max_events


def record(key: str) -> None:
    _events.setdefault(key, []).append(time.time())


def reset(key: str) -> None:
    _events.pop(key, None)
