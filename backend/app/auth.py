"""CMS-DOS — аутентификация (🔴 КРАСНАЯ ЗОНА: требует ревью ПМ/Дениса).

Один пользователь. По умолчанию admin/admin с флагом must_change=True (смена при первом входе).
Пароль хранится ХЕШИРОВАННЫМ (pbkdf2-hmac-sha256 + соль), не в открытом виде.
Файл кредов — вне рабочей папки и вне git (backend/data/auth.json, chmod 600).
Сессии — в памяти процесса (минимум; при рестарте разлогинивает — для нашего масштаба ок).
"""
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

_DEFAULT_FILE = Path(__file__).resolve().parent.parent / "data" / "auth.json"
_ITER = 600_000                 # OWASP-рекомендация для pbkdf2-sha256 (было 100k)
SESSION_TTL = 12 * 3600         # сессия живёт 12 часов, потом протухает


def _path() -> Path:
    return Path(os.environ.get("CMSDOS_AUTH_FILE", str(_DEFAULT_FILE)))


def _hash(password: str, salt: str, iterations: int = _ITER) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iterations).hex()


def _save(data: dict) -> None:
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data))
    try:
        p.chmod(0o600)
    except OSError:
        pass


def _load() -> dict:
    p = _path()
    if not p.exists():
        salt = secrets.token_hex(16)
        data = {"username": "admin", "salt": salt, "hash": _hash("admin", salt),
                "iter": _ITER, "must_change": True}
        _save(data)
        return data
    return json.loads(p.read_text())


def verify(username: str, password: str) -> bool:
    data = _load()
    if username != data["username"]:
        return False
    iterations = int(data.get("iter", 100_000))   # старые записи считались на 100k — не ломаем их
    return hmac.compare_digest(_hash(password, data["salt"], iterations), data["hash"])   # constant-time


def must_change() -> bool:
    return bool(_load().get("must_change"))


def set_password(new_password: str) -> None:
    data = _load()
    salt = secrets.token_hex(16)
    data.update(salt=salt, hash=_hash(new_password, salt), iter=_ITER, must_change=False)
    _save(data)


# --- сессии (в памяти, с TTL) ---
_sessions: dict[str, tuple[str, float]] = {}   # token -> (username, expires_at)


def new_session(username: str) -> str:
    tok = secrets.token_urlsafe(32)
    _sessions[tok] = (username, time.time() + SESSION_TTL)
    return tok


def session_user(token: str | None) -> str | None:
    if not token:
        return None
    rec = _sessions.get(token)
    if rec is None:
        return None
    username, expires = rec
    if time.time() >= expires:          # протухла — удаляем
        _sessions.pop(token, None)
        return None
    return username


def drop_session(token: str | None) -> None:
    if token:
        _sessions.pop(token, None)
