"""CMS-DOS — бэкенд: аутентификация + рабочая папка + API моста js-dos↔сервер.

Файлы живут в workspace/ на сервере. DOS-менеджер в браузере читает/пишет их через этот API.
🔴 Все пути строго внутри workspace (защита от path traversal): _safe(). Auth — красная зона (см. auth.py).
"""
import base64
import mimetypes
import os
from pathlib import Path

from fastapi import (Cookie, Depends, FastAPI, File, Form, HTTPException, Query,
                     Request, Response, UploadFile)
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app import auth, ratelimit

mimetypes.add_type("application/wasm", ".wasm")   # чтобы браузер стримил wasm (иначе js-dos тормозит/падает)

app = FastAPI(title="CMS-DOS")

DEFAULT_WS = Path(__file__).resolve().parent.parent / "workspace"
FRONTEND = Path(__file__).resolve().parent.parent.parent / "frontend"
SESSION_COOKIE = "cmsdos_session"
# На проде (HTTPS) выставить CMSDOS_COOKIE_SECURE=1 — cookie сессии не уйдёт по HTTP (защита от перехвата).
COOKIE_SECURE = os.environ.get("CMSDOS_COOKIE_SECURE", "0") == "1"


@app.middleware("http")
async def cross_origin_isolation(request: Request, call_next):
    """COOP/COEP → crossOriginIsolated → доступен SharedArrayBuffer (нужен js-dos для потоков).
    + анти-кеш для html/js (чтобы браузер не держал старую версию фронта)."""
    resp = await call_next(request)
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    path = request.url.path
    if not path.startswith("/vendor/") and (path == "/" or path.endswith((".html", ".js"))):
        resp.headers["Cache-Control"] = "no-store, must-revalidate"
    return resp


def _ws() -> Path:
    p = Path(os.environ.get("DOSFM_WORKSPACE", str(DEFAULT_WS))).resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def _safe(rel: str) -> Path:
    """Разрешить относительный путь строго внутри workspace (никаких ../ и абсолютных)."""
    ws = _ws()
    target = (ws / rel).resolve()
    if target != ws and ws not in target.parents:
        raise HTTPException(status_code=400, detail="path outside workspace")
    return target


def require_auth(cmsdos_session: str | None = Cookie(default=None)) -> str:
    user = auth.session_user(cmsdos_session)
    if not user:
        raise HTTPException(status_code=401, detail="not authenticated")
    return user


# --- аутентификация (🔴 красная зона — ревью ПМ) ---
class LoginIn(BaseModel):
    username: str
    password: str


class PasswdIn(BaseModel):
    new_password: str
    old_password: str | None = None


@app.post("/api/login")
def login(data: LoginIn, request: Request, response: Response):
    key = "login:" + (request.client.host if request.client else "?")
    if not ratelimit.allowed(key, max_events=5, window=300):
        raise HTTPException(status_code=429, detail="слишком много попыток, попробуйте позже")
    if not auth.verify(data.username, data.password):
        ratelimit.record(key)        # считаем только неудачи
        raise HTTPException(status_code=401, detail="неверный логин или пароль")
    ratelimit.reset(key)             # успешный вход снимает счётчик
    response.set_cookie(SESSION_COOKIE, auth.new_session(data.username),
                        httponly=True, samesite="lax", secure=COOKIE_SECURE, max_age=auth.SESSION_TTL)
    return {"ok": True, "must_change": auth.must_change()}


@app.get("/api/me")
def me(cmsdos_session: str | None = Cookie(default=None)):
    user = auth.session_user(cmsdos_session)
    return {"authenticated": bool(user), "username": user,
            "must_change": auth.must_change() if user else False}


@app.post("/api/passwd")
def passwd(data: PasswdIn, user: str = Depends(require_auth)):
    """Смена пароля. При первом входе (must_change) — без старого; далее — со старым."""
    if not auth.must_change():
        if not data.old_password or not auth.verify(user, data.old_password):
            raise HTTPException(status_code=401, detail="неверный текущий пароль")
    if len(data.new_password) < 8:
        raise HTTPException(status_code=400, detail="пароль слишком короткий (мин. 8 символов)")
    auth.set_password(data.new_password)
    return {"ok": True}


@app.post("/api/logout")
def logout(cmsdos_session: str | None = Cookie(default=None)):
    auth.drop_session(cmsdos_session)
    return {"ok": True}


# --- API рабочей папки (всё под аутентификацией) ---
@app.get("/api/tree")
def tree(user: str = Depends(require_auth)):
    ws = _ws()
    out = []
    for p in sorted(ws.rglob("*")):
        out.append({
            "path": p.relative_to(ws).as_posix(),
            "is_dir": p.is_dir(),
            "size": p.stat().st_size if p.is_file() else 0,
        })
    return out


@app.get("/api/download")
def download(path: str = Query(...), user: str = Depends(require_auth)):
    target = _safe(path)
    if not target.is_file():
        raise HTTPException(status_code=404, detail="not found")
    return FileResponse(target)


class SyncFile(BaseModel):
    path: str
    content_b64: str


class SyncIn(BaseModel):
    files: list[SyncFile] = []
    deleted: list[str] = []          # пути, удалённые в эмуляторе → удалить на сервере


@app.post("/api/sync")
def sync(data: SyncIn, user: str = Depends(require_auth)):
    written = 0
    for f in data.files:
        target = _safe(f.path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(base64.b64decode(f.content_b64))
        written += 1
    removed = 0
    for rel in data.deleted:
        target = _safe(rel)          # 🔴 та же защита от выхода за пределы workspace
        if target.is_file():
            target.unlink()
            removed += 1
    return {"ok": True, "written": written, "removed": removed}


@app.post("/api/upload")
async def upload(file: UploadFile = File(...), dir: str = Form(""), user: str = Depends(require_auth)):
    """Загрузка файла в папку рабочей области (для DOS-команды `uploads`). dir — относительный путь."""
    name = os.path.basename(file.filename or "upload.bin")
    rel = (Path(dir) / name).as_posix() if dir else name
    dest = _safe(rel)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(await file.read())
    return {"ok": True, "path": dest.relative_to(_ws()).as_posix()}


# --- статика фронта (ПОСЛЕ /api/*, чтобы не перехватывать API) ---
if (FRONTEND / "vendor").is_dir():
    app.mount("/vendor", StaticFiles(directory=FRONTEND / "vendor"), name="vendor")
app.mount("/", StaticFiles(directory=FRONTEND, html=True), name="frontend")
