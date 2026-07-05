"""API рабочей папки: дерево/скачивание/синхронизация + защита от выхода за пределы (path traversal).

Что и почему:
- tree/download/sync — нормальные кейсы (менеджер видит файлы, качает, сохраняет).
- 🔴 path traversal — граничный/безопасность: `..`/абсолютный путь НЕ должны писать/читать вне workspace.
"""
import base64

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setenv("DOSFM_WORKSPACE", str(ws))              # рабочая папка = временная
    monkeypatch.setenv("CMSDOS_AUTH_FILE", str(tmp_path / "auth.json"))  # свежие креды admin/admin
    from app.main import app
    c = TestClient(app)
    c.post("/api/login", json={"username": "admin", "password": "admin"})  # API теперь под auth
    return c, ws


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def test_tree_lists_files(client):
    c, ws = client
    (ws / "hello.txt").write_text("hi")
    (ws / "sub").mkdir()
    (ws / "sub" / "a.bat").write_text("echo")
    paths = {e["path"] for e in c.get("/api/tree").json()}
    assert "hello.txt" in paths and "sub/a.bat" in paths


def test_download_returns_content(client):
    c, ws = client
    (ws / "readme.txt").write_bytes(b"DOS content")
    r = c.get("/api/download", params={"path": "readme.txt"})
    assert r.status_code == 200 and r.content == b"DOS content"


def test_sync_writes_files(client):
    c, ws = client
    payload = {"files": [{"path": "new/data.txt", "content_b64": _b64(b"xyz")}]}
    assert c.post("/api/sync", json=payload).status_code == 200
    assert (ws / "new" / "data.txt").read_bytes() == b"xyz"


def test_download_traversal_blocked(client):
    c, _ = client
    assert c.get("/api/download", params={"path": "../secret"}).status_code == 400


def test_sync_traversal_blocked(client):
    c, ws = client
    payload = {"files": [{"path": "../evil.txt", "content_b64": _b64(b"x")}]}
    assert c.post("/api/sync", json=payload).status_code == 400
    assert not (ws.parent / "evil.txt").exists()          # ничего не записалось вне workspace


def test_sync_deletes_files(client):
    c, ws = client
    (ws / "gone.txt").write_text("bye")
    r = c.post("/api/sync", json={"deleted": ["gone.txt"]})
    assert r.status_code == 200 and r.json()["removed"] == 1
    assert not (ws / "gone.txt").exists()


def test_sync_delete_traversal_blocked(client):
    c, ws = client
    secret = ws.parent / "secret.txt"
    secret.write_text("keep")
    assert c.post("/api/sync", json={"deleted": ["../secret.txt"]}).status_code == 400
    assert secret.exists()                                # чужой файл не тронут
