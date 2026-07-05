"""Аутентификация CMS-DOS (🔴 красная зона): дефолт admin/admin, смена при первом входе, защита API.

Кейсы: нормальный вход, неверный пароль, защита эндпоинтов, поток смены пароля.
"""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DOSFM_WORKSPACE", str(tmp_path / "ws"))
    monkeypatch.setenv("CMSDOS_AUTH_FILE", str(tmp_path / "auth.json"))
    from app.main import app
    return TestClient(app)


def test_default_admin_login_requires_change(client):
    r = client.post("/api/login", json={"username": "admin", "password": "admin"})
    assert r.status_code == 200 and r.json()["must_change"] is True


def test_wrong_password_rejected(client):
    assert client.post("/api/login", json={"username": "admin", "password": "nope"}).status_code == 401


def test_api_protected_without_session(client):
    assert client.get("/api/tree").status_code == 401          # без логина — нельзя


def test_login_grants_access(client):
    client.post("/api/login", json={"username": "admin", "password": "admin"})
    assert client.get("/api/tree").status_code == 200


def test_password_too_short_rejected(client):
    client.post("/api/login", json={"username": "admin", "password": "admin"})
    assert client.post("/api/passwd", json={"new_password": "1234"}).status_code == 400   # < 8


def test_password_change_flow(client):
    client.post("/api/login", json={"username": "admin", "password": "admin"})
    # первый вход: смена без старого пароля
    assert client.post("/api/passwd", json={"new_password": "hunter2aa"}).status_code == 200
    client.post("/api/logout")
    # старый пароль больше не подходит
    assert client.post("/api/login", json={"username": "admin", "password": "admin"}).status_code == 401
    # новый — подходит, и must_change снят
    r = client.post("/api/login", json={"username": "admin", "password": "hunter2aa"})
    assert r.status_code == 200 and r.json()["must_change"] is False


def test_later_change_requires_old_password(client):
    client.post("/api/login", json={"username": "admin", "password": "admin"})
    client.post("/api/passwd", json={"new_password": "firstpass1"})     # снимает must_change
    # теперь смена без старого пароля — 401
    assert client.post("/api/passwd", json={"new_password": "secondpass2"}).status_code == 401
    # со старым — ок
    assert client.post("/api/passwd", json={"new_password": "secondpass2",
                                            "old_password": "firstpass1"}).status_code == 200


def test_login_rate_limited(client):
    for _ in range(5):
        client.post("/api/login", json={"username": "admin", "password": "wrong"})   # 5 неудач
    # 6-я попытка (даже с верным паролем) — заблокирована
    assert client.post("/api/login", json={"username": "admin", "password": "admin"}).status_code == 429
