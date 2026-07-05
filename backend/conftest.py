import pytest


@pytest.fixture(autouse=True)
def _clear_ratelimit():
    """Rate-limit — глобальный in-memory; чистим перед каждым тестом, чтобы не мешал соседним."""
    from app import ratelimit
    ratelimit._events.clear()
    yield
