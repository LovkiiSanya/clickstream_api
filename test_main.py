import json

import pytest
from fastapi.testclient import TestClient

from main import app
from main import redis_client as redis

client = TestClient(app)


@pytest.fixture
def mock_redis(monkeypatch):
    class MockRedis:
        def __init__(self):
            self.store = {}

        def set(self, key, value):
            self.store[key] = value

        def get(self, key):
            return self.store.get(key)

        def scan_iter(self, match):
            return (key for key in self.store if key.startswith(match))

    mock_redis = MockRedis()
    monkeypatch.setattr(redis, 'set', mock_redis.set)
    monkeypatch.setattr(redis, 'get', mock_redis.get)
    monkeypatch.setattr(redis, 'scan_iter', mock_redis.scan_iter)
    return mock_redis


def test_generate_clickstream_data(mock_redis):
    response = client.get("/v1/clickstream-event/")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_filter_events(mock_redis):
    response = client.get("/v1/filter-events/?query=smile")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_get_data(mock_redis):
    timestamp = 1234567890
    event = {
        "ip": "65.240.35.245",
        "user_id": 865740,
        "user_agent": "Mozilla/5.0",
        "session_id": "session123",
        "event_time": "06/09/2024 11:04:23.692149",
        "event_name": "Search",
        "channel": "Referral",
        "metadata": {"query": "smile"}
    }

    # Store the event in mock Redis
    mock_redis.set(f"event:{timestamp}", json.dumps(event))

    # Call the endpoint
    response = client.get(f"/v1/get-data/{timestamp}")

    # Debug print
    print(response.json())

    # Assertions
    assert response.status_code == 200
    assert response.json() == event


def test_read_root():
    response = client.get("/v1/")
    assert response.status_code == 200
    assert response.json() == {"message": "Welcome to ClickStream API v1"}

