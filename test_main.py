import json

import pytest
from fastapi.testclient import TestClient

from main import app
from redis_helpers import redis_client as real_redis_client

client = TestClient(app)
GOOD_RESPONSE = 200


class MockRedis:
    """Mock class for Redis client."""

    def __init__(self):
        """Initialize the mock Redis client with an empty store."""
        self.store = {}

    def set(self, key: str, value: str) -> None:
        """
        Mock Redis set method.

        Args:
            key (str): The key to set.
            value (str): The value to set.
        """
        self.store[key] = value

    def get(self, key: str) -> str:
        """
        Mock Redis get method.

        Args:
            key (str): The key to get.

        Returns:
            str: The value associated with the key, or None if not found.
        """
        return self.store.get(key)

    def scan_iter(self, match: str):
        """
        Mock Redis scan_iter method.

        Args:
            match (str): The pattern to match keys against.

        Returns:
            generator: A generator yielding keys that match the pattern.
        """
        return (key for key in self.store if key.startswith(match))


@pytest.fixture
def mock_redis_client(monkeypatch):
    """
    Fixture that mocks Redis client methods for testing.

    Args:
        monkeypatch: The monkeypatching fixture provided by pytest.

    Returns:
        MockRedis: An instance of MockRedis with mocked methods.
    """
    mock_redis = MockRedis()

    # Ensure redis_client is fully mocked
    monkeypatch.setattr(real_redis_client, 'set', mock_redis.set)
    monkeypatch.setattr(real_redis_client, 'get', mock_redis.get)
    monkeypatch.setattr(real_redis_client, 'scan_iter', mock_redis.scan_iter)

    return mock_redis


def test_generate_clickstream_data(mock_redis_client):
    """Test the /v1/clickstream-event/ endpoint."""
    response = client.get("/v1/clickstream-event/")
    assert response.status_code == GOOD_RESPONSE
    assert isinstance(response.json(), list)


def test_filter_events(mock_redis_client):
    """Test the /v1/clickstream-events/filters/ endpoint with a query parameter."""
    response = client.get("/v1/clickstream-events/filters/?query=smile")
    assert response.status_code == GOOD_RESPONSE
    assert isinstance(response.json(), list)


def test_get_data(mock_redis_client):
    """
    Test the /v1/get-data/{timestamp} endpoint with a stored event.

    Args:
        mock_redis_client:
         The fixture that mocks Redis client methods for testing.

    """
    timestamp = 1234567890
    event = {
        "ip": "65.240.35.245",
        "user_id": 865740,
        "user_agent": "Mozilla/5.0",
        "session_id": "session123",
        "event_time": "06/09/2024 11:04:23.692149",
        "event_name": "Search",
        "channel": "Referral",
        "metadata": {"query": "smile"},
    }

    # Store the event in mock Redis
    event_key = "event:{}".format(timestamp)
    mock_redis_client.set(event_key, json.dumps(event))

    # Call the endpoint
    url = "/v1/get-data/{timestamp}".format(timestamp=timestamp)
    response = client.get(url)

    # Assertions
    assert response.status_code == GOOD_RESPONSE
    assert response.json() == event
