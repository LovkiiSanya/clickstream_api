import json
import logging
from datetime import datetime
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from main import app
from redis_helpers import redis_client as real_redis_client

client = TestClient(app)
GOOD_RESPONSE = 200


class MockRedis:
    """Mock Redis class to simulate Redis interactions."""
    def __init__(self):
        self.store = {}
        self.set = MagicMock()
        self.get = MagicMock()
        self.scan_iter = MagicMock()

    def set(self, key, value):
        self.store[key] = value

    def get(self, key):
        return self.store.get(key)

    def scan_iter(self, match):
        return (key for key in self.store if key.startswith(match))


@pytest.fixture
def mock_redis_fixture(monkeypatch):
    """Fixture to mock Redis interactions."""
    mock_redis_instance = MockRedis()

    monkeypatch.setattr(real_redis_client, 'set', mock_redis_instance.set)
    monkeypatch.setattr(real_redis_client, 'get', mock_redis_instance.get)
    monkeypatch.setattr(real_redis_client, 'scan_iter', mock_redis_instance.scan_iter)

    return mock_redis_instance


def log_event_details(event, expected_key, mock_redis_instance):
    """Log details of the event and the Redis calls for debugging."""
    logging.debug("Expected key: {}", expected_key)
    logging.debug("Event data: {}", json.dumps(event))
    logging.debug("Actual set calls: {}", mock_redis_instance.set.call_args_list)


def assert_event_stored(event, mock_redis_instance):
    """Assert that the event has been stored correctly in Redis."""
    event_time = event['event_time']
    timestamp = int(datetime.strptime(event_time, "%d/%m/%Y %H:%M:%S.%f").timestamp())
    session_id = event['session_id']
    expected_key = "event:{}:{}".format(timestamp, session_id)

    log_event_details(event, expected_key, mock_redis_instance)

    actual_calls = [call[0] for call in mock_redis_instance.set.call_args_list]
    assert any(
        key.startswith("event:{}:".format(timestamp)) and value == json.dumps(event)
        for key, value in actual_calls
    ), (
        "Expected key-value pair not found. "
        "Actual calls: {}".format(actual_calls)
    )


def test_full_flow(mock_redis_fixture):
    """Test the complete flow of generating and filtering events.

    Args:
        mock_redis_fixture (MockRedis): The mocked Redis instance.
    """
    response = client.get("/v1/clickstream-event/?num_events=2")
    assert response.status_code == GOOD_RESPONSE
    events = response.json()
    assert len(events) == 2

    for event in events:
        assert_event_stored(event, mock_redis_fixture)

    unique_id = events[0]['session_id']
    current_timestamp = int(datetime.utcnow().timestamp())
    mock_redis_fixture.scan_iter.return_value = [
        "event:{}:{}".format(current_timestamp, unique_id),
    ]
    mock_redis_fixture.get.return_value = json.dumps(events[0])

    user_agent = events[0]['user_agent']
    response = client.get(
        "/v1/clickstream-events/filters/?user_agent={}".format(user_agent),
    )
    assert response.status_code == GOOD_RESPONSE
    filtered_events = response.json()

    assert any(
        user_agent in event.get('user_agent', '') for event in filtered_events
    ), (
        "Filtered events do not contain user agent: {}. "
        "Found events: {}".format(user_agent, filtered_events)
    )
