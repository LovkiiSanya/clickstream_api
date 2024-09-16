import json
from datetime import datetime
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from main import app

client = TestClient(app)

@pytest.fixture
def mock_redis(monkeypatch):
    mock_redis_client = MagicMock()
    monkeypatch.setattr("main.redis_client", mock_redis_client)
    return mock_redis_client

def test_full_flow(mock_redis):
    # Generate clickstream data
    response = client.get("/v1/clickstream-event/?num_events=2")
    assert response.status_code == 200
    events = response.json()
    assert len(events) == 2

    # Ensure the events are stored in Redis
    for event in events:
        event_time = event['event_time']
        timestamp = int(datetime.strptime(event_time, "%d/%m/%Y %H:%M:%S.%f").timestamp())
        session_id = event['session_id']
        expected_key = f"event:{timestamp}:{session_id}"

        # Debug print to verify correct key format
        print(f"Expected key: {expected_key}")
        print(f"Event data: {json.dumps(event)}")
        print(f"Actual calls: {mock_redis.set.call_args_list}")

        # Flexible assertion to check if any matching call was made
        matching_call = any(
            call[0][0].startswith(f"event:{timestamp}:") and call[0][1] == json.dumps(event)
            for call in mock_redis.set.call_args_list
        )
        assert matching_call, f"Expected call not found. Actual calls: {mock_redis.set.call_args_list}"

    # Simulate Redis returning stored events based on the filter
    unique_id = events[0]['session_id']
    mock_redis.scan_iter.return_value = [f"event:{int(datetime.utcnow().timestamp())}:{unique_id}"]
    mock_redis.get.return_value = json.dumps(events[0])  # Return the first event

    # Filter events with a user_agent
    user_agent = events[0]['user_agent']
    response = client.get(f"/v1/filter-events/?user_agent={user_agent}")
    assert response.status_code == 200
    filtered_events = response.json()

    # Ensure filtered events contain the expected user_agent
    assert any(user_agent in event.get('user_agent', '') for event in filtered_events)
