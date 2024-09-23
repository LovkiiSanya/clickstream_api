import json
import logging
from typing import List, Optional

import redis

from event_utils import (generate_key_for_event, is_valid_event,
                         parse_event_time, serialize_event)

# Setup logging
logger = logging.getLogger(__name__)

# Connect to Redis
REDIS_HOST = "redis"
REDIS_PORT = 6379


redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)


def store_events_in_redis(events: List[dict]) -> None:
    """
    Store a list of events in Redis.

    Args:
        events (List[dict]): A list of event dictionaries to store in Redis.
    """
    for event in events:
        if not is_valid_event(event):
            continue

        event_time = parse_event_time(event['event_time'])
        if event_time is None:
            continue

        key = generate_key_for_event(event_time)
        value = serialize_event(event)
        if value is not None:
            store_in_redis(key, value)


def fetch_event_data(key: str) -> Optional[str]:
    """
    Fetch the event data from Redis.

    Args:
        key (str): The Redis key for the event.

    Returns:
        Optional[str]:
        The raw event data as a string or None if an error occurs.
    """
    try:
        return redis_client.get(key)
    except Exception as err:
        logger.error("Error fetching event data from Redis: {}".format(err))
        return None


def parse_event_data(key: str) -> Optional[dict]:
    """
    Retrieve and parse event data from Redis by key.

    Args:
        key (str): The Redis key for the event.

    Returns:
        Optional[dict]: The parsed event data or None if parsing fails.
    """
    event_data = fetch_event_data(key)
    if event_data is None:
        return None

    try:
        return json.loads(event_data)
    except (ValueError, json.JSONDecodeError) as err:
        logger.error("Error parsing event JSON: {}".format(err))
        return None


def store_in_redis(key: str, value: str) -> None:
    """
    Store the serialized event in Redis.

    Args:
        key (str): The Redis key.
        value (str): The serialized event data.
    """
    redis_client.set(key, value)
    logger.info("Stored event in Redis: {}".format(key))
