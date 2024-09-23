import json
import logging
from typing import List, Optional

from fastapi import FastAPI, Query
from pydantic import BaseModel

from event_utils import EventConfig, fake, generate_event
from filters import apply_filters, get_start_timestamp, should_include_event
from redis_helpers import parse_event_data, redis_client, store_events_in_redis

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI()


# Models
class ClickstreamEventFilter(BaseModel):
    num_events: int = Query(5, gt=0)  # Default 5, must be > 0
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    query: Optional[str] = None


DEFAULT_NUM_EVENTS = 5


@app.get("/v1/clickstream-event/")
def generate_clickstream_data(
    num_events: Optional[int] = DEFAULT_NUM_EVENTS,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    query: Optional[str] = None,
) -> List[dict]:
    """
    Generates a specified number of clickstream events with optional filters.

    Args:
        num_events (int): The number of events to generate. Defaults to 5.
        ip (Optional[str]): An optional IP address filter.
        user_agent (Optional[str]): An optional user agent filter.
        query (Optional[str]): An optional query filter.

    Returns:
        List[dict]: A list of dictionaries,
        each representing a clickstream event.
    """
    num_events = num_events or DEFAULT_NUM_EVENTS
    events = []
    unique_data = {"ips": set(), "sessions": set()}
    config = EventConfig(ip=ip, user_agent=user_agent, query=query)
    while len(events) < num_events:
        session = fake.session_clickstream(rand_session_max_size=num_events)

        for event in session:
            event = generate_event(
                session=event,
                unique_ips=unique_data["ips"],
                unique_sessions=unique_data["sessions"],
                config=config,
            )

            events.append(event)
            logger.info("Generated Clickstream data: {}".format(events))

            if len(events) >= num_events:
                break

    events = apply_filters(events, ip, user_agent, query)
    store_events_in_redis(events)

    logger.info("Generated Clickstream data: {}".format(events))
    return events


@app.get("/v1/clickstream-events/filters/")
def filter_events(
    query: Optional[List[str]] = Query(None),
    last_hours: Optional[int] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> List[dict]:
    """
    Filter events based on query, IP, user agent, and a time window.

    Args:
        query (Optional[List[str]]): List of query terms for filtering.
        last_hours (Optional[int]): Number of hours to look back for events.
        ip (Optional[str]): An optional IP address filter.
        user_agent (Optional[str]): An optional user agent filter.

    Returns:
        List[dict]: A list of filtered event dictionaries.
    """
    start_timestamp = get_start_timestamp(last_hours)
    filtered_events = []

    for key in redis_client.scan_iter(match="event:*"):
        event = parse_event_data(key)
        if should_include_event(event, query, ip, user_agent, start_timestamp):
            filtered_events.append(event)

    return filtered_events


@app.get("/v1/get-data/{timestamp}")
def get_data(timestamp: int) -> dict:
    """
    Retrieves event data from Redis using the provided timestamp.

    Args:
        timestamp (int): The timestamp representing the event time.

    Returns:
        dict: A dictionary containing the event data if found,
              or an error message if no data is found for the given timestamp.
    """
    key = "event:{}".format(timestamp)
    data = redis_client.get(key)

    if data:
        logger.info("Data retrieved: {}".format(data))
        return json.loads(data)

    logger.warning("Data not found for timestamp: {}".format(timestamp))
    return {"error": "Data not found"}

