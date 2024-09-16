import json
import logging
import random
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional

import redis
from faker import Faker
from faker_clickstream import ClickstreamProvider
from fastapi import APIRouter, FastAPI, Query
from pydantic import BaseModel

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Connect to Redis
REDIS_HOST = "redis"
REDIS_PORT = 6379

redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)


# Initialize FastAPI app and Faker
app = FastAPI()
fake = Faker()
fake.add_provider(ClickstreamProvider)

# Initialize API Router
router = APIRouter()

DEFAULT_DAYS = 30
DEFAULT_NUM_EVENTS = 5
MIN_USER_ID = 100000
MAX_USER_ID = 999999


# Models
class EventData(BaseModel):
    event_type: str


class ClickstreamEventFilter(BaseModel):
    num_events: int = Query(5, gt=0)  # Default 5, must be > 0
    ip: Optional[str] = None
    user_agent: Optional[str] = None
    query: Optional[str] = None


@dataclass
class EventConfig:
    ip: Optional[str]
    user_agent: Optional[str]
    query: Optional[str]


def generate_event(
    session: dict,
    unique_ips: set,
    unique_sessions: set,
    config: EventConfig,
) -> dict:
    """
    Generates a single event with unique IDs and applies optional filters.

    Args:
        session (dict): The session data containing event details.
        unique_ips (set): A set of unique IPs to ensure no duplicates.
        unique_sessions (set): A set of unique session IDs to ensure no
            duplicates.
        config (EventConfig): Configuration object containing optional filters
            for IP, user agent, and query.

    Returns:
        dict: A dictionary representing the generated event with unique IDs
            and applied filters.
    """

    ip = config.ip
    user_agent = config.user_agent
    query = config.query

    # Ensure unique IP (if no filter was provided)
    if not ip:
        while session['ip'] in unique_ips:
            session['ip'] = fake.ipv4_public()
        unique_ips.add(session['ip'])

    session['user_id'] = random.randint(MIN_USER_ID, MAX_USER_ID)
    session['user_agent'] = user_agent if user_agent else fake.user_agent()

    # Ensure metadata['query'] exists before accessing or modifying it
    if 'metadata' not in session:
        session['metadata'] = {}
    session['metadata']['query'] = query if query else fake.word()

    # Format event_time
    session['event_time'] = datetime.utcnow().strftime("%d/%m/%Y %H:%M:%S.%f")

    return session


def apply_filters(
    events: List[dict],
    ip: Optional[str],
    user_agent: Optional[str],
    query: Optional[str],
) -> List[dict]:
    """
    Apply filters to a list of events based on optional criteria.

    Args:
        events (List[dict]): A list of event dictionaries to filter.
        ip (Optional[str]): An optional IP address filter.
        user_agent (Optional[str]): An optional user agent filter.
        query (Optional[str]): An optional query filter.

    Returns:
        List[dict]: A list of filtered event dictionaries.
    """
    if ip:
        events = [
            event
            for event in events
            if event["ip"] == ip
        ]

    if user_agent:
        events = [
            event
            for event in events
            if user_agent in event["user_agent"]
        ]

    if query:
        events = [
            event
            for event in events
            if (
                is_query_in_metadata(event, query)
            )
        ]

    return events


def is_query_in_metadata(event: dict, query: str) -> bool:
    """
    Check if the query is in the event's metadata.

    Args:
        event (dict): The event dictionary.
        query (str): The query to check for.

    Returns:
        bool: True if the query is in the metadata, False otherwise.
    """
    metadata = event.get("metadata", {})
    query_in_metadata = "query" in metadata
    query_exists = query in metadata.get("query", "")

    return query_in_metadata and query_exists


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


def is_valid_event(event: dict) -> bool:
    """
    Check if the event contains a valid 'event_time' field.

    Args:
        event (dict): The event dictionary to validate.

    Returns:
        bool: True if the event is valid, False otherwise.
    """
    if event.get('event_time') is None:
        logger.error("Missing 'event_time' in event data.")
        return False
    return True


def parse_event_time(event_time_str: str) -> Optional[datetime]:
    """
    Parse event time string to datetime object.

    Args:
        event_time_str (str): The event time string to parse.

    Returns:
        Optional[datetime]: Parsed datetime object or None if parsing fails.
    """
    try:
        return datetime.strptime(event_time_str, "%d/%m/%Y %H:%M:%S.%f")
    except ValueError as err:
        logger.error("Error processing event time: {0}".format(err))
        return None


def generate_key_for_event(event_time: datetime) -> str:
    """
    Generate a unique Redis key for the event.

    Args:
        event_time (datetime): The datetime object for the event.

    Returns:
        str: The generated Redis key.
    """
    timestamp = int(event_time.timestamp())
    unique_id = str(uuid.uuid4())
    return "event:{0}:{1}".format(timestamp, unique_id)


def serialize_event(event: dict) -> Optional[str]:
    """
    Serialize event data to JSON.

    Args:
        event (dict): The event dictionary to serialize.

    Returns:
        Optional[str]: JSON string or None if serialization fails.
    """
    try:
        return json.dumps(event)
    except json.JSONDecodeError as err:
        logger.error("Error serializing event data: {0}".format(err))
        return None


def store_in_redis(key: str, value: str) -> None:
    """
    Store the serialized event in Redis.

    Args:
        key (str): The Redis key.
        value (str): The serialized event data.
    """
    redis_client.set(key, value)
    logger.info("Stored event in Redis: {0}".format(key))


@app.get("/v1/clickstream-event/")
def generate_clickstream_data(
    num_events: Optional[int] = None,
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
        List[dict]: A list of dictionaries, each representing
         a clickstream event.
    """

    # Apply Query() inside the function body for num_events
    num_events = num_events or Query(DEFAULT_NUM_EVENTS, gt=0)

    events = []
    unique_data = {
        "ips": set(),
        "sessions": set(),
    }

    while len(events) < num_events:
        session = fake.session_clickstream(rand_session_max_size=num_events)

        for event in session:
            event = generate_event(
                event,
                unique_data["ips"],
                unique_data["sessions"],
                ip,
                user_agent,
                query,
            )

            events.append(event)
            logger.info("Generated Clickstream data: {}".format(events))

            if len(events) >= num_events:
                break

    events = apply_filters(events, ip, user_agent, query)
    store_events_in_redis(events)

    # Log filtered result
    logger.info("Generated Clickstream data: {}".format(events))
    return events


def query_not_in_metadata(query_list, metadata_query):
    """
    Checks if any term in the query list is not present in the metadata query.

    Args:
        query_list (list): List of query terms.
        metadata_query (str): The metadata query to check against.

    Returns:
        bool: True if none of the query terms are in the metadata query,
              False otherwise.
    """
    return not any(que in metadata_query for que in query_list)


def fetch_event_data(key: str) -> Optional[str]:
    """
    Fetch the event data from Redis.

    Args:
        key (str): The Redis key for the event.

    Returns:
        Optional[str]: The raw event data as a
         string or None if an error occurs.
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


def is_valid_event_time(event: dict, start_timestamp: int) -> bool:
    """
    Checks if the event time is within the time window.

    Args:
        event (dict): The event dictionary containing event time.
        start_timestamp (int): The starting timestamp to compare against.

    Returns:
        bool: True if the event is within the time window, False otherwise.
    """
    event_time_str = event['event_time']
    event_time = datetime.strptime(event_time_str, "%d/%m/%Y %H:%M:%S.%f")
    event_timestamp = int(event_time.timestamp())

    return event_timestamp >= start_timestamp


@app.get("/v1/filter-events/")
def filter_events(
    query: Optional[List[str]],
    last_hours: Optional[int],
    ip: Optional[str],
    user_agent: Optional[str],
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
        event = parse_redis_event_data(key)
        if should_include_event(event, query, ip, user_agent, start_timestamp):
            filtered_events.append(event)

    return filtered_events


def get_start_timestamp(last_hours: Optional[int]) -> int:
    """
    Calculate the start timestamp based on last_hours or default days.

    Args:
        last_hours (Optional[int]): Number of hours to look back.

    Returns:
        int: The calculated start timestamp in Unix format.
    """
    now = datetime.utcnow()
    delta = timedelta(hours=last_hours) if last_hours \
        else timedelta(days=DEFAULT_DAYS)
    start_time = now - delta
    return int(start_time.timestamp())


def should_include_event(
    event: dict,
    query: Optional[List[str]],
    ip: Optional[str],
    user_agent: Optional[str],
    start_timestamp: int,
) -> bool:
    """
    Determine if the event should be included based on filters.

    Args:
        event (dict): The event data to evaluate.
        query (Optional[List[str]]): List of query terms for filtering.
        ip (Optional[str]): IP filter.
        user_agent (Optional[str]): User agent filter.
        start_timestamp (int): The start timestamp for time-based filtering.

    Returns:
        bool: True if the event should be included, False otherwise.
    """
    if event is None or not is_event_within_timeframe(event, start_timestamp):
        return False

    metadata_query = event.get('metadata', {}).get('query', '')

    if query and query_not_in_metadata(query, metadata_query):
        return False

    if ip and event.get("ip") != ip:
        return False

    if user_agent:
        user_agent_value = event.get("user_agent", "")
        if user_agent not in user_agent_value:
            return False

    return True


def is_event_within_timeframe(event: dict, start_timestamp: int) -> bool:
    """
    Check if the event time is valid based on the start timestamp.

    Args:
        event (dict): The event to check.
        start_timestamp (int): The start timestamp for filtering.

    Returns:
        bool: True if the event timestamp is valid, False otherwise.
    """
    event_time_str = event.get('event_time')
    if not event_time_str:
        return False

    event_time = datetime.strptime(event_time_str, "%d/%m/%Y %H:%M:%S.%f")
    return int(event_time.timestamp()) >= start_timestamp


def parse_redis_event_data(key: str) -> Optional[dict]:
    """
    Parse the event data from Redis.

    Args:
        key (str): The Redis key to fetch.

    Returns:
        Optional[dict]: The parsed event data, or None if an error occurs.
    """
    event_data = redis_client.get(key)
    if not event_data:
        logger.error("No event data found for key: {}".format(key))
        return None

    return parse_event_json(event_data)


def parse_event_json(event_data: str) -> Optional[dict]:
    """
    Parse the JSON data for an event.

    Args:
        event_data (str): The event data in JSON format.

    Returns:
        Optional[dict]: The parsed event data as a dictionary,
        or None if an error occurs.
    """
    try:
        return json.loads(event_data)
    except (ValueError, json.JSONDecodeError) as err:
        logger.error("Error parsing event JSON: {}".format(err))
        return None


# Get data from Redis by timestamp
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
    key = "event:{}".format(timestamp)  # Using format method
    data = redis_client.get(key)

    if data:
        logger.info("Data retrieved: {}".format(data))
        return json.loads(data)

    # Split the long line to respect the 79-character limit
    logger.warning(
        "Data not found for timestamp: {}".format(timestamp),
    )
    return {"error": "Data not found"}


# Welcome message endpoint
@app.get("/v1/")
def read_root():
    """
    Returns a friendly welcome message. :)

    Returns:
        dict: A dictionary containing the welcome message.
    """
    return {"message": "Welcome to ClickStream API v1"}


# Register the router
app.include_router(router)
