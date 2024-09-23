import json
import logging
import random
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

from faker import Faker
from faker_clickstream import ClickstreamProvider

# Setup logging
logger = logging.getLogger(__name__)

# Initialize Faker
fake = Faker()
fake.add_provider(ClickstreamProvider)

DEFAULT_DAYS = 30
MIN_USER_ID = 100000
MAX_USER_ID = 999999


# Constants
IP_KEY = "ip"
METADATA_KEY = "metadata"


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
        unique_sessions (set):
        A set of unique session IDs to ensure no duplicates.
        config (EventConfig):
        The configuration containing optional IP, user agent,
            and query filters.

    Returns:
        dict: A dictionary representing the generated event with unique IDs
            and applied filters.
    """

    if not config.ip:
        while session[IP_KEY] in unique_ips:
            session[IP_KEY] = fake.ipv4_public()
        unique_ips.add(session[IP_KEY])

    session['user_id'] = random.randint(MIN_USER_ID, MAX_USER_ID)
    session['user_agent'] = config.user_agent or fake.user_agent()

    if METADATA_KEY not in session:
        session[METADATA_KEY] = {}
    session[METADATA_KEY]['query'] = config.query or fake.word()

    session['event_time'] = datetime.utcnow().strftime("%d/%m/%Y %H:%M:%S.%f")

    return session


def is_query_in_metadata(event: dict, query_list: List[str]) -> bool:
    """
    Checks if any term in the query list is present in the metadata query.

    Args:
        event (dict): The event data to evaluate.
        query_list (list): List of query terms.

    Returns:
        bool: True if any of the query terms are in the metadata query,
        False otherwise.
    """
    metadata_query = event.get('metadata', {}).get('query', '')
    return any(que in metadata_query for que in query_list)


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

