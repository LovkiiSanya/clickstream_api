from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from chain_responsibility import  UserAgentHandler,IpHandler,QueryHandler
# Local imports (order them after standard and third-party)
from event_utils import (DEFAULT_DAYS, is_event_within_timeframe,
                         is_query_in_metadata)


def get_start_timestamp(last_hours: Optional[int]) -> int:
    """
    Calculate the start timestamp based on last_hours or default days.

    Args:
        last_hours (Optional[int]): Number of hours to look back.

    Returns:
        int: The calculated start timestamp in Unix format.
    """
    now = datetime.utcnow()
    if last_hours:
        delta = timedelta(hours=last_hours)
    else:
        delta = timedelta(days=DEFAULT_DAYS)

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
        event (dict): The event data to check.
        query (Optional[List[str]]): List of query strings to filter by.
            If None, no filtering by query is applied.
        ip (Optional[str]): IP address to filter by. If None, no filtering
            by IP is applied.
        user_agent (Optional[str]): User agent to filter by. If None, no
            filtering by user agent is applied.
        start_timestamp (int): Start timestamp to filter events that occur
            after this timestamp.

    Returns:
        bool: True if the event matches the filters, False otherwise.
    """

    # Chain of responsibility
    if event is None or not is_event_within_timeframe(event, start_timestamp):
        return False

    if query and not is_query_in_metadata(event, query):
        return False

    if ip and event.get("ip") != ip:
        return False

    if user_agent:
        user_agent_value = event.get("user_agent", "")
        if user_agent not in user_agent_value:
            return False

    return True


def apply_filters(
    events: List[Dict[str, Any]],
    ip: Optional[str],
    user_agent: Optional[str],
    query: Optional[str],
) -> List[Dict[str, Any]]:
    """
    Apply filters to a list of events based on optional criteria.

    Args:
        events (List[Dict]): A list of event dictionaries to filter.
        ip (Optional[str]): An optional IP address filter.
        user_agent (Optional[str]): An optional user agent filter.
        query (Optional[str]): An optional query filter.

    Returns:
        List[Dict]: A list of filtered event dictionaries.
    """
    # Set up the chain of responsibility
    user_agent_handler = UserAgentHandler()
    ip_handler = IpHandler()
    query_handler = QueryHandler()
    user_agent_handler.set_next(ip_handler).set_next(query_handler)

    # Apply the filters in the chain
    filtered_events = user_agent_handler.handle(events, user_agent)


    return filtered_events


