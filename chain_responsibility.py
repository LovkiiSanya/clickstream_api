from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, List, Optional, Dict


class Handler(ABC):
    """
    The Handler interface declares a method for building the chain of handlers.
    It also declares a method for executing a request.
    """

    @abstractmethod
    def set_next(self, handler: Handler) -> Handler:
        pass

    @abstractmethod
    def handle(self, events: List[Dict[str, Any]], request: Any) -> List[Dict[str, Any]]:
        pass


class AbstractHandler(Handler):
    """
    The default chaining behavior can be implemented inside a base handler class.
    """

    _next_handler: Handler = None

    def set_next(self, handler: Handler) -> Handler:
        self._next_handler = handler
        return handler

    def handle(self, events: List[Dict[str, Any]], request: Any) -> List[Dict[str, Any]]:
        if self._next_handler:
            return self._next_handler.handle(events, request)
        return events


class UserAgentHandler(AbstractHandler):
    def handle(self, events: List[Dict[str, Any]], user_agent: Optional[str]) -> List[Dict[str, Any]]:
        if user_agent:
            events = [event for event in events if user_agent in event.get("user_agent", "")]
        return super().handle(events, user_agent)


class IpHandler(AbstractHandler):
    def handle(self, events: List[Dict[str, Any]], ip: Optional[str]) -> List[Dict[str, Any]]:
        if ip:
            events = [event for event in events if event.get("ip") == ip]
        return super().handle(events, ip)

class QueryHandler(AbstractHandler):
    def handle(self, events: list, query: Optional[str]) -> list:
        if query:
            return [event for event in events if query in event["metadata"]]
        else:
            return super().handle(events, query)

