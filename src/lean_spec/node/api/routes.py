"""API route definitions."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import NamedTuple

from aiohttp import web

from lean_spec.node.api.handlers import ApiHandlers

Handler = Callable[[web.Request], Awaitable[web.Response]]
"""Request handler already bound to its dependencies."""


class Route(NamedTuple):
    """One API route: its verb, path, and handler."""

    method: str
    """HTTP verb the route responds to."""

    path: str
    """URL path the route is registered under."""

    handler: Handler
    """Coroutine that serves requests to this route."""


def build_routes(handlers: ApiHandlers) -> list[Route]:
    """Bind every API route to its handler method."""
    return [
        Route("GET", "/lean/v0/health", handlers.health),
        Route("GET", "/lean/v0/states/finalized", handlers.finalized_state),
        Route("GET", "/lean/v0/checkpoints/justified", handlers.justified_checkpoint),
        Route("GET", "/lean/v0/fork_choice", handlers.fork_choice),
        Route("GET", "/metrics", handlers.metrics),
        Route("GET", "/lean/v0/admin/aggregator", handlers.aggregator_status),
        Route("POST", "/lean/v0/admin/aggregator", handlers.aggregator_toggle),
    ]
