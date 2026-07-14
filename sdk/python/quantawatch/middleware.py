"""Framework middleware for QuantaWatch.

Provides integration points for popular AI and web frameworks:

- **LangChain**: ``QuantaWatchLangChainCallback`` -- a callback handler that
  logs LangChain events to the QuantaWatch audit trail.
- **ASGI**: ``quantawatch_middleware`` -- wraps any ASGI application to proxy
  outbound AI requests through the gateway.

.. note::

   The LangChain callback handler requires the ``langchain`` optional
   dependency: ``pip install quantawatch[langchain]``
"""

from __future__ import annotations

from typing import Any, Callable, Awaitable


# ---------------------------------------------------------------------------
# LangChain callback handler (Phase 2 stub)
# ---------------------------------------------------------------------------

class QuantaWatchLangChainCallback:
    """LangChain callback handler that logs chain events to QuantaWatch.

    This handler integrates with LangChain's callback system to capture
    LLM calls, chain runs, tool invocations, and errors, forwarding them
    to the QuantaWatch admin API as audit entries.

    .. admonition:: Phase 2

       This class is a stub. A full implementation will be provided in a
       future release once the LangChain callback protocol is finalised.

    Parameters
    ----------
    admin_url:
        Base URL of the QuantaWatch admin API.
    session_id:
        Optional session ID to associate events with. If *None*, a new
        session will be created automatically.

    Example
    -------
    ::

        from langchain.chat_models import ChatAnthropic
        from quantawatch.middleware import QuantaWatchLangChainCallback

        handler = QuantaWatchLangChainCallback(admin_url="http://localhost:9091")
        llm = ChatAnthropic(callbacks=[handler])
        llm.invoke("Summarize this document.")
    """

    def __init__(
        self,
        admin_url: str = "http://localhost:9091",
        session_id: str | None = None,
    ) -> None:
        self.admin_url = admin_url.rstrip("/")
        self.session_id = session_id

    # -- LangChain callback protocol stubs -----------------------------------
    # These will be fully implemented in Phase 2.

    def on_llm_start(self, serialized: dict[str, Any], prompts: list[str], **kwargs: Any) -> None:
        """Called when an LLM call begins."""

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Called when an LLM call completes."""

    def on_llm_error(self, error: BaseException, **kwargs: Any) -> None:
        """Called when an LLM call raises an error."""

    def on_chain_start(self, serialized: dict[str, Any], inputs: dict[str, Any], **kwargs: Any) -> None:
        """Called when a chain run begins."""

    def on_chain_end(self, outputs: dict[str, Any], **kwargs: Any) -> None:
        """Called when a chain run completes."""

    def on_chain_error(self, error: BaseException, **kwargs: Any) -> None:
        """Called when a chain run raises an error."""

    def on_tool_start(self, serialized: dict[str, Any], input_str: str, **kwargs: Any) -> None:
        """Called when a tool invocation begins."""

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        """Called when a tool invocation completes."""

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        """Called when a tool invocation raises an error."""


# ---------------------------------------------------------------------------
# Generic ASGI middleware
# ---------------------------------------------------------------------------

# ASGI type aliases
Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class QuantaWatchASGIMiddleware:
    """ASGI middleware that routes outbound AI API calls through the QuantaWatch gateway.

    Wrap any ASGI application (FastAPI, Starlette, etc.) to ensure that all
    outbound HTTP requests made by the application to AI providers are
    automatically proxied through the gateway for auditing and threat
    detection.

    Parameters
    ----------
    app:
        The ASGI application to wrap.
    gateway_url:
        Base URL of the QuantaWatch gateway.
    admin_url:
        Base URL of the QuantaWatch admin API (used for health checks).

    Example
    -------
    ::

        from fastapi import FastAPI
        from quantawatch.middleware import quantawatch_middleware

        app = FastAPI()
        app = quantawatch_middleware(app, gateway_url="http://localhost:9090")
    """

    def __init__(
        self,
        app: ASGIApp,
        gateway_url: str = "http://localhost:9090",
        admin_url: str = "http://localhost:9091",
    ) -> None:
        self.app = app
        self.gateway_url = gateway_url.rstrip("/")
        self.admin_url = admin_url.rstrip("/")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """ASGI entry point.

        Currently passes requests through unchanged.  A future version
        will inject gateway-aware HTTP clients into the request state so
        that downstream route handlers automatically proxy AI calls.
        """
        # Store gateway config in scope for downstream access
        if scope["type"] in ("http", "websocket"):
            scope.setdefault("state", {})
            scope["state"]["quantawatch_gateway_url"] = self.gateway_url
            scope["state"]["quantawatch_admin_url"] = self.admin_url

        await self.app(scope, receive, send)


def quantawatch_middleware(
    app: ASGIApp,
    *,
    gateway_url: str = "http://localhost:9090",
    admin_url: str = "http://localhost:9091",
) -> QuantaWatchASGIMiddleware:
    """Wrap an ASGI application with QuantaWatch middleware.

    This is a convenience factory; it returns a
    :class:`QuantaWatchASGIMiddleware` instance.

    Parameters
    ----------
    app:
        The ASGI application to wrap.
    gateway_url:
        Base URL of the QuantaWatch gateway.
    admin_url:
        Base URL of the QuantaWatch admin API.

    Returns
    -------
    QuantaWatchASGIMiddleware
    """
    return QuantaWatchASGIMiddleware(app, gateway_url=gateway_url, admin_url=admin_url)
