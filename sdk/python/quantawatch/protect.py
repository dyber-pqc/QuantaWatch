"""Convenience wrapper that routes AI client HTTP traffic through the QuantaWatch gateway.

Usage::

    from anthropic import Anthropic
    from quantawatch import protect

    # All API calls now go through the QuantaWatch gateway
    client = protect(Anthropic(), gateway_url="http://localhost:9090")
    response = client.messages.create(...)

The wrapper is transparent: it preserves the original client's interface
so that existing code requires no changes beyond the ``protect()`` call.
"""

from __future__ import annotations

import copy
from typing import Any
from urllib.parse import urlparse

import httpx


_DEFAULT_GATEWAY_URL = "http://localhost:9090"


class _ProtectedTransport(httpx.BaseTransport):
    """Synchronous httpx transport that rewrites requests to the gateway."""

    def __init__(self, gateway_url: str, inner: httpx.BaseTransport) -> None:
        self._gateway_url = gateway_url.rstrip("/")
        self._inner = inner
        parsed = urlparse(self._gateway_url)
        self._gateway_host = parsed.hostname or "localhost"
        self._gateway_port = parsed.port
        self._gateway_scheme = parsed.scheme or "http"

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        # Rewrite the URL to point at the gateway, preserving path and query
        original_url = request.url
        new_url = original_url.copy_with(
            scheme=self._gateway_scheme,
            host=self._gateway_host,
            port=self._gateway_port,
        )
        request.url = new_url
        # Attach original host so the gateway knows which upstream to use
        request.headers["X-Original-Host"] = str(original_url.host)
        return self._inner.handle_request(request)


class _ProtectedAsyncTransport(httpx.AsyncBaseTransport):
    """Asynchronous httpx transport that rewrites requests to the gateway."""

    def __init__(self, gateway_url: str, inner: httpx.AsyncBaseTransport) -> None:
        self._gateway_url = gateway_url.rstrip("/")
        self._inner = inner
        parsed = urlparse(self._gateway_url)
        self._gateway_host = parsed.hostname or "localhost"
        self._gateway_port = parsed.port
        self._gateway_scheme = parsed.scheme or "http"

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        original_url = request.url
        new_url = original_url.copy_with(
            scheme=self._gateway_scheme,
            host=self._gateway_host,
            port=self._gateway_port,
        )
        request.url = new_url
        request.headers["X-Original-Host"] = str(original_url.host)
        return await self._inner.handle_async_request(request)


class _ProtectedClientProxy:
    """Transparent proxy that wraps an AI SDK client.

    Intercepts attribute access so that the wrapped client behaves identically
    to the original, but all HTTP traffic is routed through the gateway.
    """

    def __init__(self, wrapped: Any, gateway_url: str) -> None:
        # Store on the instance dict directly to avoid __getattr__ recursion
        object.__setattr__(self, "_wrapped", wrapped)
        object.__setattr__(self, "_gateway_url", gateway_url)
        object.__setattr__(self, "_patched", False)
        self._patch_http_client()

    def _patch_http_client(self) -> None:
        """Attempt to patch the underlying httpx client used by the AI SDK."""
        wrapped = object.__getattribute__(self, "_wrapped")
        gateway_url = object.__getattribute__(self, "_gateway_url")

        # Anthropic SDK exposes _client (an httpx.Client or httpx.AsyncClient)
        # OpenAI SDK similarly uses _client
        for attr_name in ("_client", "http_client", "_http_client"):
            http_client = getattr(wrapped, attr_name, None)
            if http_client is None:
                continue

            if isinstance(http_client, httpx.Client):
                original_transport = http_client._transport
                http_client._transport = _ProtectedTransport(gateway_url, original_transport)
                object.__setattr__(self, "_patched", True)
                return

            if isinstance(http_client, httpx.AsyncClient):
                original_transport = http_client._transport
                http_client._transport = _ProtectedAsyncTransport(gateway_url, original_transport)
                object.__setattr__(self, "_patched", True)
                return

        # If we could not find an httpx client, the proxy still works --
        # attribute access is forwarded unchanged. The user can manually
        # configure their HTTP client to use the gateway.

    def __getattr__(self, name: str) -> Any:
        wrapped = object.__getattribute__(self, "_wrapped")
        return getattr(wrapped, name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name.startswith("_"):
            object.__setattr__(self, name, value)
        else:
            setattr(object.__getattribute__(self, "_wrapped"), name, value)

    def __repr__(self) -> str:
        wrapped = object.__getattribute__(self, "_wrapped")
        gateway_url = object.__getattribute__(self, "_gateway_url")
        patched = object.__getattribute__(self, "_patched")
        status = "active" if patched else "passthrough"
        return f"<QuantaWatch-protected {type(wrapped).__name__} via {gateway_url} [{status}]>"


def protect(
    client: Any,
    *,
    gateway_url: str = _DEFAULT_GATEWAY_URL,
) -> Any:
    """Wrap an AI SDK client so its HTTP traffic flows through the QuantaWatch gateway.

    This is the simplest integration path: wrap your existing Anthropic, OpenAI,
    or other httpx-based client and all requests are automatically proxied
    through the gateway for threat detection and audit logging.

    Parameters
    ----------
    client:
        An AI SDK client instance (e.g. ``anthropic.Anthropic()``,
        ``openai.OpenAI()``, or any object whose HTTP calls should be proxied).
    gateway_url:
        URL of the QuantaWatch gateway (default ``http://localhost:9090``).

    Returns
    -------
    A proxy object that behaves identically to *client* but routes HTTP
    traffic through the gateway.

    Examples
    --------
    ::

        from anthropic import Anthropic
        from quantawatch import protect

        client = protect(Anthropic(), gateway_url="http://localhost:9090")
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": "Hello!"}],
        )
    """
    return _ProtectedClientProxy(client, gateway_url)
