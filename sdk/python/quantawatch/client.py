"""QuantaWatch gateway client.

Provides an async client for interacting with both the QuantaWatch gateway
(proxying AI API requests) and the admin API (sessions, audit, stats).

Usage::

    async with QuantaWatchClient() as qw:
        # Proxy a request through the gateway
        resp = await qw.proxy_request("POST", "/v1/messages", headers, body)

        # Query the admin API
        sessions = await qw.get_sessions()
        stats = await qw.get_stats()
"""

from __future__ import annotations

from typing import Any

import httpx

from quantawatch.types import AuditEntry, GatewayStats, SessionInfo


class QuantaWatchClient:
    """Async client for the QuantaWatch security gateway.

    Parameters
    ----------
    gateway_url:
        Base URL of the QuantaWatch gateway proxy (default ``http://localhost:9090``).
    admin_url:
        Base URL of the QuantaWatch admin API (default ``http://localhost:9091``).
    timeout:
        Request timeout in seconds (default 30).
    """

    def __init__(
        self,
        gateway_url: str = "http://localhost:9090",
        admin_url: str = "http://localhost:9091",
        *,
        timeout: float = 30.0,
    ) -> None:
        self.gateway_url = gateway_url.rstrip("/")
        self.admin_url = admin_url.rstrip("/")
        self._client = httpx.AsyncClient(timeout=timeout)

    # -- Gateway proxy --------------------------------------------------------

    async def proxy_request(
        self,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> httpx.Response:
        """Proxy an HTTP request through the QuantaWatch gateway.

        The gateway will inspect the request for threats, log it to the
        audit trail, and forward it to the upstream AI provider.

        Parameters
        ----------
        method:
            HTTP method (GET, POST, etc.).
        path:
            Request path (e.g. ``/v1/messages``).
        headers:
            HTTP headers to forward. The ``Authorization`` header is typically
            required by the upstream provider.
        body:
            Raw request body bytes, or *None* for bodyless requests.

        Returns
        -------
        httpx.Response
            The upstream response, as received through the gateway.
        """
        url = f"{self.gateway_url}{path}"
        return await self._client.request(
            method,
            url,
            headers=headers or {},
            content=body,
        )

    # -- Admin API ------------------------------------------------------------

    async def get_sessions(self) -> list[SessionInfo]:
        """Fetch all sessions from the admin API.

        Returns
        -------
        list[SessionInfo]
            A list of current and historical gateway sessions.
        """
        resp = await self._client.get(f"{self.admin_url}/api/sessions")
        resp.raise_for_status()
        return [SessionInfo.model_validate(s) for s in resp.json()]

    async def get_audit_entries(self, limit: int = 100) -> list[AuditEntry]:
        """Fetch recent audit log entries.

        Parameters
        ----------
        limit:
            Maximum number of entries to return (default 100).

        Returns
        -------
        list[AuditEntry]
            Audit entries ordered by sequence number (most recent last).
        """
        resp = await self._client.get(
            f"{self.admin_url}/api/audit",
            params={"limit": limit},
        )
        resp.raise_for_status()
        return [AuditEntry.model_validate(e) for e in resp.json()]

    async def get_stats(self) -> GatewayStats:
        """Fetch aggregate gateway statistics.

        Returns
        -------
        GatewayStats
            Current gateway statistics (sessions, requests, threats, etc.).
        """
        resp = await self._client.get(f"{self.admin_url}/api/stats")
        resp.raise_for_status()
        return GatewayStats.model_validate(resp.json())

    async def verify_audit_chain(self) -> dict[str, Any]:
        """Verify the integrity of the cryptographic audit chain.

        The admin API checks that every audit entry's signature is valid
        and that the chain is unbroken from the first entry.

        Returns
        -------
        dict
            Verification result with keys like ``valid`` (bool),
            ``entries_checked`` (int), and ``errors`` (list).
        """
        resp = await self._client.get(f"{self.admin_url}/api/audit/verify")
        resp.raise_for_status()
        return resp.json()

    # -- Lifecycle ------------------------------------------------------------

    async def close(self) -> None:
        """Close the underlying HTTP client and release resources."""
        await self._client.aclose()

    async def __aenter__(self) -> "QuantaWatchClient":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        await self.close()
