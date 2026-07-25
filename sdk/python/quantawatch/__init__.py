"""QuantaWatch Python SDK -- AI agent security gateway client.

Quickstart::

    from quantawatch import QuantaWatchClient, protect

    # Option 1: Direct gateway client
    async with QuantaWatchClient() as qw:
        sessions = await qw.get_sessions()
        stats = await qw.get_stats()

    # Option 2: Wrap an existing AI client
    from anthropic import Anthropic
    client = protect(Anthropic(), gateway_url="http://localhost:9090")
"""

from quantawatch.client import QuantaWatchClient
from quantawatch.protect import protect
from quantawatch.types import (
    AuditEntry,
    DetectedThreat,
    GatewayStats,
    SessionInfo,
    ThreatAssessment,
)

__version__ = "0.1.3"

__all__ = [
    "QuantaWatchClient",
    "protect",
    "AuditEntry",
    "DetectedThreat",
    "GatewayStats",
    "SessionInfo",
    "ThreatAssessment",
]
