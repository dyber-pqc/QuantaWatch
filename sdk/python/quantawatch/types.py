"""Pydantic models for the QuantaWatch SDK.

These models correspond to the JSON schemas returned by the QuantaWatch
gateway and admin APIs.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SessionInfo(BaseModel):
    """Represents an active or historical gateway session."""

    session_id: str = Field(description="Unique identifier for the session")
    agent_name: str = Field(description="Name of the AI agent that owns the session")
    created_at: datetime = Field(description="When the session was created")
    expires_at: datetime = Field(description="When the session expires")
    request_count: int = Field(
        default=0, description="Number of requests made in this session"
    )
    total_tokens: int = Field(
        default=0, description="Total tokens consumed in this session"
    )
    public_key_fingerprint: str = Field(
        default="", description="Fingerprint of the public key used to create the session"
    )


class DetectedThreat(BaseModel):
    """A single threat detected by the gateway's threat analysis engine."""

    category: str = Field(description="Threat category (e.g. prompt_injection, data_exfil)")
    severity: str = Field(description="Severity level: low, medium, high, critical")
    pattern_name: str = Field(description="Name of the detection pattern that matched")
    confidence: float = Field(
        ge=0.0, le=1.0, description="Confidence score between 0 and 1"
    )
    description: str = Field(description="Human-readable description of the threat")


class ThreatAssessment(BaseModel):
    """Result of running threat analysis on a request or response."""

    threats: list[DetectedThreat] = Field(
        default_factory=list, description="List of detected threats"
    )
    overall_severity: str = Field(
        default="none",
        description="Highest severity among all detected threats, or 'none'",
    )
    blocked: bool = Field(
        default=False, description="Whether the request was blocked by the gateway"
    )


class AuditEntry(BaseModel):
    """A single entry in the cryptographic audit log."""

    sequence: int = Field(description="Monotonically increasing sequence number")
    timestamp: datetime = Field(description="When the event occurred")
    event_type: str = Field(
        description="Type of event (e.g. session_created, request_proxied, threat_detected)"
    )
    session_id: str = Field(description="Session this event belongs to")
    details: dict[str, Any] = Field(
        default_factory=dict, description="Arbitrary event-specific metadata"
    )
    signature: str = Field(
        default="", description="Cryptographic signature chaining this entry to the previous one"
    )


class GatewayStats(BaseModel):
    """Aggregate statistics from the QuantaWatch gateway."""

    total_sessions: int = Field(default=0, description="Total sessions created since startup")
    active_sessions: int = Field(default=0, description="Currently active sessions")
    total_requests: int = Field(default=0, description="Total requests proxied")
    total_audit_entries: int = Field(default=0, description="Total audit log entries")
    active_threats: int = Field(default=0, description="Currently active/unresolved threats")
