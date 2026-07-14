"""Tests for the QuantaWatch Python SDK."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from quantawatch import (
    AuditEntry,
    DetectedThreat,
    GatewayStats,
    QuantaWatchClient,
    SessionInfo,
    ThreatAssessment,
    protect,
)


# ---------------------------------------------------------------------------
# Client initialisation
# ---------------------------------------------------------------------------


class TestClientInit:
    """Tests for QuantaWatchClient construction."""

    def test_default_urls(self) -> None:
        client = QuantaWatchClient()
        assert client.gateway_url == "http://localhost:9090"
        assert client.admin_url == "http://localhost:9091"

    def test_custom_urls(self) -> None:
        client = QuantaWatchClient(
            gateway_url="http://gateway:8080",
            admin_url="http://admin:8081",
        )
        assert client.gateway_url == "http://gateway:8080"
        assert client.admin_url == "http://admin:8081"

    def test_trailing_slashes_stripped(self) -> None:
        client = QuantaWatchClient(
            gateway_url="http://localhost:9090/",
            admin_url="http://localhost:9091/",
        )
        assert client.gateway_url == "http://localhost:9090"
        assert client.admin_url == "http://localhost:9091"

    def test_has_httpx_client(self) -> None:
        import httpx

        client = QuantaWatchClient()
        assert isinstance(client._client, httpx.AsyncClient)

    @pytest.mark.asyncio
    async def test_context_manager(self) -> None:
        async with QuantaWatchClient() as client:
            assert client.gateway_url == "http://localhost:9090"
        # After exit, the internal httpx client should be closed
        assert client._client.is_closed


# ---------------------------------------------------------------------------
# protect() wrapper
# ---------------------------------------------------------------------------


class _FakeAIClient:
    """Minimal stand-in for an AI SDK client."""

    def __init__(self) -> None:
        self.model = "claude-sonnet-4-20250514"

    def hello(self) -> str:
        return "world"


class TestProtect:
    """Tests for the protect() convenience function."""

    def test_returns_proxy(self) -> None:
        original = _FakeAIClient()
        wrapped = protect(original)
        # Should not be the same object
        assert wrapped is not original
        # But should proxy attribute access
        assert wrapped.model == "claude-sonnet-4-20250514"
        assert wrapped.hello() == "world"

    def test_repr_contains_gateway_url(self) -> None:
        wrapped = protect(_FakeAIClient(), gateway_url="http://gw:1234")
        r = repr(wrapped)
        assert "QuantaWatch-protected" in r
        assert "http://gw:1234" in r
        assert "_FakeAIClient" in r

    def test_custom_gateway_url(self) -> None:
        wrapped = protect(_FakeAIClient(), gateway_url="http://custom:5555")
        # Access internal gateway_url via object.__getattribute__
        gw = object.__getattribute__(wrapped, "_gateway_url")
        assert gw == "http://custom:5555"

    def test_setattr_forwarded(self) -> None:
        original = _FakeAIClient()
        wrapped = protect(original)
        wrapped.model = "gpt-4"
        assert original.model == "gpt-4"


# ---------------------------------------------------------------------------
# Pydantic models: serialisation / deserialisation
# ---------------------------------------------------------------------------


class TestSessionInfo:
    """Tests for SessionInfo model."""

    def test_roundtrip(self) -> None:
        now = datetime.now(tz=timezone.utc)
        data = {
            "session_id": "sess-123",
            "agent_name": "test-agent",
            "created_at": now.isoformat(),
            "expires_at": now.isoformat(),
            "request_count": 42,
            "total_tokens": 1000,
            "public_key_fingerprint": "sha256:abc",
        }
        session = SessionInfo.model_validate(data)
        assert session.session_id == "sess-123"
        assert session.agent_name == "test-agent"
        assert session.request_count == 42
        assert session.total_tokens == 1000
        assert session.public_key_fingerprint == "sha256:abc"

        # Re-serialise and check round-trip
        dumped = session.model_dump(mode="json")
        session2 = SessionInfo.model_validate(dumped)
        assert session2.session_id == session.session_id

    def test_defaults(self) -> None:
        now = datetime.now(tz=timezone.utc)
        session = SessionInfo(
            session_id="s1",
            agent_name="a1",
            created_at=now,
            expires_at=now,
        )
        assert session.request_count == 0
        assert session.total_tokens == 0
        assert session.public_key_fingerprint == ""


class TestDetectedThreat:
    """Tests for DetectedThreat model."""

    def test_roundtrip(self) -> None:
        data = {
            "category": "prompt_injection",
            "severity": "high",
            "pattern_name": "system_override",
            "confidence": 0.95,
            "description": "Attempted system prompt override detected",
        }
        threat = DetectedThreat.model_validate(data)
        assert threat.category == "prompt_injection"
        assert threat.confidence == 0.95

        dumped = threat.model_dump(mode="json")
        assert dumped["severity"] == "high"

    def test_confidence_bounds(self) -> None:
        with pytest.raises(Exception):
            DetectedThreat(
                category="x",
                severity="low",
                pattern_name="p",
                confidence=1.5,
                description="d",
            )

        with pytest.raises(Exception):
            DetectedThreat(
                category="x",
                severity="low",
                pattern_name="p",
                confidence=-0.1,
                description="d",
            )


class TestThreatAssessment:
    """Tests for ThreatAssessment model."""

    def test_defaults(self) -> None:
        assessment = ThreatAssessment()
        assert assessment.threats == []
        assert assessment.overall_severity == "none"
        assert assessment.blocked is False

    def test_with_threats(self) -> None:
        data = {
            "threats": [
                {
                    "category": "data_exfil",
                    "severity": "critical",
                    "pattern_name": "pii_leak",
                    "confidence": 0.88,
                    "description": "PII detected in response",
                }
            ],
            "overall_severity": "critical",
            "blocked": True,
        }
        assessment = ThreatAssessment.model_validate(data)
        assert len(assessment.threats) == 1
        assert assessment.threats[0].category == "data_exfil"
        assert assessment.blocked is True


class TestAuditEntry:
    """Tests for AuditEntry model."""

    def test_roundtrip(self) -> None:
        now = datetime.now(tz=timezone.utc)
        data = {
            "sequence": 1,
            "timestamp": now.isoformat(),
            "event_type": "request_proxied",
            "session_id": "sess-abc",
            "details": {"method": "POST", "path": "/v1/messages"},
            "signature": "sig-xyz",
        }
        entry = AuditEntry.model_validate(data)
        assert entry.sequence == 1
        assert entry.event_type == "request_proxied"
        assert entry.details["method"] == "POST"
        assert entry.signature == "sig-xyz"

    def test_defaults(self) -> None:
        now = datetime.now(tz=timezone.utc)
        entry = AuditEntry(
            sequence=0,
            timestamp=now,
            event_type="test",
            session_id="s",
        )
        assert entry.details == {}
        assert entry.signature == ""


class TestGatewayStats:
    """Tests for GatewayStats model."""

    def test_roundtrip(self) -> None:
        data = {
            "total_sessions": 100,
            "active_sessions": 5,
            "total_requests": 2500,
            "total_audit_entries": 5000,
            "active_threats": 2,
        }
        stats = GatewayStats.model_validate(data)
        assert stats.total_sessions == 100
        assert stats.active_sessions == 5
        assert stats.total_requests == 2500
        assert stats.total_audit_entries == 5000
        assert stats.active_threats == 2

        dumped = stats.model_dump(mode="json")
        stats2 = GatewayStats.model_validate(dumped)
        assert stats2 == stats

    def test_defaults(self) -> None:
        stats = GatewayStats()
        assert stats.total_sessions == 0
        assert stats.active_sessions == 0
        assert stats.total_requests == 0
        assert stats.total_audit_entries == 0
        assert stats.active_threats == 0
