"""Admin client example: query sessions, audit log, and verify the audit chain."""
import asyncio
from quantawatch import QuantaWatchClient


async def main() -> None:
    async with QuantaWatchClient(
        gateway_url="http://localhost:9090",
        admin_url="http://localhost:9091",
    ) as qw:
        # ---- Sessions -----------------------------------------------------------
        sessions = await qw.get_sessions()
        print(f"Total sessions: {len(sessions)}\n")
        for s in sessions:
            print(f"  [{s.session_id}] agent={s.agent_name}  "
                  f"requests={s.request_count}  tokens={s.total_tokens}")

        # ---- Audit log ----------------------------------------------------------
        entries = await qw.get_audit_entries(limit=10)
        print(f"\nLast {len(entries)} audit entries:")
        for e in entries:
            print(f"  #{e.sequence}  {e.timestamp}  {e.event_type}  "
                  f"session={e.session_id}")

        # ---- Verify chain -------------------------------------------------------
        result = await qw.verify_audit_chain()
        if result.get("valid"):
            checked = result.get("entries_checked", "?")
            print(f"\nAudit chain OK  ({checked} entries verified)")
        else:
            print(f"\nAudit chain INVALID: {result.get('errors', [])}")

        # ---- Stats --------------------------------------------------------------
        stats = await qw.get_stats()
        print(f"\nGateway stats:")
        print(f"  active sessions : {stats.active_sessions}")
        print(f"  total requests  : {stats.total_requests}")
        print(f"  audit entries   : {stats.total_audit_entries}")
        print(f"  active threats  : {stats.active_threats}")


if __name__ == "__main__":
    asyncio.run(main())
