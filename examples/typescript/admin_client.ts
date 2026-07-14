/**
 * Admin client example: query sessions, audit log, stats, and verify the
 * cryptographic audit chain using the QuantaWatch TypeScript SDK.
 */
import { QuantaWatchClient } from "@quantawatch/sdk";

async function main(): Promise<void> {
  const qw = new QuantaWatchClient({
    gatewayUrl: "http://localhost:9090",
    adminUrl: "http://localhost:9091",
  });

  // ---- Sessions -------------------------------------------------------------
  const sessions = await qw.getSessions();
  console.log(`Total sessions: ${sessions.length}\n`);
  for (const s of sessions) {
    console.log(
      `  [${s.sessionId}] agent=${s.agentName}  ` +
        `requests=${s.requestCount}  tokens=${s.totalTokens}`,
    );
  }

  // ---- Audit log ------------------------------------------------------------
  const entries = await qw.getAuditEntries(10);
  console.log(`\nLast ${entries.length} audit entries:`);
  for (const e of entries) {
    console.log(
      `  #${e.sequence}  ${e.timestamp}  ${e.eventType}  ` +
        `session=${e.sessionId}`,
    );
  }

  // ---- Verify chain ---------------------------------------------------------
  const result = await qw.verifyAuditChain();
  if (result.valid) {
    console.log(`\nAudit chain OK`);
  } else {
    console.log(`\nAudit chain INVALID: ${result.errors.join(", ")}`);
  }

  // ---- Stats ----------------------------------------------------------------
  const stats = await qw.getStats();
  console.log(`\nGateway stats:`);
  console.log(`  active sessions : ${stats.activeSessions}`);
  console.log(`  total requests  : ${stats.totalRequests}`);
  console.log(`  audit entries   : ${stats.totalAuditEntries}`);
  console.log(`  active threats  : ${stats.activeThreats}`);
}

main().catch(console.error);
