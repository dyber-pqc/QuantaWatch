import { useQuery } from "@tanstack/react-query";
import { fetchAgents } from "../api/client";
import type { AgentPosture } from "../api/types";
import { Card, PageHeader, Stat, Spinner, EmptyState, PqcBadge, scoreText, scoreColor } from "../components/ui";

function ScoreBar({ score }: { score: number }) {
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-800">
      <div
        className="h-full rounded-full transition-all duration-500"
        style={{ width: `${score}%`, backgroundColor: scoreColor(score) }}
      />
    </div>
  );
}

function AgentCard({ agent }: { agent: AgentPosture }) {
  return (
    <Card className="p-4" hover>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="truncate text-sm font-semibold text-white">{agent.name}</h3>
            {agent.offline && (
              <span className="qw-chip bg-emerald-400/10 text-emerald-300" title="Isolated — local models only">
                offline
              </span>
            )}
          </div>
          <p className="mt-0.5 line-clamp-1 text-xs text-gray-400">{agent.description || "No description"}</p>
        </div>
        <div className="text-right">
          <div className={`text-2xl font-semibold tabular-nums ${scoreText(agent.overallScore)}`}>
            {Math.round(agent.overallScore)}
          </div>
          <div className="text-[10px] uppercase tracking-wider text-gray-500">posture</div>
        </div>
      </div>

      <div className="mt-3">
        <ScoreBar score={agent.overallScore} />
      </div>

      {/* Channels */}
      <div className="mt-4 space-y-2">
        <div className="qw-eyebrow">Channels ({agent.providers.length})</div>
        {agent.providers.length === 0 ? (
          <p className="text-xs text-gray-500">No external providers — fully isolated.</p>
        ) : (
          agent.providers.map((p) => (
            <div key={p.provider} className="flex items-center justify-between gap-2 rounded border border-white/[0.06] bg-surface-850/60 px-2.5 py-1.5">
              <div className="flex items-center gap-2">
                <span className="text-xs font-medium capitalize text-gray-200">{p.provider}</span>
                {!p.observed && (
                  <span className="text-[10px] uppercase tracking-wider text-gray-600" title="Allowed by policy but not yet observed">
                    allowed
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2.5">
                <span className="text-[11px] text-gray-500">{p.tlsVersion ?? "—"}</span>
                <PqcBadge status={p.pqcStatus} />
                <span className="w-7 text-right text-xs font-semibold tabular-nums text-gray-300">{Math.round(p.score)}</span>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Activity footer */}
      <div className="mt-4 flex items-center gap-4 border-t border-white/[0.06] pt-3 text-[11px] text-gray-500">
        <span>{agent.sessionCount} sessions</span>
        <span>{agent.requestCount.toLocaleString()} requests</span>
        <span>{agent.modelCount} models</span>
        <span className="ml-auto">
          {agent.lastActive ? `active ${new Date(agent.lastActive).toLocaleDateString()}` : "no activity"}
        </span>
      </div>
    </Card>
  );
}

export default function AgentsPage() {
  const { data, isLoading } = useQuery({
    queryKey: ["agents"],
    queryFn: fetchAgents,
  });

  if (isLoading) return <Spinner className="h-64" />;

  const agents = data?.agents ?? [];

  return (
    <div className="space-y-5">
      <PageHeader title="Agent Posture" subtitle="Cryptographic posture of each AI agent, scored by the channels it uses" />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Stat label="Agents" value={data?.total ?? 0} accent="brand" />
        <Stat label="At Risk" value={data?.atRisk ?? 0} accent={(data?.atRisk ?? 0) > 0 ? "rose" : "emerald"} sub="posture below 80" />
        <Stat label="Avg Posture" value={Math.round(data?.avgScore ?? 100)} accent="violet" />
      </div>

      {agents.length === 0 ? (
        <Card>
          <EmptyState title="No agents configured">
            Define agents in your quantawatch.yaml, or send traffic through the gateway, and each agent's crypto posture will appear here.
          </EmptyState>
        </Card>
      ) : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {agents.map((agent) => (
            <AgentCard key={agent.name} agent={agent} />
          ))}
        </div>
      )}

      <Card className="p-4">
        <div className="qw-eyebrow mb-2">How this is scored</div>
        <p className="text-xs leading-relaxed text-gray-400">
          Each agent's posture is the score of its <span className="text-gray-200">weakest channel</span> — an agent is only as
          quantum-safe as the least-protected provider it can reach. Channels are derived from the agent's allowed models and from
          live sessions, then scored against the TLS/PQC crypto QuantaWatch captured for each provider endpoint.
        </p>
      </Card>
    </div>
  );
}
