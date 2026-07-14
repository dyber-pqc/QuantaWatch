import { useQuery } from "@tanstack/react-query";
import { fetchSessions } from "../api/client";
import { Card, PageHeader, Spinner, EmptyState } from "../components/ui";

const statusStyles: Record<string, { dot: string; chip: string }> = {
  active: { dot: "bg-emerald-400", chip: "bg-emerald-400/10 text-emerald-300" },
  completed: { dot: "bg-brand-400", chip: "bg-brand-400/10 text-brand-200" },
  terminated: { dot: "bg-rose-400", chip: "bg-rose-400/10 text-rose-300" },
};

export default function SessionsPage() {
  const { data: sessions, isLoading } = useQuery({
    queryKey: ["sessions"],
    queryFn: fetchSessions,
  });

  const activeCount = sessions?.filter((s) => s.status === "active").length ?? 0;

  return (
    <div className="space-y-5">
      <PageHeader
        title="Sessions"
        subtitle="Active and historical agent sessions"
        actions={
          <div className="flex items-center gap-2 text-sm text-gray-400">
            <span className="relative flex h-2 w-2">
              <span className="qw-pulse-glow absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
            </span>
            {activeCount} active
          </div>
        }
      />

      <Card>
        {isLoading ? (
          <Spinner className="py-16" />
        ) : !sessions || sessions.length === 0 ? (
          <EmptyState title="No sessions yet">Agent sessions will appear here as traffic flows through the gateway.</EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="qw-eyebrow border-b border-white/5 text-left">
                  <th className="px-4 py-2.5 font-semibold">Session ID</th>
                  <th className="px-4 py-2.5 font-semibold">Agent Name</th>
                  <th className="px-4 py-2.5 font-semibold">Created At</th>
                  <th className="px-4 py-2.5 font-semibold">Requests</th>
                  <th className="px-4 py-2.5 font-semibold">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {sessions.map((session) => {
                  const style = statusStyles[session.status] ?? statusStyles.completed;
                  return (
                    <tr key={session.session_id} className="transition-colors hover:bg-white/5">
                      <td className="px-4 py-2.5">
                        <code className="rounded bg-brand-400/10 px-2 py-0.5 font-mono text-sm text-brand-200">
                          {session.session_id}
                        </code>
                      </td>
                      <td className="px-4 py-2.5 text-sm text-gray-300">{session.agent_name}</td>
                      <td className="px-4 py-2.5 text-sm text-gray-400">{new Date(session.created_at).toLocaleString()}</td>
                      <td className="px-4 py-2.5 text-sm font-medium text-white">{session.request_count.toLocaleString()}</td>
                      <td className="px-4 py-2.5">
                        <span className={`qw-chip ${style.chip}`}>
                          <span className={`h-1.5 w-1.5 rounded-full ${style.dot}`} />
                          {session.status}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
