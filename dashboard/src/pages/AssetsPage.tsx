import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { fetchAssets, syncAssets } from "../api/client";
import { Card, PageHeader, Stat, Spinner, EmptyState, PqcBadge } from "../components/ui";

const KIND_ICON: Record<string, string> = {
  tls_endpoint: "🌐", k8s_ingress: "☸", load_balancer: "⚖", kms_key: "🔑", certificate: "🔏", private_ca: "🏛",
};

export default function AssetsPage() {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ["assets"], queryFn: fetchAssets });

  const sync = useMutation({
    mutationFn: syncAssets,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["assets"] });
      queryClient.invalidateQueries({ queryKey: ["attack-paths"] });
      queryClient.invalidateQueries({ queryKey: ["posture"] });
    },
  });

  if (isLoading) return <Spinner className="h-64" />;

  const assets = data?.assets ?? [];
  const envs = Object.entries(data?.environments ?? {});

  return (
    <div className="space-y-5">
      <PageHeader
        title="Asset Inventory"
        subtitle="External crypto assets discovered by agentless connectors and declared inventory"
        actions={
          <button onClick={() => sync.mutate()} disabled={sync.isPending} className="qw-btn-primary">
            {sync.isPending ? "Syncing…" : "Sync Connectors"}
          </button>
        }
      />

      {sync.isSuccess && (
        <div className="qw-fade-up rounded border border-brand-500/30 bg-brand-500/10 px-4 py-2.5 text-sm text-brand-200">
          Synced {sync.data.total} assets ({sync.data.scanned} scanned).
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
        <Stat label="Total Assets" value={data?.total ?? 0} accent="brand" />
        <Stat label="Quantum-Vulnerable" value={data?.vulnerable ?? 0} accent={(data?.vulnerable ?? 0) > 0 ? "rose" : "emerald"} />
        <Stat label="Environments" value={envs.length} accent="violet" />
        <Stat label="Connectors" value={data?.connectors.length ?? 0} accent="brand" />
      </div>

      {(data?.connectors.length ?? 0) > 0 && (
        <Card className="p-4">
          <div className="qw-eyebrow mb-3">Agentless Connectors</div>
          <div className="flex flex-wrap gap-3">
            {data?.connectors.map((c) => (
              <div key={c.name} className="rounded border border-white/10 bg-surface-850/60 px-3 py-2">
                <div className="text-sm font-medium text-white">{c.name}</div>
                <div className="text-xs text-gray-500">{c.type} · {c.environment} · {c.endpoints} endpoint(s)</div>
              </div>
            ))}
          </div>
        </Card>
      )}

      <Card>
        <div className="border-b border-white/10 px-4 py-2.5"><div className="qw-eyebrow">Discovered Assets</div></div>
        {assets.length === 0 ? (
          <EmptyState title="No assets yet">
            Declare assets under <span className="font-mono">assets:</span> or add cloud/K8s <span className="font-mono">connectors:</span> in quantawatch.yaml, then Sync.
          </EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="qw-eyebrow border-b border-white/10 text-left">
                  <th className="px-4 py-2.5 font-semibold">Asset</th>
                  <th className="px-4 py-2.5 font-semibold">Kind</th>
                  <th className="px-4 py-2.5 font-semibold">Environment</th>
                  <th className="px-4 py-2.5 font-semibold">PQC Status</th>
                  <th className="px-4 py-2.5 font-semibold">Source</th>
                  <th className="px-4 py-2.5 font-semibold">Address</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {assets.map((a) => (
                  <tr key={a.id} className="transition-colors hover:bg-white/5">
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-2">
                        <span>{KIND_ICON[a.kind] ?? "🔒"}</span>
                        <div>
                          <div className="text-sm font-medium text-white">{a.id}</div>
                          {a.tags.length > 0 && <div className="mt-0.5 flex gap-1">{a.tags.map((t) => <span key={t} className="qw-chip bg-white/5 text-gray-400">{t}</span>)}</div>}
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-2.5 text-sm text-gray-400">{a.kind.replace(/_/g, " ")}</td>
                    <td className="px-4 py-2.5 text-sm text-gray-300">{a.environment}</td>
                    <td className="px-4 py-2.5"><PqcBadge status={a.pqcStatus} /></td>
                    <td className="px-4 py-2.5"><span className="qw-chip bg-brand-500/10 text-brand-200">{a.source}</span></td>
                    <td className="px-4 py-2.5 font-mono text-xs text-gray-500">{a.address}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
