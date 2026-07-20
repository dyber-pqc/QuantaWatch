import { useQuery } from "@tanstack/react-query";
import { fetchRbac, fetchMe } from "../api/client";
import type { RbacRole } from "../api/types";
import { Card, PageHeader, Spinner, EmptyState } from "../components/ui";

/** Does a permission pattern set grant `resource:action`? Mirrors the gateway's
 *  PermissionSet::allows (wildcards on either side; bare "*" = everything). */
function allows(patterns: string[], resource: string, action: string): boolean {
  return patterns.some((p) => {
    const [pres, pact] = p.includes(":") ? p.split(":") : [p, "*"];
    return (pres === "*" || pres === resource) && (pact === "*" || pact === action);
  });
}

function Cell({ role, resource }: { role: RbacRole; resource: string }) {
  const r = allows(role.permissions, resource, "read");
  const w = allows(role.permissions, resource, "write");
  let label = "·";
  let cls = "text-gray-700";
  if (r && w) { label = "RW"; cls = "bg-emerald-500/15 text-emerald-300"; }
  else if (r) { label = "R"; cls = "bg-brand-500/15 text-brand-200"; }
  else if (w) { label = "W"; cls = "bg-amber-500/15 text-amber-300"; }
  return (
    <td className="px-2 py-1.5 text-center">
      <span className={`inline-flex h-6 w-8 items-center justify-center rounded text-[11px] font-semibold ${cls}`}>{label}</span>
    </td>
  );
}

function RoleTag({ builtin }: { builtin: boolean }) {
  return builtin ? (
    <span className="rounded bg-white/[0.06] px-1.5 py-0.5 text-[9.5px] font-semibold uppercase tracking-wide text-gray-400">built-in</span>
  ) : (
    <span className="rounded bg-quantum-500/15 px-1.5 py-0.5 text-[9.5px] font-semibold uppercase tracking-wide text-quantum-300">custom</span>
  );
}

export default function RbacPage() {
  const { data, isLoading, isError } = useQuery({ queryKey: ["rbac"], queryFn: fetchRbac });
  const { data: me } = useQuery({ queryKey: ["me"], queryFn: fetchMe });

  if (isLoading) return <Spinner className="h-64" />;
  if (isError || !data)
    return (
      <div className="space-y-5">
        <PageHeader title="Access Control (RBAC)" subtitle="Roles and the permissions they grant" />
        <Card><EmptyState title="RBAC unavailable">Enable authentication to define roles and permissions.</EmptyState></Card>
      </div>
    );

  // Show config too (admin-only; not in the general resource list).
  const resources = [...data.resources, "config"];
  const roles = data.roles;

  return (
    <div className="space-y-5">
      <PageHeader
        title="Access Control (RBAC)"
        subtitle="Every route requires a resource:action permission. Roles are permission bundles — least-privilege by design."
      />

      {/* Your access */}
      {me?.permissions && me.permissions.length > 0 && (
        <Card className="p-4">
          <div className="qw-eyebrow mb-2.5">Your access</div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-md bg-brand-500/15 px-2.5 py-1 text-[13px] font-semibold text-brand-200">{me.username}</span>
            <span className="text-gray-600">·</span>
            <span className="rounded-md bg-white/[0.06] px-2 py-1 text-[12px] font-semibold text-gray-300">{me.role}</span>
            <span className="text-gray-600">·</span>
            <div className="flex flex-wrap gap-1.5">
              {me.permissions.map((p) => (
                <span key={p} className="rounded bg-white/[0.04] px-1.5 py-0.5 font-mono text-[11px] text-gray-400 ring-1 ring-white/10">
                  {p === "*" ? "* (all)" : p}
                </span>
              ))}
            </div>
          </div>
        </Card>
      )}

      {/* Legend */}
      <div className="flex flex-wrap items-center gap-4 px-1 text-[11px] text-gray-500">
        <span className="flex items-center gap-1.5"><span className="inline-flex h-5 w-7 items-center justify-center rounded bg-emerald-500/15 text-[10px] font-semibold text-emerald-300">RW</span> read + write</span>
        <span className="flex items-center gap-1.5"><span className="inline-flex h-5 w-7 items-center justify-center rounded bg-brand-500/15 text-[10px] font-semibold text-brand-200">R</span> read only</span>
        <span className="flex items-center gap-1.5"><span className="inline-flex h-5 w-7 items-center justify-center rounded bg-amber-500/15 text-[10px] font-semibold text-amber-300">W</span> write only</span>
        <span className="flex items-center gap-1.5"><span className="text-gray-700">·</span> no access</span>
      </div>

      {/* Matrix */}
      <Card>
        <div className="border-b border-white/10 px-4 py-2.5">
          <div className="qw-eyebrow">Role · Permission Matrix</div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-white/10">
                <th className="sticky left-0 z-10 bg-surface-900 px-4 py-2.5 text-left text-[11px] font-semibold uppercase tracking-wide text-gray-500">Resource</th>
                {roles.map((role) => (
                  <th key={role.name} className="px-2 py-2.5 text-center">
                    <div className="flex flex-col items-center gap-1">
                      <span className="text-[12.5px] font-semibold text-gray-200">{role.name}</span>
                      <RoleTag builtin={role.builtin} />
                    </div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {resources.map((res, i) => (
                <tr key={res} className={`border-b border-white/[0.04] ${i % 2 ? "bg-white/[0.012]" : ""}`}>
                  <td className="sticky left-0 z-10 bg-surface-900 px-4 py-1.5 font-mono text-[12px] text-gray-300">
                    {res}
                    {res === "config" && <span className="ml-1.5 text-[9.5px] text-gray-600">admin-only</span>}
                  </td>
                  {roles.map((role) => <Cell key={role.name} role={role} resource={res} />)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <p className="px-1 text-[11px] leading-relaxed text-gray-600">
        Built-in roles: <span className="text-gray-400">viewer</span>/<span className="text-gray-400">auditor</span> read everything but config,
        <span className="text-gray-400"> operator</span> adds writes, <span className="text-gray-400">admin</span> has everything.
        Define custom least-privilege roles under <span className="font-mono text-gray-400">auth.roles</span> in quantawatch.yaml.
      </p>
    </div>
  );
}
