import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Table, TextInput, PasswordInput, Select, Button, Badge, Group, Text, ActionIcon, Tooltip, Alert } from "@mantine/core";
import { fetchRbac, fetchMe, fetchUsers, createUser, updateUser, deleteUser } from "../api/client";
import type { ManagedUser } from "../api/client";
import type { RbacRole } from "../api/types";
import { Card, PageHeader, Spinner, EmptyState } from "../components/ui";

function UserManagement() {
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ["users"], queryFn: fetchUsers });
  const invalidate = () => qc.invalidateQueries({ queryKey: ["users"] });
  const [nu, setNu] = useState({ username: "", password: "", role: "viewer" });
  const [err, setErr] = useState<string | null>(null);

  const add = useMutation({
    mutationFn: () => createUser(nu),
    onSuccess: () => { setNu({ username: "", password: "", role: "viewer" }); setErr(null); invalidate(); },
    onError: (e) => setErr((e as Error)?.message ?? "Failed to add user"),
  });
  const setRole = useMutation({ mutationFn: (v: { u: string; role: string }) => updateUser(v.u, { role: v.role }), onSuccess: invalidate });
  const del = useMutation({ mutationFn: (u: string) => deleteUser(u), onSuccess: invalidate, onError: (e) => setErr((e as Error)?.message ?? "Failed to delete") });

  const roles = data?.roles ?? ["admin", "operator", "viewer"];
  const users = data?.users ?? [];

  return (
    <Card className="p-4">
      <Text fw={700} c="gray.1">Users</Text>
      <Text size="12px" c="dimmed" mb="sm">Add and remove people, change their role, or revoke access. Config-declared users are read-only (they live in quantawatch.yaml); users you add here are stored and fully editable.</Text>

      {err && <Alert color="red" radius={2} variant="light" p="xs" mb="sm" withCloseButton onClose={() => setErr(null)}><Text size="11px">{err}</Text></Alert>}

      {/* Add user */}
      <Group gap="sm" align="flex-end" wrap="wrap" mb="md">
        <TextInput size="xs" radius={2} label="Username" placeholder="jsmith" value={nu.username} onChange={(e) => setNu({ ...nu, username: e.currentTarget.value })} w={170} />
        <PasswordInput size="xs" radius={2} label="Password" description="min 8 chars" placeholder="••••••••" value={nu.password} onChange={(e) => setNu({ ...nu, password: e.currentTarget.value })} w={190} />
        <Select size="xs" radius={2} label="Role" value={nu.role} onChange={(v) => setNu({ ...nu, role: v ?? "viewer" })} data={roles} w={150} comboboxProps={{ radius: 2 }} />
        <Button size="xs" radius={2} color="brand" loading={add.isPending} disabled={!nu.username.trim() || nu.password.length < 8} onClick={() => add.mutate()}>Add user</Button>
      </Group>

      <Table verticalSpacing={6} fz="13px" horizontalSpacing="sm">
        <Table.Thead><Table.Tr><Table.Th>User</Table.Th><Table.Th>Role</Table.Th><Table.Th>Org</Table.Th><Table.Th>Source</Table.Th><Table.Th></Table.Th></Table.Tr></Table.Thead>
        <Table.Tbody>
          {users.map((u: ManagedUser) => (
            <Table.Tr key={u.username}>
              <Table.Td fw={600} c="gray.2">{u.username}{u.isSelf && <Badge ml={6} size="xs" radius={2} variant="light" color="brand" tt="none">you</Badge>}</Table.Td>
              <Table.Td>
                {u.editable ? (
                  <Select size="xs" radius={2} value={u.role} data={roles} w={130} comboboxProps={{ radius: 2 }}
                    disabled={setRole.isPending} onChange={(v) => v && setRole.mutate({ u: u.username, role: v })} />
                ) : (
                  <Badge size="sm" radius={2} variant="light" color={u.role === "admin" ? "brand" : "gray"} tt="none">{u.role}</Badge>
                )}
              </Table.Td>
              <Table.Td c="dimmed">{u.org}</Table.Td>
              <Table.Td><Badge size="xs" radius={2} variant="outline" color={u.source === "config" ? "gray" : "cyan"}>{u.source}</Badge></Table.Td>
              <Table.Td style={{ textAlign: "right" }}>
                {u.editable && !u.isSelf ? (
                  <Tooltip label="Remove user & revoke access" withArrow>
                    <ActionIcon size="sm" radius={2} variant="subtle" color="red" loading={del.isPending && del.variables === u.username} onClick={() => del.mutate(u.username)}>
                      <svg width={14} height={14} fill="none" viewBox="0 0 24 24" strokeWidth={1.8} stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" d="m14.74 9-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0" /></svg>
                    </ActionIcon>
                  </Tooltip>
                ) : (
                  <Text size="10px" c="dark.3">{u.isSelf ? "current" : "config"}</Text>
                )}
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </Card>
  );
}

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
        subtitle="Add and remove people, change roles and revoke access — then see exactly what each role can do in the permission matrix."
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

      {/* Editable user management */}
      <UserManagement />

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
