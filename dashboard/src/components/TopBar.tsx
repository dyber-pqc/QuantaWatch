import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Group, TextInput, Select, Avatar, ActionIcon, Text, Box } from "@mantine/core";
import { fetchMe, fetchTenants, getTenant, setTenant, logout } from "../api/client";

function SearchIcon() {
  return (
    <svg width={15} height={15} fill="none" viewBox="0 0 24 24" strokeWidth={1.8} stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" d="m21 21-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z" />
    </svg>
  );
}

export default function TopBar() {
  const queryClient = useQueryClient();
  const { data: me } = useQuery({ queryKey: ["me"], queryFn: fetchMe });
  const { data: tenants } = useQuery({ queryKey: ["tenants"], queryFn: fetchTenants });

  const current = getTenant() ?? "default";
  const switchOrg = (org: string | null) => {
    setTenant(!org || org === "default" ? null : org);
    queryClient.clear();
    window.location.reload();
  };

  const initials = me?.username ? me.username.replace(/^apikey:/, "").slice(0, 2).toUpperCase() : "DY";

  const doLogout = async () => {
    await logout();
    queryClient.clear();
    window.dispatchEvent(new Event("qw-unauthorized"));
  };

  return (
    <Group h="100%" px="md" gap="md" wrap="nowrap">
      <TextInput
        placeholder="Search assets, findings, sessions"
        leftSection={<SearchIcon />}
        variant="filled"
        size="xs"
        radius="md"
        style={{ flex: 1, maxWidth: 440 }}
      />

      <Group gap="xs" ml="auto" wrap="nowrap">
        {tenants?.canSwitch && (tenants.tenants.length ?? 0) > 0 && (
          <Select
            data={tenants.tenants}
            value={current}
            onChange={switchOrg}
            size="xs"
            radius="md"
            w={150}
            allowDeselect={false}
            aria-label="Switch organization"
            comboboxProps={{ withinPortal: true }}
          />
        )}
        {me?.username && (
          <Box visibleFrom="sm" ta="right">
            <Text size="xs" fw={600} c="gray.2">{me.username.replace(/^apikey:/, "")}</Text>
            <Text size="9px" tt="uppercase" c="dimmed" style={{ letterSpacing: "0.08em" }}>{me.role}</Text>
          </Box>
        )}
        <Avatar color="brand" radius="xl" size={30} title={me?.username ? `Signed in as ${me.username}` : "QuantaWatch"}>
          <Text size="xs" fw={700}>{initials}</Text>
        </Avatar>
        {me?.authEnabled && me?.username && (
          <ActionIcon variant="subtle" color="gray" size="lg" radius="xl" onClick={doLogout} aria-label="Sign out" title="Sign out">
            <svg width={18} height={18} fill="none" viewBox="0 0 24 24" strokeWidth={1.6} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0 0 13.5 3h-6a2.25 2.25 0 0 0-2.25 2.25v13.5A2.25 2.25 0 0 0 7.5 21h6a2.25 2.25 0 0 0 2.25-2.25V15M12 9l-3 3m0 0 3 3m-3-3h12.75" />
            </svg>
          </ActionIcon>
        )}
      </Group>
    </Group>
  );
}
