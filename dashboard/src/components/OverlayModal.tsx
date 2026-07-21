import { useEffect } from "react";
import { Box, Group, Text, ActionIcon } from "@mantine/core";

/**
 * A self-contained modal: a fixed full-screen overlay + centered panel, with no
 * Mantine Portal/Transition (which don't render under this app's React 19
 * StrictMode). Renders nothing when closed. Closes on overlay click + Escape.
 */
export function OverlayModal({
  opened,
  onClose,
  title,
  children,
  width = 560,
}: {
  opened: boolean;
  onClose: () => void;
  title: React.ReactNode;
  children: React.ReactNode;
  width?: number;
}) {
  useEffect(() => {
    if (!opened) return;
    const esc = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", esc);
    return () => window.removeEventListener("keydown", esc);
  }, [opened, onClose]);

  if (!opened) return null;

  return (
    <Box
      onClick={onClose}
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 2000,
        background: "rgba(0,0,0,0.55)",
        display: "grid",
        placeItems: "center",
        padding: 16,
      }}
    >
      <Box
        onClick={(e) => e.stopPropagation()}
        style={{
          width: "100%",
          maxWidth: width,
          maxHeight: "88vh",
          overflowY: "auto",
          background: "var(--mantine-color-dark-7)",
          border: "1px solid var(--mantine-color-dark-4)",
          borderRadius: 4,
          boxShadow: "0 12px 48px rgba(0,0,0,0.6)",
        }}
      >
        <Group justify="space-between" px="md" py="sm" style={{ borderBottom: "1px solid var(--mantine-color-dark-5)", position: "sticky", top: 0, background: "var(--mantine-color-dark-7)", zIndex: 1 }}>
          <Text fw={700} size="sm" c="gray.1">{title}</Text>
          <ActionIcon variant="subtle" color="gray" size="sm" radius={2} onClick={onClose} aria-label="Close">
            <svg width={15} height={15} fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" /></svg>
          </ActionIcon>
        </Group>
        <Box p="md">{children}</Box>
      </Box>
    </Box>
  );
}
