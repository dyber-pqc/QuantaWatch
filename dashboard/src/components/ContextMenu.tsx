import { useCallback, useEffect, useState } from "react";
import { Paper, Stack, UnstyledButton, Text, Box, Divider } from "@mantine/core";

export interface ContextMenuItem {
  label: string;
  icon?: React.ReactNode;
  onClick?: () => void;
  color?: string;
  disabled?: boolean;
  /** Render a section divider above this item. */
  divider?: boolean;
}

interface OpenState {
  x: number;
  y: number;
  items: ContextMenuItem[];
}

/**
 * Lightweight right-click menu. `useContextMenu` returns `onContextMenu` to
 * attach to any element (it builds the item list from the event target) and the
 * `<ContextMenu/>` node to render once per page.
 */
export function useContextMenu() {
  const [state, setState] = useState<OpenState | null>(null);

  const open = useCallback((e: React.MouseEvent, items: ContextMenuItem[]) => {
    e.preventDefault();
    e.stopPropagation();
    setState({ x: e.clientX, y: e.clientY, items });
  }, []);

  const close = useCallback(() => setState(null), []);

  const menu = state ? <ContextMenu x={state.x} y={state.y} items={state.items} onClose={close} /> : null;

  return { openMenu: open, menu };
}

export function ContextMenu({ x, y, items, onClose }: OpenState & { onClose: () => void }) {
  useEffect(() => {
    const dismiss = () => onClose();
    const esc = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    // Defer so the opening click doesn't immediately close it.
    const id = window.setTimeout(() => {
      window.addEventListener("click", dismiss);
      window.addEventListener("contextmenu", dismiss);
      window.addEventListener("keydown", esc);
      window.addEventListener("resize", dismiss);
    }, 0);
    return () => {
      window.clearTimeout(id);
      window.removeEventListener("click", dismiss);
      window.removeEventListener("contextmenu", dismiss);
      window.removeEventListener("keydown", esc);
      window.removeEventListener("resize", dismiss);
    };
  }, [onClose]);

  const width = 224;
  const estHeight = items.length * 34 + 10;
  const left = Math.min(x, window.innerWidth - width - 8);
  const top = Math.min(y, window.innerHeight - estHeight - 8);

  return (
    <Paper
      onClick={(e) => e.stopPropagation()}
      onContextMenu={(e) => e.preventDefault()}
      style={{
        position: "fixed",
        left,
        top,
        width,
        zIndex: 3000,
        border: "1px solid var(--mantine-color-dark-4)",
        background: "var(--mantine-color-dark-7)",
        boxShadow: "0 8px 28px rgba(0,0,0,0.55)",
        borderRadius: 4,
        overflow: "hidden",
      }}
      p={4}
    >
      <Stack gap={0}>
        {items.map((it, i) => (
          <Box key={i}>
            {it.divider && <Divider my={4} color="dark.5" />}
            <UnstyledButton
              disabled={it.disabled}
              onClick={() => {
                if (it.disabled) return;
                onClose();
                it.onClick?.();
              }}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                width: "100%",
                padding: "6px 10px",
                borderRadius: 3,
                opacity: it.disabled ? 0.4 : 1,
                cursor: it.disabled ? "default" : "pointer",
              }}
              onMouseEnter={(e) => {
                if (!it.disabled) (e.currentTarget as HTMLElement).style.background = "var(--mantine-color-dark-5)";
              }}
              onMouseLeave={(e) => {
                (e.currentTarget as HTMLElement).style.background = "transparent";
              }}
            >
              {it.icon && <Box w={15} h={15} c={it.color ?? "gray.4"} style={{ flexShrink: 0 }}>{it.icon}</Box>}
              <Text size="13px" c={it.color ?? "gray.2"}>{it.label}</Text>
            </UnstyledButton>
          </Box>
        ))}
      </Stack>
    </Paper>
  );
}
