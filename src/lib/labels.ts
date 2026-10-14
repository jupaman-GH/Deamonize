import type { VerdictCategory } from "@/types";
import type { LucideIcon } from "lucide-react";
import { AlertTriangle, HelpCircle, ShieldAlert, ShieldCheck } from "lucide-react";

// Labels are localized through i18n keys: `category.${key}`,
// `status.${key}` and `start.${key}` (see src/lib/i18n.tsx).
export const categoryMeta: Record<
  VerdictCategory,
  { color: string; badge: string; icon: LucideIcon }
> = {
  safe: {
    color: "text-safe",
    badge: "bg-safe/15 text-safe border-safe/30",
    icon: ShieldCheck,
  },
  suspicious: {
    color: "text-suspicious",
    badge: "bg-suspicious/15 text-suspicious border-suspicious/30",
    icon: AlertTriangle,
  },
  dangerous: {
    color: "text-dangerous",
    badge: "bg-dangerous/15 text-dangerous border-dangerous/30",
    icon: ShieldAlert,
  },
  unknown: {
    color: "text-unknown",
    badge: "bg-unknown/15 text-unknown border-unknown/30",
    icon: HelpCircle,
  },
};

export function truncateMiddle(s: string, max = 48): string {
  if (s.length <= max) return s;
  const half = Math.floor((max - 3) / 2);
  return `${s.slice(0, half)}...${s.slice(-half)}`;
}
