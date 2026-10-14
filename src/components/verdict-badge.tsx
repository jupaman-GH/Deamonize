import { Badge } from "@/components/ui/badge";
import { categoryMeta } from "@/lib/labels";
import type { VerdictCategory } from "@/types";
import { cn } from "@/lib/utils";
import { useI18n } from "@/lib/i18n";

export function VerdictBadge({
  category,
  className,
}: {
  category: VerdictCategory;
  className?: string;
}) {
  const { t } = useI18n();
  const meta = categoryMeta[category];
  return (
    <Badge variant="outline" className={cn("gap-1 font-medium", meta.badge, className)}>
      <meta.icon className="size-3" />
      {t(`category.${category}`)}
    </Badge>
  );
}
