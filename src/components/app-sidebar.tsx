import {
  ShieldCheck,
  LayoutDashboard,
  ListChecks,
  Database,
  FileText,
  Settings,
  type LucideIcon,
} from "lucide-react";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
  SidebarSeparator,
} from "@/components/ui/sidebar";
import { Badge } from "@/components/ui/badge";
import { Wordmark } from "@/components/wordmark";
import { useI18n, type TKey } from "@/lib/i18n";
import { useAppVersion } from "@/lib/version";

export type PageId =
  | "dashboard"
  | "services"
  | "rules"
  | "cache"
  | "reports"
  | "settings";

interface NavItem {
  id: PageId;
  titleKey: TKey;
  icon: LucideIcon;
}

const mainNav: NavItem[] = [
  { id: "dashboard", titleKey: "nav.dashboard", icon: LayoutDashboard },
  { id: "services", titleKey: "nav.services", icon: ListChecks },
  { id: "rules", titleKey: "nav.rules", icon: ShieldCheck },
  { id: "cache", titleKey: "nav.cache", icon: Database },
  { id: "reports", titleKey: "nav.reports", icon: FileText },
];

const bottomNav: NavItem[] = [
  { id: "settings", titleKey: "nav.settings", icon: Settings },
];

interface AppSidebarProps {
  active: PageId;
  onNavigate: (id: PageId) => void;
}

export function AppSidebar({ active, onNavigate }: AppSidebarProps) {
  const { t } = useI18n();
  const version = useAppVersion();
  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <div className="flex items-center gap-2 px-1 py-1.5" data-tauri-drag-region>
          <img
            src="/brand/Logo.png"
            alt="Deamonize"
            className="size-7 shrink-0 object-contain drop-shadow-[0_0_6px_rgba(250,196,86,0.45)]"
            data-tauri-drag-region
          />
          <div className="grid flex-1 text-left leading-tight" data-tauri-drag-region>
            <Wordmark
              className="truncate text-sm font-semibold tracking-wide"
            />
            <span
              className="truncate text-[10px] font-semibold tracking-widest text-brand"
              data-tauri-drag-region
            >
              SCAN - SECURE - PROTECT
            </span>
          </div>
          {version && (
            <Badge
              variant="secondary"
              className="hidden shrink-0 text-[10px] tabular-nums group-data-[collapsible=icon]:hidden"
            >
              v{version}
            </Badge>
          )}
        </div>
      </SidebarHeader>
      <SidebarSeparator />
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>{t("nav.analysis")}</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {mainNav.map((item) => (
                <SidebarMenuItem key={item.id}>
                  <SidebarMenuButton
                    isActive={active === item.id}
                    onClick={() => onNavigate(item.id)}
                    tooltip={t(item.titleKey)}
                  >
                    <item.icon />
                    <span>{t(item.titleKey)}</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
        <div className="flex-1" />
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>
              {bottomNav.map((item) => (
                <SidebarMenuItem key={item.id}>
                  <SidebarMenuButton
                    isActive={active === item.id}
                    onClick={() => onNavigate(item.id)}
                    tooltip={t(item.titleKey)}
                  >
                    <item.icon />
                    <span>{t(item.titleKey)}</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
      <SidebarRail />
    </Sidebar>
  );
}
