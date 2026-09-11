/* Layout.tsx — Persistent app shell: collapsible grouped sidebar + topbar. Wraps every route. */
import { useState, type ReactNode } from "react";
import { useLocation } from "wouter";
import {
  Activity, AlertTriangle, ArrowRight, Check, ChevronDown, ChevronRight,
  CircleHelp, Clock3, ClipboardCheck, Download, FileCheck2, FileText,
  Fingerprint, GitBranch, Layers3, LifeBuoy, LockKeyhole, Moon, Network,
  PanelRight, Play, Search, Scale, Server, Settings2, ShieldCheck, Sun, TerminalSquare,
  Upload, Zap, Database, Cpu,
} from "lucide-react";
import { useTheme } from "../contexts/ThemeContext";
import { useCapabilities } from "../contexts/CapabilityContext";

const logo = "/brand/configsentinel-mark-final.png";
const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

type NavItemDef = { label: string; path: string; icon: any; description: string };

const CORE_ITEMS: NavItemDef[] = [
  { label: "Overview", path: "/", icon: Layers3, description: "Posture at a glance" },
  { label: "Asset Inventory", path: "/inventory", icon: Server, description: "Manage tracked devices" },
  { label: "Continuous Monitoring", path: "/monitoring", icon: Activity, description: "Scheduled checks" },
  { label: "Website Security", path: "/website-security", icon: ShieldCheck, description: "Scan website posture" },
];

const ASSURANCE_ITEMS: NavItemDef[] = [
  { label: "Audits", path: "/audits", icon: ClipboardCheck, description: "Run and compare audits" },
  { label: "Assurance Chain", path: "/assurance-chain", icon: LockKeyhole, description: "Verify evidence timeline" },
  { label: "Review Queue", path: "/review-queue", icon: CircleHelp, description: "Resolve unknown evidence" },
  { label: "Remediation", path: "/remediation", icon: TerminalSquare, description: "Review proof-carrying fixes" },
  { label: "Drift Detection", path: "/drift", icon: GitBranch, description: "Compare configuration changes" },
  { label: "Notary Console", path: "/notary", icon: LockKeyhole, description: "Sign & verify evidence" },
  { label: "Evidence Exchange", path: "/exchange", icon: Download, description: "Share signed findings" },
  { label: "Evidence Freshness", path: "/freshness", icon: Clock3, description: "Verify data age" },
];

const LAB_ITEMS: NavItemDef[] = [
  { label: "Blast Radius", path: "/blast-radius", icon: AlertTriangle, description: "Assess change impact" },
  { label: "Mutation Lab", path: "/mutation-lab", icon: Zap, description: "Evaluate rule robustness" },
  { label: "Attack Graph", path: "/graph", icon: Network, description: "Simulate exploit paths" },
  { label: "Threat Models", path: "/threat-model", icon: AlertTriangle, description: "Compile code to STRIDE" },
  { label: "Counterfactuals", path: "/counterfactual", icon: Play, description: "Test hypothetical rules" },
  { label: "Parser Differential", path: "/parser-diff", icon: GitBranch, description: "Find ambiguity gaps" },
  { label: "Control Packs", path: "/control-packs", icon: FileCheck2, description: "Inspect deterministic rules" },
  { label: "Knowledge Graph", path: "/knowledge-graph", icon: Network, description: "Query institutional memory" },
  { label: "Incident Timeline", path: "/timeline", icon: Clock3, description: "Trace post-incident state" },
  { label: "Decision Quality", path: "/decision-quality", icon: Check, description: "Analyze approval stats" },
  { label: "Secrets Gate", path: "/secrets-gate", icon: ShieldCheck, description: "Verify redaction" },
  { label: "Supply Chain", path: "/supply-chain", icon: FileText, description: "Inspect SBOM evidence" },
  { label: "Provenance Tracker", path: "/provenance", icon: Fingerprint, description: "Verify artifact origin" },
  { label: "API Contracts", path: "/api-contract", icon: Network, description: "Verify schema vs runtime" },
  { label: "Resilience Drills", path: "/resilience", icon: Activity, description: "Schedule failover checks" },
  { label: "Technical Debt", path: "/debt", icon: AlertTriangle, description: "Track posture debt" },
  { label: "Regulatory Export", path: "/regulatory", icon: FileText, description: "Export to OSCAL" },
];

const SYSTEM_ITEMS: NavItemDef[] = [
  { label: "Settings", path: "/settings", icon: Settings2, description: "Local preferences" },
  { label: "Operator Guide", path: "/operator-guide", icon: LifeBuoy, description: "Safe demo sequence" },
  { label: "Privacy Policy", path: "/privacy", icon: ShieldCheck, description: "Data handling practices" },
  { label: "Terms & Conditions", path: "/terms", icon: Scale, description: "Terms of service" },
  { label: "Security Policy", path: "/policy", icon: ShieldCheck, description: "Security principles" },
];

const ALL_PATHS = [...CORE_ITEMS, ...ASSURANCE_ITEMS, ...LAB_ITEMS, ...SYSTEM_ITEMS];

function navLabel(path: string) {
  return ALL_PATHS.find((item) => item.path === path)?.label || "Overview";
}

function NavItem({ item, active, onClick, count }: {
  item: NavItemDef; active: boolean; onClick: () => void; count?: number;
}) {
  const Icon = item.icon;
  return (
    <button
      type="button"
      className={`nav-item ${active ? "nav-item-active" : ""}`}
      onClick={onClick}
      title={item.description}
    >
      <span className="nav-icon"><Icon size={15} strokeWidth={1.8} /></span>
      <span className="nav-copy">
        <strong>{item.label}</strong>
        <small>{item.description}</small>
      </span>
      {count !== undefined && count > 0 && (
        <span className="nav-count">{count.toString().padStart(2, "0")}</span>
      )}
    </button>
  );
}

function NavGroup({ label, items, activePath, onNavigate, defaultOpen = false, reviewCount, searchTerm }: {
  label: string;
  items: NavItemDef[];
  activePath: string;
  onNavigate: (path: string) => void;
  defaultOpen?: boolean;
  reviewCount?: number;
  searchTerm?: string;
}) {
  const filteredItems = searchTerm ? items.filter(i => i.label.toLowerCase().includes(searchTerm.toLowerCase()) || i.description.toLowerCase().includes(searchTerm.toLowerCase())) : items;
  const hasActive = items.some((i) => i.path === activePath);
  const [open, setOpen] = useState(defaultOpen || hasActive);

  const isOpen = searchTerm ? filteredItems.length > 0 : open;
  if (searchTerm && filteredItems.length === 0) return null;

  return (
    <div className="nav-group">
      <button
        type="button"
        className={`nav-group-toggle ${isOpen ? "nav-group-open" : ""}`}
        onClick={() => setOpen((o) => !o)}
        aria-expanded={isOpen}
      >
        <span className="nav-group-label">{label}</span>
        {isOpen ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
      </button>
      {isOpen && (
        <div className="nav-group-items">
          {filteredItems.map((item) => (
            <NavItem
              key={item.path}
              item={item}
              active={activePath === item.path}
              onClick={() => onNavigate(item.path)}
              count={item.path === "/review-queue" ? reviewCount : undefined}
            />
          ))}
        </div>
      )}
    </div>
  );
}

interface LayoutProps {
  children: ReactNode;
  reviewCount?: number;
  apiOnline?: boolean;
  sdkVersion?: string;
  session?: { actor_id: string; role: string } | null;
  onSwitchRole?: (role: string) => void;
}

export default function Layout({
  children,
  reviewCount = 0,
  apiOnline = false,
  sdkVersion = "—",
  session = null,
  onSwitchRole,
}: LayoutProps) {
  const [location, setLocation] = useLocation();
  const { theme, toggleTheme } = useTheme();
  const capabilities = useCapabilities();
  const [menuOpen, setMenuOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [sidebarSearch, setSidebarSearch] = useState("");
  const [quickSearch, setQuickSearch] = useState("");

  const navigate = (path: string) => { setLocation(path); setMenuOpen(false); };
  const activeNav = navLabel(location);
  const filteredSystemItems = sidebarSearch ? SYSTEM_ITEMS.filter(i => i.label.toLowerCase().includes(sidebarSearch.toLowerCase()) || i.description.toLowerCase().includes(sidebarSearch.toLowerCase())) : SYSTEM_ITEMS;

  return (
    <main className="app-shell">
      {/* ── Sidebar ── */}
      <aside className="sidebar">
        <div className="brand-lockup">
          <div className="brand-mark-wrap">
            <img src={logo} alt="ConfigSentinel AI mark" className="brand-mark" />
          </div>
          <div>
            <div className="brand-name">CONFIGSENTINEL</div>
            <div className="brand-sub">AI · OFFLINE SECURITY</div>
            <div className="brand-team">BY VEYRONIX</div>
          </div>
        </div>

        <div className="workspace-switcher">
          <div className="section-label">WORKSPACE</div>
          <button type="button" className="workspace-button">
            <span className="signal signal-teal" /> SIH / FIELD LAB <ChevronDown size={14} />
          </button>
        </div>

        <div style={{ padding: "16px 8px 0" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", background: "var(--rail-2)", padding: "8px 10px", borderRadius: "var(--radius)", border: "1px solid var(--rail-line)" }}>
            <Search size={14} color="var(--rail-muted)" />
            <input
              type="search"
              placeholder="Filter menu..."
              value={sidebarSearch}
              onChange={(e) => setSidebarSearch(e.target.value)}
              style={{ background: "transparent", border: "none", color: "var(--rail-text)", fontSize: "12px", outline: "none", width: "100%" }}
            />
          </div>
        </div>

        <nav className="nav-list" aria-label="Workbench navigation">
          <NavGroup
            label="CORE SECURITY"
            items={CORE_ITEMS}
            activePath={location}
            onNavigate={navigate}
            defaultOpen
            searchTerm={sidebarSearch}
          />
          <NavGroup
            label="ASSURANCE & EVIDENCE"
            items={ASSURANCE_ITEMS}
            activePath={location}
            onNavigate={navigate}
            reviewCount={reviewCount}
            searchTerm={sidebarSearch}
          />
          <NavGroup
            label="ADVANCED LAB"
            items={LAB_ITEMS}
            activePath={location}
            onNavigate={navigate}
            searchTerm={sidebarSearch}
          />

          {(!sidebarSearch || filteredSystemItems.length > 0) && (
            <div className="nav-spacer">
              <div className="section-label">SYSTEM</div>
            </div>
          )}
          {filteredSystemItems.map((item) => (
            <NavItem
              key={item.path}
              item={item}
              active={location === item.path}
              onClick={() => navigate(item.path)}
            />
          ))}
        </nav>

        <div className="sidebar-foot">
          {/* Evidence mode indicator */}
          <div className="local-badge" title={capabilities.apiOnline ? `Backend v${capabilities.manifest?.app_version ?? '—'} — live data` : 'No backend — using fixture/demo data'}>
            <span className={`signal ${capabilities.apiOnline ? "signal-teal" : "signal-amber"}`} />
            {capabilities.apiOnline ? "LIVE API" : "FIXTURE / DEMO"}
          </div>
          <div className="sidebar-foot-row">
            <span>API</span>
            <strong>{capabilities.manifest?.app_version ?? sdkVersion}</strong>
          </div>
          <div className="sidebar-foot-row">
            <span><Cpu size={10} style={{display:'inline',verticalAlign:'middle',marginRight:2}} />CONTROLS</span>
            <strong>{capabilities.manifest?.total_control_count ?? '—'}</strong>
          </div>
          <div className="sidebar-foot-row">
            <span><Database size={10} style={{display:'inline',verticalAlign:'middle',marginRight:2}} />VENDORS</span>
            <strong>{capabilities.manifest?.vendor_count ?? '—'}</strong>
          </div>
          <div className="sidebar-foot-row">
            <span>THEME</span>
            <strong>{theme.toUpperCase()}</strong>
          </div>
        </div>
      </aside>

      {/* ── Workbench ── */}
      <section className="workbench">
        <header className="topbar">
          <div className="breadcrumb">
            <span className="breadcrumb-muted">WORKBENCH</span>
            <span>/</span>
            <strong>{activeNav.toUpperCase()}</strong>
          </div>
          <div className="topbar-actions">
            <span className="topbar-status">
              <span className={`signal ${capabilities.apiOnline ? "signal-teal" : "signal-amber"}`} />
              {capabilities.apiOnline ? "DETERMINISTIC" : "LOCAL DEMO"}
            </span>
            <button
              type="button"
              className="theme-toggle"
              onClick={() => toggleTheme?.()}
              aria-label={`Switch to ${theme === "light" ? "dark" : "light"} mode`}
            >
              {theme === "light" ? <Moon size={16} /> : <Sun size={16} />}
              <span>{theme === "light" ? "Dark" : "Light"}</span>
            </button>
            <button
              type="button"
              className="icon-button"
              aria-label="Search"
              onClick={() => setSearchOpen((s) => !s)}
            >
              <Search size={17} />
            </button>
            <button
              type="button"
              className="avatar-button"
              onClick={() => setMenuOpen((o) => !o)}
              aria-label="Open operator menu"
            >
              {session ? session.actor_id.substring(0, 2).toUpperCase() : "HG"}
            </button>
            {menuOpen && (
              <div className="operator-menu">
                <strong>{session ? session.actor_id : "HARSHIT GARG"}</strong>
                <span>{session ? session.role : "operator"} · local only</span>
                <button type="button" onClick={() => { setMenuOpen(false); navigate("/settings"); }}>
                  Open settings <ArrowRight size={13} />
                </button>
                {onSwitchRole && (
                  <button type="button" onClick={() => onSwitchRole(session?.role === "operator" ? "reviewer" : "operator")}>
                    Switch to {session?.role === "operator" ? "reviewer" : "operator"} <ArrowRight size={13} />
                  </button>
                )}
              </div>
            )}
          </div>
        </header>

        {/* Search overlay */}
        {searchOpen && (
          <div
            className="search-overlay"
            role="dialog"
            aria-label="Quick search"
            onClick={(e) => { if (e.target === e.currentTarget) setSearchOpen(false); }}
          >
            <div className="search-box">
              <div className="search-input-row">
                <Search size={18} />
                <input
                  autoFocus
                  type="search"
                  placeholder="Search pages…"
                  className="search-input"
                  value={quickSearch}
                  onChange={(e) => setQuickSearch(e.target.value)}
                />
              </div>
              <div className="search-hints">
                {ALL_PATHS.filter((item) => {
                  const query = quickSearch.trim().toLowerCase();
                  return !query || `${item.label} ${item.description}`.toLowerCase().includes(query);
                }).slice(0, 8).map((item) => {
                  const Icon = item.icon;
                  return (
                    <button
                      key={item.path}
                      type="button"
                      className="search-hint-item"
                      onClick={() => { navigate(item.path); setSearchOpen(false); }}
                    >
                      <Icon size={14} />
                      <span>{item.label}</span>
                      <small>{item.description}</small>
                    </button>
                  );
                })}
                {ALL_PATHS.every((item) => !`${item.label} ${item.description}`.toLowerCase().includes(quickSearch.trim().toLowerCase())) && (
                  <div className="search-empty">No pages match “{quickSearch}”</div>
                )}
              </div>
            </div>
          </div>
        )}

        <div className="content-scroll">
          <div className="content-inner">
            {children}
          </div>
        </div>
      </section>
    </main>
  );
}