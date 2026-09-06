/* DashboardCharts - Visualizations to fill empty space in key pages */
import { Activity, ShieldCheck, AlertTriangle, TrendingUp } from "lucide-react";

function SectionLabel({ children }: { children: React.ReactNode }) {
  return <div className="section-label">{children}</div>;
}

interface ChartCardProps {
  title: string;
  value: string;
  change?: string;
  icon: React.ReactNode;
  color: string;
  progress: number;
}

function ChartCard({ title, value, change, icon, color, progress }: ChartCardProps) {
  return (
    <div className="chart-card">
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "16px" }}>
        <h3>{title}</h3>
        <div style={{ padding: "8px", background: `var(--${color}-soft)`, borderRadius: "6px", color: `var(--${color})` }}>
          {icon}
        </div>
      </div>
      <div style={{ fontSize: "32px", fontWeight: "600", color: "var(--ink)", marginBottom: "8px" }}>{value}</div>
      {change && (
        <div style={{ fontSize: "12px", color: change.startsWith("+") ? "var(--teal)" : "var(--danger)", marginBottom: "12px" }}>
          {change} from last week
        </div>
      )}
      <div className="stat-bar">
        <div className={`stat-bar-fill ${progress < 50 ? "warning" : progress < 30 ? "danger" : ""}`} style={{ width: `${progress}%` }} />
      </div>
    </div>
  );
}

export default function DashboardCharts() {
  return (
    <div className="dashboard-charts">
      <ChartCard
        title="Security Posture"
        value="87%"
        change="+5%"
        icon={<ShieldCheck size={20} />}
        color="teal"
        progress={87}
      />
      <ChartCard
        title="Active Audits"
        value="24"
        change="+12%"
        icon={<Activity size={20} />}
        color="accent"
        progress={65}
      />
      <ChartCard
        title="Critical Findings"
        value="3"
        change="-40%"
        icon={<AlertTriangle size={20} />}
        color="danger"
        progress={15}
      />
      <ChartCard
        title="Compliance Score"
        value="92%"
        change="+8%"
        icon={<TrendingUp size={20} />}
        color="teal"
        progress={92}
      />
    </div>
  );
}
