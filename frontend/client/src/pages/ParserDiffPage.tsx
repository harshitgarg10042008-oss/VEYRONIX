/* Parser Differential — compare two parsers to find ambiguity gaps. */
import { useState } from "react";
import { GitBranch, AlertTriangle, FileText } from "lucide-react";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

type DiffEntry = {
  control_id: string;
  parser_a_status: string;
  parser_b_status: string;
  discrepancy_type: string;
  rationale: string;
  risk_level: string;
};

type ParserDiffResult = {
  diff_id: string;
  parser_a: string;
  parser_b: string;
  config_hash: string;
  total_controls: number;
  agreement_count: number;
  discrepancy_count: number;
  critical_discrepancy_count: number;
  diffs: DiffEntry[];
  verdict: string;
};

const RISK_TONE: Record<string, string> = {
  HIGH: "danger",
  MEDIUM: "warn",
  LOW: "neutral",
};

function SectionLabel({ children }: { children: React.ReactNode }) {
  return <div className="section-label">{children}</div>;
}

function Metric({ label, value, note, tone = "neutral" }: { label: string; value: string; note: string; tone?: string }) {
  return (
    <div className={`metric metric-${tone}`}>
      <SectionLabel>{label}</SectionLabel>
      <strong>{value}</strong>
      <span>{note}</span>
    </div>
  );
}

export default function ParserDiffPage() {
  const [configText, setConfigText] = useState("version 17.9\nhostname Router1\nline vty 0 4\n transport input telnet\n");
  const [parserA, setParserA] = useState("cisco_ios_v1");
  const [parserB, setParserB] = useState("cisco_ios_v2");
  const [result, setResult] = useState<ParserDiffResult | null>(null);
  const [running, setRunning] = useState(false);
  const [toast, setToast] = useState("");
  const [selected, setSelected] = useState<DiffEntry | null>(null);

  const run = async () => {
    if (!configText.trim()) return setToast("Configuration text is required");
    setRunning(true);
    try {
      const res = await fetch(`${API_BASE}/api/parser-diff/compare`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ config_text: configText, parser_a: parserA, parser_b: parserB }),
      });
      if (!res.ok) throw new Error(`Comparison returned ${res.status}`);
      const data = await res.json() as ParserDiffResult;
      setResult(data);
      setSelected(data.diffs[0] ?? null);
      setToast(`Differential complete · ${data.discrepancy_count} discrepancies`);
    } catch (e) {
      setToast(`Failed · ${e instanceof Error ? e.message : "start the local API"}`);
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="content-scroll">
      <div className="content-inner">
        <div className="page-intro">
          <div>
            <SectionLabel>PARSER DIFFERENTIAL / AMBIGUITY DETECTION</SectionLabel>
            <h1>Where do parsers disagree?</h1>
            <p>Run the same configuration through two parser versions and identify controls where verdicts diverge. Ambiguity is a reliability risk — surface it before it reaches audit reports.</p>
          </div>
          <div className="intro-action">
            <span className="queue-readout"><GitBranch size={14} /> DIFFERENTIAL</span>
          </div>
        </div>

        <div className="website-scan-form">
          <div className="form-row">
            <label>Parser A</label>
            <input type="text" value={parserA} onChange={e => setParserA(e.target.value)} placeholder="cisco_ios_v1" />
            <label>Parser B</label>
            <input type="text" value={parserB} onChange={e => setParserB(e.target.value)} placeholder="cisco_ios_v2" />
            <button className="button button-primary" type="button" onClick={run} disabled={running}>
              <GitBranch size={15} /> {running ? "Comparing…" : "Run Differential"}
            </button>
          </div>
          <div className="form-row" style={{ flexDirection: "column", alignItems: "stretch" }}>
            <label>Configuration Text</label>
            <textarea
              rows={5}
              value={configText}
              onChange={e => setConfigText(e.target.value)}
              style={{ fontFamily: "monospace", fontSize: 12, padding: 10, border: "1px solid var(--line)", background: "var(--surface)", color: "var(--ink)", resize: "vertical", borderRadius: 4 }}
            />
          </div>
        </div>

        {toast && (
          <div className="queue-banner" style={{ marginBottom: 16 }}>
            <div className="queue-icon"><AlertTriangle size={18} /></div>
            <span>{toast}</span>
          </div>
        )}

        {result && (
          <>
            <div className="scan-summary">
              <Metric label="VERDICT" value={result.verdict} note={`${result.parser_a} vs ${result.parser_b}`} tone={result.discrepancy_count > 0 ? "warn" : "verified"} />
              <Metric label="AGREEMENT" value={result.agreement_count.toString()} note="controls with matching verdict" tone="verified" />
              <Metric label="DISCREPANCIES" value={result.discrepancy_count.toString()} note="controls where parsers disagree" tone={result.discrepancy_count > 0 ? "danger" : "verified"} />
              <Metric label="CRITICAL" value={result.critical_discrepancy_count.toString()} note="high-risk disagreements" tone={result.critical_discrepancy_count > 0 ? "danger" : "neutral"} />
            </div>

            <div className="two-column">
              <section className="panel">
                <div className="panel-head">
                  <div>
                    <SectionLabel>DISCREPANCIES / {result.diff_id}</SectionLabel>
                    <h2>Parser verdict disagreements</h2>
                  </div>
                  <span className="count-badge">{result.diffs.length.toString().padStart(2, "0")}</span>
                </div>
                <div className="findings-table">
                  <div className="table-head"><span>CONTROL</span><span>PARSER A</span><span>PARSER B</span><span>RISK</span></div>
                  {result.diffs.length === 0
                    ? <div className="empty-state"><GitBranch size={22} /><strong>No discrepancies</strong><span>Both parsers agree on all controls.</span></div>
                    : result.diffs.map(d => (
                      <button
                        type="button"
                        key={d.control_id}
                        className={`finding-row ${selected?.control_id === d.control_id ? "finding-selected" : ""}`}
                        onClick={() => setSelected(d)}
                      >
                        <span className="finding-main">
                          <span className={`finding-symbol symbol-${RISK_TONE[d.risk_level] ?? "neutral"}`}>≠</span>
                          <span>
                            <strong>{d.control_id}</strong>
                            <small>{d.discrepancy_type.replace(/_/g, " ")}</small>
                          </span>
                        </span>
                        <span className={`status-pill status-${d.parser_a_status === "FAIL" ? "fail" : "pass"}`}><span className="status-dot" />{d.parser_a_status}</span>
                        <span className={`status-pill status-${d.parser_b_status === "FAIL" ? "fail" : "pass"}`}><span className="status-dot" />{d.parser_b_status}</span>
                        <span className={`severity severity-${d.risk_level.toLowerCase()}`}>{d.risk_level}</span>
                      </button>
                    ))
                  }
                </div>
              </section>

              <aside className="evidence-panel">
                <div className="evidence-top">
                  <SectionLabel>SELECTED DISCREPANCY</SectionLabel>
                  <span className="proof-tag"><GitBranch size={12} /> DIFF</span>
                </div>
                {selected ? (
                  <>
                    <div className="evidence-id">{selected.control_id} · {selected.discrepancy_type.replace(/_/g, " ").toUpperCase()}</div>
                    <h2>{selected.rationale}</h2>
                    <div className="evidence-block">
                      <SectionLabel>VERDICT COMPARISON</SectionLabel>
                      <div className="evidence-state">
                        <span className={`status-pill status-${selected.parser_a_status === "FAIL" ? "fail" : "pass"}`}><span className="status-dot" />{result.parser_a}: {selected.parser_a_status}</span>
                        <span className={`status-pill status-${selected.parser_b_status === "FAIL" ? "fail" : "pass"}`}><span className="status-dot" />{result.parser_b}: {selected.parser_b_status}</span>
                      </div>
                    </div>
                    <div className="evidence-block">
                      <SectionLabel>RISK ASSESSMENT</SectionLabel>
                      <span className={`severity severity-${selected.risk_level.toLowerCase()}`}>{selected.risk_level}</span>
                    </div>
                    <div className="evidence-block">
                      <SectionLabel>INTERPRETATION</SectionLabel>
                      <p className="muted-copy">
                        Parser discrepancy on this control means audit results may differ depending on which parser version is active. Manual review is required to determine the authoritative verdict.
                      </p>
                    </div>
                    <div className="evidence-footer">
                      <span>diff/{result.diff_id}</span>
                      <span>Config hash: {result.config_hash.slice(0, 12)}…</span>
                    </div>
                  </>
                ) : (
                  <div className="empty-state"><FileText size={22} /><strong>Select a discrepancy</strong><span>Details will appear here</span></div>
                )}
              </aside>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
