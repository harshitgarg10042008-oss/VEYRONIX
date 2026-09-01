/* Knowledge Graph — institutional memory of assets, controls, evidence, decisions, and lessons. */
import { useState } from "react";
import { Network, AlertTriangle, FileText, Search, ShieldCheck } from "lucide-react";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

type RelationType = "OBSERVED" | "DECLARED" | "INFERRED" | "UNKNOWN";

type GraphRelation = {
  relation_id: string;
  subject: string;
  subject_type: string;
  predicate: string;
  object: string;
  object_type: string;
  relation_type: RelationType;
  confidence: number;
  provenance: string;
  created_at: string;
};

type KnowledgeQueryResult = {
  query_id: string;
  query: string;
  executed_at: string;
  total_relations: number;
  relations: GraphRelation[];
  summary: string;
  limitations: string;
};

type GraphStats = {
  total_nodes: number;
  total_relations: number;
  node_types: Record<string, number>;
  relation_types: Record<string, number>;
  oldest_fact: string;
  newest_fact: string;
};

const RELATION_TONE: Record<RelationType, string> = {
  OBSERVED: "verified",
  DECLARED: "neutral",
  INFERRED: "warn",
  UNKNOWN: "safe",
};

const PREDICATE_EXAMPLES = [
  "Which controls have recurring failures?",
  "Which assets are affected by FAIL findings?",
  "Which parser ambiguities affect critical assets?",
  "What decisions were made after this incident?",
  "Which exceptions have been renewed more than once?",
  "Which controls changed after the last rule-pack update?",
];

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

export default function KnowledgeGraphPage() {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<KnowledgeQueryResult | null>(null);
  const [stats, setStats] = useState<GraphStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [statsLoading, setStatsLoading] = useState(false);
  const [toast, setToast] = useState("");
  const [selected, setSelected] = useState<GraphRelation | null>(null);
  const [relationFilter, setRelationFilter] = useState<string>("ALL");
  const [tab, setTab] = useState<"query" | "stats">("query");

  const runQuery = async (q?: string) => {
    const q_ = q ?? query;
    if (!q_.trim()) return setToast("Enter a query");
    setLoading(true);
    if (q) setQuery(q);
    try {
      const res = await fetch(`${API_BASE}/api/knowledge-graph/query`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: q_ }),
      });
      if (!res.ok) throw new Error(`Query returned ${res.status}`);
      const data = await res.json() as KnowledgeQueryResult;
      setResult(data);
      setSelected(data.relations[0] ?? null);
      setToast(`Query complete · ${data.total_relations} relations found`);
    } catch (e) {
      setToast(`Failed · ${e instanceof Error ? e.message : "start the local API"}`);
    } finally {
      setLoading(false);
    }
  };

  const loadStats = async () => {
    setStatsLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/knowledge-graph/stats`);
      if (!res.ok) throw new Error(`Stats returned ${res.status}`);
      const data = await res.json() as GraphStats;
      setStats(data);
    } catch (e) {
      setToast(`Stats failed · ${e instanceof Error ? e.message : "start the local API"}`);
    } finally {
      setStatsLoading(false);
    }
  };

  const visible = result?.relations.filter(r => relationFilter === "ALL" || r.relation_type === relationFilter) ?? [];

  const relationBadge = (type: RelationType) => (
    <span className={`status-pill status-${RELATION_TONE[type]}`}>
      <span className="status-dot" />{type}
    </span>
  );

  return (
    <div className="content-scroll">
      <div className="content-inner">
        <div className="page-intro">
          <div>
            <SectionLabel>KNOWLEDGE GRAPH / INSTITUTIONAL MEMORY</SectionLabel>
            <h1>Remember what you know. Know why you know it.</h1>
            <p>
              Query the graph of relationships between assets, controls, evidence, decisions, incidents, exceptions, and lessons learned. Every relationship preserves its provenance — observed, declared, inferred, or unknown. AI may summarize but never invents graph edges.
            </p>
          </div>
          <div className="intro-action">
            <span className="queue-readout"><Network size={14} /> KNOWLEDGE GRAPH</span>
          </div>
        </div>

        <div className="queue-banner" style={{ marginBottom: 24 }}>
          <div className="queue-icon"><ShieldCheck size={22} /></div>
          <div>
            <strong>Provenance-backed answers only.</strong>
            <span>Every relationship in this graph links to its source evidence. Inferred relationships are labeled as such. No relationship is invented to produce a plausible-sounding answer.</span>
          </div>
          <span className="proof-tag">EVIDENCE-LINKED</span>
        </div>

        {/* Tab selector */}
        <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
          <button type="button" className={`button ${tab === "query" ? "button-primary" : "button-secondary"}`} onClick={() => setTab("query")}>
            <Search size={15} /> Query Graph
          </button>
          <button
            type="button"
            className={`button ${tab === "stats" ? "button-primary" : "button-secondary"}`}
            onClick={() => { setTab("stats"); if (!stats) loadStats(); }}
          >
            <Network size={15} /> Graph Statistics
          </button>
        </div>

        {tab === "query" && (
          <>
            <div className="website-scan-form">
              <div className="form-row">
                <label>Natural Language Query</label>
                <input
                  type="text"
                  placeholder="Which controls have recurring failures?"
                  value={query}
                  onChange={e => setQuery(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && runQuery()}
                  style={{ flex: 3 }}
                />
                <button className="button button-primary" type="button" onClick={() => runQuery()} disabled={loading}>
                  <Search size={15} /> {loading ? "Querying…" : "Query"}
                </button>
              </div>
              {/* Example queries */}
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 4 }}>
                {PREDICATE_EXAMPLES.map(ex => (
                  <button
                    key={ex}
                    type="button"
                    className="button button-tertiary"
                    style={{ fontSize: 11 }}
                    onClick={() => runQuery(ex)}
                  >
                    {ex}
                  </button>
                ))}
              </div>
            </div>

            {toast && (
              <div className="queue-banner" style={{ marginBottom: 16, marginTop: 16 }}>
                <div className="queue-icon"><AlertTriangle size={18} /></div>
                <span>{toast}</span>
              </div>
            )}

            {result && (
              <>
                {/* Summary */}
                {result.summary && (
                  <div className="queue-banner" style={{ marginBottom: 16 }}>
                    <div className="queue-icon"><Network size={18} /></div>
                    <div>
                      <strong>Graph summary</strong>
                      <span>{result.summary}</span>
                    </div>
                    <span className="proof-tag">AI SUMMARY</span>
                  </div>
                )}

                <div className="scan-summary">
                  <Metric label="RELATIONS FOUND" value={result.total_relations.toString()} note={`for: "${result.query}"`} tone="neutral" />
                  <Metric label="OBSERVED" value={result.relations.filter(r => r.relation_type === "OBSERVED").length.toString()} note="direct evidence" tone="verified" />
                  <Metric label="INFERRED" value={result.relations.filter(r => r.relation_type === "INFERRED").length.toString()} note="derived relationships" tone="warn" />
                  <Metric label="UNKNOWN" value={result.relations.filter(r => r.relation_type === "UNKNOWN").length.toString()} note="provenance unclear" tone="neutral" />
                </div>

                {/* Relation type filter */}
                <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
                  {["ALL", "OBSERVED", "DECLARED", "INFERRED", "UNKNOWN"].map(t => (
                    <button key={t} type="button" className={`button ${relationFilter === t ? "button-primary" : "button-secondary"}`} onClick={() => setRelationFilter(t)}>
                      {t}
                    </button>
                  ))}
                </div>

                <div className="two-column">
                  <section className="panel">
                    <div className="panel-head">
                      <div>
                        <SectionLabel>RELATIONS / {result.query_id}</SectionLabel>
                        <h2>Graph query results</h2>
                      </div>
                      <span className="count-badge">{visible.length.toString().padStart(2, "0")}</span>
                    </div>
                    <div className="findings-table">
                      <div className="table-head"><span>SUBJECT → OBJECT</span><span>PREDICATE</span><span>TYPE</span><span>CONF.</span></div>
                      {visible.length === 0
                        ? <div className="empty-state"><Network size={22} /><strong>No relations found</strong><span>Try a different query or relation filter.</span></div>
                        : visible.map(r => (
                          <button
                            type="button"
                            key={r.relation_id}
                            className={`finding-row ${selected?.relation_id === r.relation_id ? "finding-selected" : ""}`}
                            onClick={() => setSelected(r)}
                          >
                            <span className="finding-main">
                              <span className={`finding-symbol symbol-${RELATION_TONE[r.relation_type]}`}>
                                {r.relation_type === "OBSERVED" ? "●" : r.relation_type === "INFERRED" ? "~" : "○"}
                              </span>
                              <span>
                                <strong>{r.subject}</strong>
                                <small>→ {r.object}</small>
                              </span>
                            </span>
                            <span className="vendor-label" style={{ fontSize: 11 }}>{r.predicate}</span>
                            {relationBadge(r.relation_type)}
                            <span className="vendor-label">{(r.confidence * 100).toFixed(0)}%</span>
                          </button>
                        ))
                      }
                    </div>
                  </section>

                  <aside className="evidence-panel">
                    <div className="evidence-top">
                      <SectionLabel>SELECTED RELATION</SectionLabel>
                      <span className="proof-tag"><Network size={12} /> GRAPH</span>
                    </div>
                    {selected ? (
                      <>
                        <div className="evidence-id">{selected.subject_type} → {selected.object_type}</div>
                        <h2>{selected.predicate}</h2>
                        <div className="evidence-block">
                          <SectionLabel>SUBJECTS</SectionLabel>
                          <div className="evidence-line"><code>SBJ</code><span><strong>{selected.subject}</strong> ({selected.subject_type})</span></div>
                          <div className="evidence-line"><code>OBJ</code><span><strong>{selected.object}</strong> ({selected.object_type})</span></div>
                        </div>
                        <div className="evidence-block">
                          <SectionLabel>RELATION METADATA</SectionLabel>
                          {relationBadge(selected.relation_type)}
                          <div className="evidence-line" style={{ marginTop: 8 }}>
                            <code>CONF</code><span>Confidence: {(selected.confidence * 100).toFixed(0)}%</span>
                          </div>
                          <div className="evidence-line">
                            <code>AT</code><span>Recorded: {new Date(selected.created_at).toLocaleString()}</span>
                          </div>
                        </div>
                        <div className="evidence-block">
                          <SectionLabel>PROVENANCE</SectionLabel>
                          <p className="muted-copy" style={{ wordBreak: "break-all", fontSize: 12 }}>{selected.provenance}</p>
                        </div>
                        <div className="evidence-block">
                          <SectionLabel>RELATION TYPE MEANING</SectionLabel>
                          <p className="muted-copy">
                            {selected.relation_type === "OBSERVED" && "This relationship was directly observed from authorized evidence."}
                            {selected.relation_type === "DECLARED" && "This relationship was declared in an authorized manifest or inventory."}
                            {selected.relation_type === "INFERRED" && "This relationship was inferred from other graph facts. Treat with appropriate uncertainty."}
                            {selected.relation_type === "UNKNOWN" && "The provenance of this relationship is unclear. Manual review is required before acting on it."}
                          </p>
                        </div>
                        <div className="evidence-footer">
                          <span>relation/{selected.relation_id}</span>
                          <span>AI may not invent graph edges</span>
                        </div>
                      </>
                    ) : (
                      <div className="empty-state"><FileText size={22} /><strong>Select a relation</strong><span>Graph relationship details will appear here</span></div>
                    )}
                  </aside>
                </div>

                {result.limitations && (
                  <div className="queue-banner" style={{ marginTop: 24 }}>
                    <div className="queue-icon"><FileText size={18} /></div>
                    <div><strong>Query limitations</strong><span>{result.limitations}</span></div>
                  </div>
                )}
              </>
            )}
          </>
        )}

        {tab === "stats" && (
          <>
            {statsLoading && (
              <div className="queue-banner">
                <div className="queue-icon"><Network size={18} /></div>
                <span>Loading graph statistics…</span>
              </div>
            )}
            {stats && (
              <>
                <div className="scan-summary">
                  <Metric label="TOTAL NODES" value={stats.total_nodes.toString()} note="unique entities in graph" tone="neutral" />
                  <Metric label="TOTAL RELATIONS" value={stats.total_relations.toString()} note="edges in the knowledge graph" tone="neutral" />
                  <Metric label="OLDEST FACT" value={new Date(stats.oldest_fact).toLocaleDateString()} note={new Date(stats.oldest_fact).toLocaleTimeString()} tone="neutral" />
                  <Metric label="NEWEST FACT" value={new Date(stats.newest_fact).toLocaleDateString()} note={new Date(stats.newest_fact).toLocaleTimeString()} tone="neutral" />
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24 }}>
                  <section className="panel">
                    <div className="panel-head">
                      <div><SectionLabel>NODES BY TYPE</SectionLabel><h2>Entity distribution</h2></div>
                    </div>
                    <div style={{ padding: "0 16px 16px" }}>
                      {Object.entries(stats.node_types).map(([type, count]) => (
                        <div key={type} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                          <span style={{ fontSize: 13 }}>{type}</span>
                          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                            <div style={{
                              width: Math.max(4, (count / Math.max(...Object.values(stats.node_types))) * 120),
                              height: 8, background: "var(--teal)", borderRadius: 4
                            }} />
                            <span className="vendor-label">{count}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </section>

                  <section className="panel">
                    <div className="panel-head">
                      <div><SectionLabel>RELATIONS BY TYPE</SectionLabel><h2>Provenance distribution</h2></div>
                    </div>
                    <div style={{ padding: "0 16px 16px" }}>
                      {Object.entries(stats.relation_types).map(([type, count]) => (
                        <div key={type} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                          <span className={`status-pill status-${RELATION_TONE[type as RelationType] ?? "neutral"}`} style={{ fontSize: 11 }}>
                            <span className="status-dot" />{type}
                          </span>
                          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                            <div style={{
                              width: Math.max(4, (count / Math.max(...Object.values(stats.relation_types))) * 120),
                              height: 8, background: "var(--teal)", borderRadius: 4
                            }} />
                            <span className="vendor-label">{count}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </section>
                </div>
              </>
            )}
          </>
        )}
      </div>
    </div>
  );
}
