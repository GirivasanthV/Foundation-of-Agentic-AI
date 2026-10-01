import { FormEvent, useEffect, useMemo, useState } from "react";
import { api } from "./api";
import type { AuditEvent, BlocklistEntry, Investigation, SystemStatus } from "./types";

type View = "investigations" | "approvals" | "blocklist" | "audit" | "system";
type DetailTab = "explanation" | "evidence" | "trace";

const verdictClass: Record<string, string> = {
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
  UNKNOWN: "unknown",
};

const viewTitles: Record<View, [string, string]> = {
  investigations: ["Investigation Console", "Submit and review URL, IP, hash, and screenshot evidence"],
  approvals: ["Human Approval Queue", "Review high-risk and uncertain recommendations before response"],
  blocklist: ["Response Blocklist", "Manage analyst-approved containment indicators"],
  audit: ["Audit Trail", "Immutable investigation, decision, and response activity"],
  system: ["System Readiness", "Live provider and capability configuration"],
};

function formatTime(value: string) {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

function humanize(value: string) {
  return value.replaceAll("_", " ").replaceAll(".", " ");
}

function downloadText(filename: string, content: string, type = "application/json") {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function csvCell(value: unknown) {
  return `"${String(value ?? "").replaceAll('"', '""')}"`;
}

function fileAsDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(new Error("Could not read screenshot"));
    reader.readAsDataURL(file);
  });
}

function InvestigationDetail({
  selected,
  loading,
  tab,
  setTab,
  comment,
  setComment,
  onDecision,
  onRerun,
}: {
  selected?: Investigation;
  loading: boolean;
  tab: DetailTab;
  setTab: (tab: DetailTab) => void;
  comment: string;
  setComment: (value: string) => void;
  onDecision: (decision: "approve" | "reject" | "override_monitor") => void;
  onRerun: () => void;
}) {
  if (!selected) {
    return <section className="panel detail-panel"><div className="empty large"><strong>Select an investigation</strong><span>Evidence and agent reasoning will appear here.</span></div></section>;
  }

  const intel = selected.evidence.threat_intelligence;
  const visual = selected.evidence.visual_analysis;
  const explanation = selected.evidence.risk_explanation;
  const pageEvidence = selected.evidence.page;
  const exportId = selected.id;

  function downloadJson() {
    downloadText(`sentinel-investigation-${exportId.slice(0, 8)}.json`, JSON.stringify(selected, null, 2));
  }

  return (
    <section className="panel detail-panel">
      <div className="detail-top">
        <div className="detail-title">
          <p className="eyebrow">INVESTIGATION {selected.id.slice(0, 8).toUpperCase()}</p>
          <h2 title={selected.normalized_indicator}>{selected.normalized_indicator}</h2>
          <span className="status-line">{selected.indicator_type.toUpperCase()} · Status: {humanize(selected.status)}</span>
        </div>
        <div className="detail-actions">
          <button title="Copy indicator" onClick={() => void navigator.clipboard.writeText(selected.normalized_indicator)}>Copy</button>
          <button title="Download complete evidence as JSON" onClick={downloadJson}>Export</button>
          <button title="Run a fresh investigation" onClick={onRerun} disabled={loading}>Re-run</button>
        </div>
        <div className={`score-ring ${verdictClass[selected.verdict]}`} style={{ "--score": `${selected.risk_score * 3.6}deg` } as React.CSSProperties}>
          <div><strong>{Math.round(selected.risk_score)}</strong><small>/100</small></div>
        </div>
      </div>

      <div className="assessment-row">
        <div><small>Verdict</small><span className={`verdict ${verdictClass[selected.verdict]}`}>{selected.verdict}</span></div>
        <div><small>Confidence</small><strong>{Math.round(selected.confidence * 100)}%</strong></div>
        <div><small>Recommended action</small><strong>{selected.recommended_action}</strong></div>
        <div><small>Evidence mode</small><strong>{intel?.mode ?? "unknown"}</strong></div>
      </div>

      <div className="detail-tabs">
        <button className={tab === "explanation" ? "active" : ""} onClick={() => setTab("explanation")}>Why this verdict</button>
        <button className={tab === "evidence" ? "active" : ""} onClick={() => setTab("evidence")}>Evidence</button>
        <button className={tab === "trace" ? "active" : ""} onClick={() => setTab("trace")}>Agent trace</button>
      </div>

      {tab === "explanation" && (
        <div className="tab-content">
          <div className="explanation-hero">
            <div><p className="eyebrow">ORCHESTRATOR EXPLANATION</p><h3>{explanation?.summary ?? "No structured explanation is available for this older investigation."}</h3></div>
            {explanation?.formula && <code>{explanation.formula}</code>}
          </div>
          <div className="factor-grid">
            {explanation?.factors?.map((factor) => (
              <article className="factor-card" key={factor.label}>
                <div><strong>{factor.label}</strong><span>{Math.round(factor.weight * 100)}% weight</span></div>
                <b>{factor.score}<small>/100</small></b>
                <p>{factor.reason}</p>
                <footer>Contribution: {factor.contribution} points</footer>
              </article>
            ))}
          </div>
          <div className="reason-grid">
            <article><small>Decision threshold</small><p>{explanation?.threshold_reason ?? "This record predates detailed threshold explanations."}</p></article>
            <article><small>Confidence</small><p>{explanation?.confidence_reason ?? "Confidence was calculated from available evidence."}</p></article>
          </div>
          {!!explanation?.limitations?.length && <div className="limitations"><strong>Limitations</strong>{explanation.limitations.map((item) => <p key={item}>• {item}</p>)}</div>}
        </div>
      )}

      {tab === "evidence" && (
        <div className="tab-content evidence-grid">
          <div>
            <h3>Threat-intelligence providers</h3>
            <div className="evidence-card">
              {intel?.sources?.map((source) => (
                <div className="provider-row" key={source.name}>
                  <div><strong>{source.name}</strong><small>{source.status}</small></div>
                  <b>{Math.round(Number(source.score ?? 0))}/100</b>
                  {source.message && <p>{source.message}</p>}
                </div>
              ))}
              {!intel?.sources?.length && <p className="muted">No provider evidence returned.</p>}
            </div>
            {!!intel?.resolved_ips?.length && <div className="evidence-card"><small>Resolved public IP addresses</small>{intel.resolved_ips.map((ip) => <code className="chip" key={ip}>{ip}</code>)}</div>}
          </div>
          <div>
            <h3>Vision-language analysis</h3>
            <div className="evidence-card visual-card">
              <div className="source-row"><strong>Screenshot</strong><span>{pageEvidence?.screenshot_included ? `${pageEvidence.screenshot_source ?? "available"}` : "not captured"}</span></div>
              {pageEvidence?.storage && <div className="source-row"><strong>Evidence storage</strong><span>{pageEvidence.storage.provider.replaceAll("_", " ")}</span></div>}
              <div className="source-row"><strong>Mode</strong><span>{visual?.mode ?? "not available"}</span></div>
              <div className="source-row"><strong>Visual score</strong><span>{Math.round(Number(visual?.score ?? 0))}/100</span></div>
              <p>{visual?.summary ?? "No visual evidence was supplied."}</p>
              {pageEvidence?.screenshot_error && <p className="capture-error">Capture warning: {pageEvidence.screenshot_error}</p>}
              {!!visual?.brands_detected?.length && <p><b>Brands:</b> {visual.brands_detected.join(", ")}</p>}
              {!!visual?.suspicious_elements?.length && <ul>{visual.suspicious_elements.map((item) => <li key={item}>{item}</li>)}</ul>}
            </div>
          </div>
          <div className="rag-column">
            <h3>RAG supporting knowledge</h3>
            <div className="rag-list">
              {selected.evidence.rag_context?.map((source) => (
                <a key={source.id} href={source.url} target="_blank" rel="noreferrer">
                  <div><strong>{source.id}</strong><span>Relevance {source.relevance_score ?? 0}</span></div>
                  <h4>{source.title}</h4>
                  <p>{source.text}</p>
                  <small>{source.why_relevant}</small>
                </a>
              ))}
            </div>
          </div>
        </div>
      )}

      {tab === "trace" && (
        <div className="tab-content">
          <h3>Collaborative multi-agent execution</h3>
          <div className="timeline">
            {selected.agent_trace.map((step, index) => (
              <div className="timeline-item" key={`${step.agent}-${index}`}>
                <span>{index + 1}</span>
                <div><strong>{step.agent}</strong><em>{step.status}</em><p>{step.summary}</p></div>
              </div>
            ))}
          </div>
        </div>
      )}

      {selected.status === "awaiting_approval" && (
        <div className="approval-bar">
          <div><strong>Human verification required</strong><span>Record a reason, review the evidence, then choose the response.</span><input value={comment} onChange={(event) => setComment(event.target.value)} placeholder="Analyst comment (recommended)" /></div>
          <div>
            <button className="reject" disabled={loading} onClick={() => onDecision("reject")}>Reject</button>
            <button className="monitor" disabled={loading} onClick={() => onDecision("override_monitor")}>Monitor</button>
            <button className="approve" disabled={loading} onClick={() => onDecision("approve")}>Approve block</button>
          </div>
        </div>
      )}
    </section>
  );
}

function App() {
  const [view, setView] = useState<View>("investigations");
  const [detailTab, setDetailTab] = useState<DetailTab>("explanation");
  const [items, setItems] = useState<Investigation[]>([]);
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [blocklist, setBlocklist] = useState<BlocklistEntry[]>([]);
  const [system, setSystem] = useState<SystemStatus | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [indicator, setIndicator] = useState("");
  const [screenshot, setScreenshot] = useState<File | null>(null);
  const [autoCapture, setAutoCapture] = useState(true);
  const [query, setQuery] = useState("");
  const [auditQuery, setAuditQuery] = useState("");
  const [blockStatus, setBlockStatus] = useState("ALL");
  const [verdictFilter, setVerdictFilter] = useState("ALL");
  const [comment, setComment] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const pending = items.filter((item) => item.status === "awaiting_approval");
  const highRisk = items.filter((item) => ["HIGH", "CRITICAL"].includes(item.verdict));
  const activeBlocks = blocklist.filter((entry) => entry.status === "active");
  const selected = view === "approvals"
    ? pending.find((item) => item.id === selectedId) ?? pending[0]
    : items.find((item) => item.id === selectedId) ?? items[0];
  const [title, subtitle] = viewTitles[view];

  const visibleItems = useMemo(() => {
    const base = view === "approvals" ? pending : items;
    const normalizedQuery = query.toLowerCase();
    return base.filter((item) => {
      const matchesQuery = !normalizedQuery || item.normalized_indicator.toLowerCase().includes(normalizedQuery);
      const matchesVerdict = verdictFilter === "ALL"
        || (verdictFilter === "HIGH_RISK" && ["HIGH", "CRITICAL"].includes(item.verdict))
        || item.verdict === verdictFilter;
      return matchesQuery && matchesVerdict;
    });
  }, [items, view, query, verdictFilter]);

  const visibleAudit = useMemo(() => {
    const needle = auditQuery.trim().toLowerCase();
    if (!needle) return audit;
    return audit.filter((event) => `${event.action} ${event.actor} ${event.investigation_id} ${JSON.stringify(event.details)}`.toLowerCase().includes(needle));
  }, [audit, auditQuery]);

  const visibleBlocks = useMemo(
    () => blockStatus === "ALL" ? blocklist : blocklist.filter((entry) => entry.status === blockStatus),
    [blocklist, blockStatus],
  );

  async function refreshAll(selectFirst = false) {
    setError("");
    try {
      const [investigations, auditEvents, blocks, status] = await Promise.all([
        api.list(), api.audit(), api.blocklist(), api.systemStatus(),
      ]);
      setItems(investigations);
      setAudit(auditEvents);
      setBlocklist(blocks);
      setSystem(status);
      if ((selectFirst || !selectedId) && investigations.length) setSelectedId(investigations[0].id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load SentinelAI data");
    }
  }

  useEffect(() => { void refreshAll(true); }, []);

  async function submit(event?: FormEvent, value = indicator) {
    event?.preventDefault();
    if (!value.trim()) return;
    setLoading(true);
    setError("");
    setNotice("");
    try {
      const screenshotDataUrl = screenshot ? await fileAsDataUrl(screenshot) : null;
      const created = await api.create(value.trim(), screenshot?.name ?? "", screenshotDataUrl, autoCapture && !screenshot);
      setItems((current) => [created, ...current]);
      setSelectedId(created.id);
      setIndicator("");
      setScreenshot(null);
      setView("investigations");
      setDetailTab("explanation");
      setNotice("Investigation completed. Review the explanation and evidence.");
      await refreshAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Investigation failed");
    } finally {
      setLoading(false);
    }
  }

  async function decide(decision: "approve" | "reject" | "override_monitor") {
    if (!selected) return;
    setLoading(true);
    setError("");
    try {
      const updated = await api.decide(selected.id, decision, comment);
      setItems((current) => current.map((item) => item.id === updated.id ? updated : item));
      setComment("");
      setNotice(decision === "approve" ? "Approved and added to the response blocklist." : "Analyst decision recorded.");
      await refreshAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Decision failed");
    } finally {
      setLoading(false);
    }
  }

  async function removeBlock(entry: BlocklistEntry) {
    if (!window.confirm(`Remove ${entry.indicator} from the active blocklist?`)) return;
    setLoading(true);
    try {
      await api.removeBlock(entry.id);
      setNotice("Blocklist entry removed and audit event recorded.");
      await refreshAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not remove blocklist entry");
    } finally {
      setLoading(false);
    }
  }

  async function runReadinessCheck() {
    setLoading(true);
    setError("");
    try {
      const status = await api.systemStatus();
      setSystem(status);
      const missing = Object.values(status.providers).filter((ready) => !ready).length;
      setNotice(missing ? `Readiness check completed: ${missing} optional provider(s) require configuration.` : "Readiness check passed: all providers are configured.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Readiness check failed");
    } finally {
      setLoading(false);
    }
  }

  function navigate(next: View) {
    setView(next);
    setError("");
    setNotice("");
    setQuery("");
    setVerdictFilter("ALL");
    setAuditQuery("");
    setBlockStatus("ALL");
    if (next === "approvals" && pending[0]) setSelectedId(pending[0].id);
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">S</span><div><strong>SentinelAI</strong><small>Threat Operations</small></div></div>
        <nav>
          <button className={view === "investigations" ? "nav-active" : ""} onClick={() => navigate("investigations")}><span>⌁</span>Investigations <em>{items.length}</em></button>
          <button className={view === "approvals" ? "nav-active" : ""} onClick={() => navigate("approvals")}><span>◇</span>Approval Queue <em>{pending.length}</em></button>
          <button className={view === "blocklist" ? "nav-active" : ""} onClick={() => navigate("blocklist")}><span>⊘</span>Blocklist <em>{activeBlocks.length}</em></button>
          <button className={view === "audit" ? "nav-active" : ""} onClick={() => navigate("audit")}><span>≡</span>Audit Trail</button>
          <button className={view === "system" ? "nav-active" : ""} onClick={() => navigate("system")}><span>◎</span>System Status</button>
        </nav>
        <button className="system-card" onClick={() => navigate("system")}>
          <span className="pulse"/>
          <div><strong>Live analysis active</strong><small>Response mode: {system?.response_mode ?? "loading"}</small></div>
        </button>
      </aside>

      <main>
        <header>
          <div><p className="eyebrow">SECURITY OPERATIONS CENTER</p><h1>{title}</h1><span className="page-subtitle">{subtitle}</span></div>
          <div className="analyst"><span>GV</span><div><strong>SOC Analyst</strong><small>Human reviewer</small></div></div>
        </header>

        {error && <div className="banner error-banner">{error}<button onClick={() => setError("")}>×</button></div>}
        {notice && <div className="banner success-banner">{notice}<button onClick={() => setNotice("")}>×</button></div>}

        {(view === "investigations" || view === "approvals") && (
          <>
            <section className="stats">
              <button onClick={() => { navigate("investigations"); setVerdictFilter("ALL"); }}><small>Total investigations</small><strong>{items.length}</strong><span>All submitted indicators</span></button>
              <button onClick={() => { navigate("investigations"); setVerdictFilter("HIGH_RISK"); }}><small>High-risk findings</small><strong>{highRisk.length}</strong><span>High and critical verdicts</span></button>
              <button onClick={() => navigate("approvals")}><small>Awaiting approval</small><strong>{pending.length}</strong><span>Human decision required</span></button>
              <button onClick={() => navigate("blocklist")}><small>Active blocklist</small><strong>{activeBlocks.length}</strong><span>Approved response actions</span></button>
            </section>

            {view === "investigations" && (
              <form className="scan-form" onSubmit={(event) => void submit(event)}>
                <div><label htmlFor="indicator">Investigate an indicator</label><span>Public URL, IP address, or SHA-256 hash. URL screenshots are captured automatically.</span></div>
                <div className="input-row">
                  <input id="indicator" value={indicator} onChange={(event) => setIndicator(event.target.value)} placeholder="https://suspicious-login.example, 8.8.8.8, or SHA-256" />
                  <label className={`file-button ${screenshot ? "attached" : ""}`}><input type="file" accept="image/png,image/jpeg" onChange={(event) => setScreenshot(event.target.files?.[0] ?? null)} />{screenshot ? screenshot.name : "Add screenshot"}</label>
                  <button disabled={loading || !indicator.trim()}>{loading ? "Investigating…" : "Run investigation"}</button>
                </div>
                <label className="capture-toggle"><input type="checkbox" checked={autoCapture} disabled={Boolean(screenshot)} onChange={(event) => setAutoCapture(event.target.checked)} />Automatically capture the visible website area when no image is attached</label>
              </form>
            )}

            <div className="workspace-grid">
              <section className="panel investigation-list">
                <div className="panel-heading"><div><p className="eyebrow">{view === "approvals" ? "HITL" : "RECENT"}</p><h2>{view === "approvals" ? "Pending reviews" : "Investigations"}</h2></div><button className="icon-button" title="Refresh" onClick={() => void refreshAll()}>↻</button></div>
                <div className="list-tools">
                  <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search indicators…" />
                  <select value={verdictFilter} onChange={(event) => setVerdictFilter(event.target.value)}>
                    <option value="ALL">All risks</option><option value="HIGH_RISK">High + critical</option><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option>
                  </select>
                </div>
                <div className="list-body">
                  {!visibleItems.length && <div className="empty"><strong>{view === "approvals" ? "Approval queue is clear" : "No investigations found"}</strong><span>{view === "approvals" ? "High-risk and uncertain results appear here." : "Submit an indicator to start the workflow."}</span></div>}
                  {visibleItems.map((item) => (
                    <button key={item.id} className={`list-item ${selected?.id === item.id ? "selected" : ""}`} onClick={() => { setSelectedId(item.id); setDetailTab("explanation"); }}>
                      <div><strong>{item.normalized_indicator}</strong><small>{item.indicator_type.toUpperCase()} · {formatTime(item.created_at)}</small></div>
                      <span className={`verdict ${verdictClass[item.verdict]}`}>{item.verdict}</span>
                    </button>
                  ))}
                </div>
              </section>

              <InvestigationDetail
                selected={selected}
                loading={loading}
                tab={detailTab}
                setTab={setDetailTab}
                comment={comment}
                setComment={setComment}
                onDecision={(decision) => void decide(decision)}
                onRerun={() => selected && void submit(undefined, selected.normalized_indicator)}
              />
            </div>
          </>
        )}

        {view === "blocklist" && (
          <section className="panel full-panel">
            <div className="panel-heading"><div><p className="eyebrow">AUTOMATED RESPONSE</p><h2>Analyst-approved indicators</h2></div><div className="toolbar"><select value={blockStatus} onChange={(event) => setBlockStatus(event.target.value)}><option value="ALL">All entries</option><option value="active">Active</option><option value="removed">Removed</option></select><button className="secondary-button" onClick={() => downloadText("sentinel-blocklist.csv", ["indicator,type,status,mode,reason,created", ...visibleBlocks.map((entry) => [entry.indicator, entry.indicator_type, entry.status, entry.enforcement_mode, entry.reason, entry.created_at].map(csvCell).join(","))].join("\n"), "text/csv")}>Export CSV</button><button className="secondary-button" onClick={() => void refreshAll()}>Refresh</button></div></div>
            <div className="table-wrap">
              <table><thead><tr><th>Indicator</th><th>Type</th><th>Status</th><th>Mode</th><th>Reason</th><th>Added</th><th>Action</th></tr></thead>
                <tbody>
                  {visibleBlocks.map((entry) => <tr key={entry.id}><td><code>{entry.indicator}</code></td><td>{entry.indicator_type.toUpperCase()}</td><td><span className={`status-pill ${entry.status}`}>{entry.status}</span></td><td>{entry.enforcement_mode}</td><td>{entry.reason}</td><td>{formatTime(entry.created_at)}</td><td>{entry.status === "active" ? <button className="danger-button" disabled={loading} onClick={() => void removeBlock(entry)}>Remove</button> : "—"}</td></tr>)}
                  {!visibleBlocks.length && <tr><td colSpan={7}><div className="empty"><strong>No matching blocklist entries</strong><span>Approve a BLOCK recommendation from the Approval Queue.</span></div></td></tr>}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {view === "audit" && (
          <section className="panel full-panel">
            <div className="panel-heading"><div><p className="eyebrow">ACCOUNTABILITY</p><h2>Recorded events</h2></div><div className="toolbar"><input value={auditQuery} onChange={(event) => setAuditQuery(event.target.value)} placeholder="Search events…"/><button className="secondary-button" onClick={() => downloadText("sentinel-audit.json", JSON.stringify(visibleAudit, null, 2))}>Export JSON</button><button className="secondary-button" onClick={() => void refreshAll()}>Refresh</button></div></div>
            <div className="audit-list">
              {visibleAudit.map((event) => <article key={event.id}><span className="audit-dot"/><div><strong>{humanize(event.action)}</strong><p>{event.actor} · Investigation {event.investigation_id.slice(0, 8)}</p><code title={JSON.stringify(event.details)}>{JSON.stringify(event.details)}</code></div><time>{formatTime(event.created_at)}</time></article>)}
              {!visibleAudit.length && <div className="empty"><strong>No matching audit events</strong><span>System and analyst activity will be recorded here.</span></div>}
            </div>
          </section>
        )}

        {view === "system" && (
          <>
            <section className="system-overview"><article><small>Analysis mode</small><strong>{system?.mode ?? "unknown"}</strong></article><article><small>Response mode</small><strong>{system?.response_mode ?? "unknown"}</strong></article><button disabled={loading} onClick={() => void runReadinessCheck()}>{loading ? "Checking…" : "Run readiness check"}</button></section>
            {!!system?.warnings?.length && <section className="readiness-warnings">{system.warnings.map((warning) => <p key={warning}>{warning}</p>)}</section>}
            <div className="readiness-grid">
              <section className="panel"><div className="panel-heading"><div><p className="eyebrow">INTEGRATIONS</p><h2>External providers</h2></div></div><div className="check-list">{Object.entries(system?.providers ?? {}).map(([name, ready]) => <div key={name}><span className={ready ? "ready" : "missing"}>{ready ? "✓" : "!"}</span><div><strong>{name}</strong><small>{ready ? "Configured" : "Not configured"}</small></div></div>)}</div></section>
              <section className="panel"><div className="panel-heading"><div><p className="eyebrow">FEATURES</p><h2>Abstract requirements</h2></div></div><div className="check-list">{Object.entries(system?.capabilities ?? {}).map(([name, ready]) => <div key={name}><span className={ready ? "ready" : "missing"}>{ready ? "✓" : "!"}</span><div><strong>{humanize(name)}</strong><small>{ready ? "Available" : "Requires configuration"}</small></div></div>)}</div></section>
            </div>
          </>
        )}
      </main>
    </div>
  );
}

export default App;
