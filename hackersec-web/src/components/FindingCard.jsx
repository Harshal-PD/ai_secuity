import { useState } from "react"
import { ChevronDown, ChevronUp, Info, CheckCircle, ShieldAlert, ShieldOff, HelpCircle } from "lucide-react"
import { SEVERITY_COLORS } from "../lib/constants"
import { parseDiff } from "../lib/diff"

function VerdictTag({ verdict }) {
  const map = {
    true_positive: ["var(--danger)", "rgba(239,68,68,0.1)"],
    false_positive: ["var(--success)", "rgba(34,197,94,0.1)"],
  }
  const [color, bg] = map[verdict] || ["var(--warning)", "rgba(234,179,8,0.1)"]
  return (
    <span style={{ color, background: bg, fontWeight: 600, textTransform: "uppercase",
      fontSize: "0.7rem", padding: "0.1rem 0.4rem", borderRadius: "3px" }}>
      {verdict || "pending"}
    </span>
  )
}

// reproduced arrives as "true" | "false" | null from the backend.
function ExploitBadge({ reproduced }) {
  if (reproduced === "true")
    return <span className="badge badge-danger"><ShieldAlert size={13} /> Exploit Confirmed</span>
  if (reproduced === "false")
    return <span className="badge badge-success"><ShieldOff size={13} /> Not Triggered</span>
  return <span className="badge badge-info" style={{ opacity: 0.7 }}><HelpCircle size={13} /> Not Checkable</span>
}

export default function FindingCard({ finding, index }) {
  const [expanded, setExpanded] = useState(false)
  const severity = (finding.severity || "low").toLowerCase()
  const color = SEVERITY_COLORS[severity] || SEVERITY_COLORS.low
  const badgeClass = severity === "critical" || severity === "high" ? "badge-danger"
    : severity === "medium" ? "badge-warning" : "badge-info"

  const llm = finding.llm_analysis
  const diff = parseDiff(finding.patch)

  return (
    <div className="finding-card animate-fade-in" style={{ borderLeft: `3px solid ${color}`, animationDelay: `${index * 0.04}s` }}>
      <div className="finding-head" onClick={() => setExpanded(!expanded)}>
        <div style={{ display: "flex", flexDirection: "column", gap: "0.4rem", flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", flexWrap: "wrap" }}>
            <span className={`badge ${badgeClass}`}>{severity}</span>
            <span style={{ fontWeight: 600, fontSize: "0.9rem" }}>{finding.rule_id}</span>
            {finding.cwe_ids?.length > 0 && (
              <span className="cwe-chip">{finding.cwe_ids.join(", ")}</span>
            )}
            {finding.reproduced === "true" && <ExploitBadge reproduced="true" />}
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", fontSize: "0.8rem", color: "var(--text-muted)", flexWrap: "wrap" }}>
            <span>{finding.tool}</span><span>•</span>
            <span>Line {finding.line_start}</span><span>•</span>
            <VerdictTag verdict={finding.fusion_verdict} />
          </div>
        </div>
        {expanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
      </div>

      {expanded && (
        <div className="finding-body">
          <p style={{ marginBottom: "1rem", lineHeight: 1.6 }}>{finding.message}</p>

          {/* Exploit Verification — the differentiator */}
          <div className="verify-block">
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: finding.repro_evidence?.stdout ? "0.5rem" : 0 }}>
              <h4 style={{ fontSize: "0.85rem" }}>Dynamic Verification</h4>
              <ExploitBadge reproduced={finding.reproduced} />
            </div>
            {finding.repro_evidence?.stdout && (
              <pre className="evidence"><code>{finding.repro_evidence.stdout}</code></pre>
            )}
          </div>

          {/* LLM Analysis */}
          {llm?.explanation && (
            <div className="ai-block">
              <h4 style={{ fontSize: "0.85rem", marginBottom: "0.5rem", color: "var(--accent)", display: "flex", alignItems: "center", gap: "0.5rem" }}>
                <Info size={14} /> AI Analysis
              </h4>
              <p style={{ fontSize: "0.85rem", lineHeight: 1.6 }}>{llm.explanation}</p>
              {llm.root_cause && <p style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginTop: "0.5rem" }}><strong>Root Cause:</strong> {llm.root_cause}</p>}
              {llm.fix_suggestion && <p style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginTop: "0.25rem" }}><strong>Suggested Fix:</strong> {llm.fix_suggestion}</p>}
              {llm.confidence !== undefined && (
                <div style={{ marginTop: "0.5rem", display: "flex", alignItems: "center", gap: "0.5rem" }}>
                  <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>LLM Confidence</span>
                  <div className="meter"><div style={{ width: `${(llm.confidence || 0) * 100}%` }} /></div>
                  <span style={{ fontSize: "0.75rem", color: "var(--accent)" }}>{((llm.confidence || 0) * 100).toFixed(0)}%</span>
                </div>
              )}
            </div>
          )}

          {/* RAG */}
          {finding.rag_docs?.length > 0 && (
            <div style={{ marginBottom: "1.25rem" }}>
              <h4 style={{ fontSize: "0.85rem", marginBottom: "0.5rem", color: "var(--text-muted)" }}>Security References</h4>
              {finding.rag_docs.map((doc, i) => (
                <div key={i} className="rag-doc">
                  <strong style={{ color: "var(--accent)" }}>{doc.id}</strong>: {(doc.text || "").substring(0, 200)}…
                </div>
              ))}
            </div>
          )}

          {/* SHAP */}
          {llm?.shap_values && (
            <div style={{ marginBottom: "1.25rem" }}>
              <h4 style={{ fontSize: "0.85rem", marginBottom: "0.5rem", color: "var(--text-muted)" }}>Decision Factors (SHAP)</h4>
              <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
                {Object.entries(llm.shap_values).map(([k, val]) => (
                  <span key={k} className="shap-chip" style={{
                    background: val > 0 ? "rgba(239,68,68,0.1)" : "rgba(34,197,94,0.1)",
                    color: val > 0 ? "var(--danger)" : "var(--success)",
                    border: `1px solid ${val > 0 ? "rgba(239,68,68,0.2)" : "rgba(34,197,94,0.2)"}`,
                  }}>{k}: {val > 0 ? "+" : ""}{val.toFixed(3)}</span>
                ))}
              </div>
            </div>
          )}

          {/* Patch diff */}
          {finding.patch && (
            <div>
              <h4 style={{ marginBottom: "0.5rem", display: "flex", alignItems: "center", gap: "0.5rem", fontSize: "0.85rem" }}>
                <CheckCircle size={14} color={finding.patch_status === "fixed" ? "var(--success)" : "var(--warning)"} />
                Generated Patch
                <span className={`badge ${finding.patch_status === "fixed" ? "badge-success" : "badge-warning"}`} style={{ fontSize: "0.7rem" }}>
                  {finding.patch_status}
                </span>
              </h4>
              <pre className="diff"><code>{diff.map((l, i) => (
                <div key={i} className={`diff-${l.type}`}>{l.text || " "}</div>
              ))}</code></pre>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
