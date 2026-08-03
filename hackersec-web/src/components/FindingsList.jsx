import { useMemo, useState } from "react"
import { Search } from "lucide-react"
import FindingCard from "./FindingCard"
import { SEVERITY_RANK } from "../lib/constants"

export default function FindingsList({ findings }) {
  const [severity, setSeverity] = useState("all")
  const [verdict, setVerdict] = useState("all")
  const [query, setQuery] = useState("")

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase()
    return findings
      .filter((f) => severity === "all" || (f.severity || "").toLowerCase() === severity)
      .filter((f) => verdict === "all" || f.fusion_verdict === verdict)
      .filter((f) => {
        if (!q) return true
        const hay = `${f.rule_id} ${f.message} ${(f.cwe_ids || []).join(" ")}`.toLowerCase()
        return hay.includes(q)
      })
      .sort((a, b) => (SEVERITY_RANK[(b.severity || "").toLowerCase()] || 0)
        - (SEVERITY_RANK[(a.severity || "").toLowerCase()] || 0))
  }, [findings, severity, verdict, query])

  return (
    <section className="glass-panel animate-fade-in" style={{ padding: "2rem", minHeight: "600px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.25rem", gap: "1rem", flexWrap: "wrap" }}>
        <h2 style={{ fontSize: "1.2rem" }}>
          Findings <span style={{ color: "var(--text-muted)", fontWeight: 400 }}>({shown.length})</span>
        </h2>
        <div className="toolbar">
          <div className="search-box">
            <Search size={14} />
            <input placeholder="Search rule, CWE, text…" value={query} onChange={(e) => setQuery(e.target.value)} />
          </div>
          <select className="input" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <select className="input" value={verdict} onChange={(e) => setVerdict(e.target.value)}>
            <option value="all">All verdicts</option>
            <option value="true_positive">True positive</option>
            <option value="false_positive">False positive</option>
            <option value="uncertain">Uncertain</option>
          </select>
        </div>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
        {shown.length === 0 ? (
          <p style={{ color: "var(--text-muted)", textAlign: "center", marginTop: "3rem" }}>
            No findings match the current filters.
          </p>
        ) : (
          shown.map((f, i) => <FindingCard key={f.id || i} finding={f} index={i} />)
        )}
      </div>
    </section>
  )
}
