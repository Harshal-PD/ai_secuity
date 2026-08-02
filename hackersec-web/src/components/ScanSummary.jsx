import { ShieldCheck } from "lucide-react"
import StatBox from "./StatBox"

export default function ScanSummary({ summary }) {
  if (!summary) return null

  if (summary.total === 0) {
    return (
      <section className="glass-panel animate-fade-in" style={{ padding: "2rem", textAlign: "center" }}>
        <ShieldCheck size={48} color="var(--success)" style={{ marginBottom: "1rem" }} />
        <h3 style={{ color: "var(--success)", marginBottom: "0.5rem" }}>No Vulnerabilities Detected</h3>
        <p style={{ color: "var(--text-muted)", fontSize: "0.875rem" }}>
          Static analysis (Semgrep + Bandit) found no security issues in this submission.
        </p>
      </section>
    )
  }

  return (
    <section className="glass-panel animate-fade-in" style={{ padding: "2rem" }}>
      <h3 style={{ marginBottom: "1rem", fontSize: "1rem" }}>Scan Results</h3>
      <div className="stat-grid">
        <StatBox
          label="Confirmed Exploitable" value={summary.confirmed}
          color="var(--danger)" highlight
        />
        <StatBox label="True Positives" value={summary.true_positive} color="#f97316" />
        <StatBox label="Total Findings" value={summary.total} color="var(--text-main)" />
        <StatBox label="Critical / High" value={summary.critical + summary.high} color="#f97316" />
      </div>
    </section>
  )
}
