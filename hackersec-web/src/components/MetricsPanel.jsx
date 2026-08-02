import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from "recharts"

const pct = (v) => (v == null ? 0 : +(v * 100).toFixed(1))

export default function MetricsPanel({ metrics }) {
  if (!metrics || !metrics.hackersec_metrics || !(metrics.hackersec_metrics.f1 > 0)) return null

  const b = metrics.baseline_metrics
  const h = metrics.hackersec_metrics
  const v = metrics.hackersec_verified_metrics // present only when verify ran with hits

  const data = [
    { name: "Precision", Baseline: pct(b.precision), HackerSec: pct(h.precision), Verified: pct(v?.precision) },
    { name: "Recall", Baseline: pct(b.recall), HackerSec: pct(h.recall), Verified: pct(v?.recall) },
    { name: "F1", Baseline: pct(b.f1), HackerSec: pct(h.f1), Verified: pct(v?.f1) },
  ]

  return (
    <section className="glass-panel animate-fade-in" style={{ padding: "2rem" }}>
      <h3 style={{ marginBottom: "1rem", fontSize: "1rem" }}>Model Performance</h3>
      <div style={{ height: 240 }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data}>
            <XAxis dataKey="name" stroke="var(--text-muted)" fontSize={12} />
            <YAxis stroke="var(--text-muted)" fontSize={12} unit="%" domain={[0, 100]} />
            <Tooltip
              contentStyle={{ backgroundColor: "var(--bg-dark)", border: "1px solid var(--border)", borderRadius: "8px" }}
              formatter={(val) => `${val}%`}
            />
            <Legend />
            <Bar dataKey="Baseline" fill="var(--text-muted)" radius={[4, 4, 0, 0]} />
            <Bar dataKey="HackerSec" fill="var(--accent)" radius={[4, 4, 0, 0]} />
            {v && <Bar dataKey="Verified" fill="var(--danger)" radius={[4, 4, 0, 0]} />}
          </BarChart>
        </ResponsiveContainer>
      </div>
      <p style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.5rem" }}>
        Baseline = Semgrep-only{v ? ". Verified = repro-gated (sandbox-confirmed only)." : "."}
      </p>
    </section>
  )
}
