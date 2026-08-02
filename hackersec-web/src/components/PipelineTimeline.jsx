import { CheckCircle, Circle, XCircle } from "lucide-react"
import { STAGES } from "../lib/constants"

// Live pipeline stepper. Driven purely by (status, stage) from /status polling.
export default function PipelineTimeline({ status, stage }) {
  const complete = status === "complete"
  const failed = status === "failed"
  const current = STAGES.findIndex((s) => s.key === stage)

  const stepState = (i) => {
    if (complete) return "done"
    if (failed && i === current) return "error"
    if (current === -1) return i === 0 ? "active" : "pending" // queued, nothing emitted yet
    if (i < current) return "done"
    if (i === current) return "active"
    return "pending"
  }

  return (
    <section className="glass-panel animate-fade-in" style={{ padding: "1.75rem 2rem" }}>
      <h3 style={{ marginBottom: "1.25rem", fontSize: "1rem" }}>Analysis Pipeline</h3>
      <div className="pipeline">
        {STAGES.map((s, i) => {
          const st = stepState(i)
          return (
            <div key={s.key} className={`pipeline-step ${st}`}>
              <span className="pipeline-icon">
                {st === "done" ? <CheckCircle size={18} />
                  : st === "error" ? <XCircle size={18} />
                  : st === "active" ? <span className="spinner spinner-sm" />
                  : <Circle size={18} />}
              </span>
              <span className="pipeline-label">{s.label}</span>
              {i < STAGES.length - 1 && <span className="pipeline-line" />}
            </div>
          )
        })}
      </div>
    </section>
  )
}
