import { useState, useEffect, useCallback } from "react"
import { Shield, FileWarning } from "lucide-react"
import { uploadFile, analyzeRepo, getStatus, getResults, getMetrics } from "./lib/api"
import UploadPanel from "./components/UploadPanel"
import PipelineTimeline from "./components/PipelineTimeline"
import ScanSummary from "./components/ScanSummary"
import MetricsPanel from "./components/MetricsPanel"
import FindingsList from "./components/FindingsList"
import "./index.css"

export default function App() {
  const [jobId, setJobId] = useState(null)
  const [status, setStatus] = useState(null)
  const [stage, setStage] = useState(null)
  const [findings, setFindings] = useState([])
  const [summary, setSummary] = useState(null)
  const [metrics, setMetrics] = useState(null)

  useEffect(() => { getMetrics().then(setMetrics).catch(() => {}) }, [])

  const loadResults = useCallback(async (id) => {
    try {
      const data = await getResults(id)
      const f = data.findings || []
      setFindings(f)
      const c = { critical: 0, high: 0, medium: 0, low: 0, true_positive: 0, confirmed: 0 }
      f.forEach((x) => {
        const s = (x.severity || "").toLowerCase()
        if (c[s] !== undefined) c[s]++
        if (x.fusion_verdict === "true_positive") c.true_positive++
        if (x.reproduced === "true") c.confirmed++
      })
      setSummary({ total: f.length, ...c })
    } catch (e) { console.error(e) }
  }, [])

  // Poll status every 2s while a job runs; pick up stage for the live timeline.
  useEffect(() => {
    if (!jobId || status === "complete" || status === "failed") return
    const iv = setInterval(async () => {
      try {
        const data = await getStatus(jobId)
        setStatus(data.status)
        setStage(data.stage)
        if (data.status === "complete") loadResults(jobId)
      } catch (e) { console.error(e) }
    }, 2000)
    return () => clearInterval(iv)
  }, [jobId, status, loadResults])

  const start = async (promise) => {
    setStatus("pending"); setStage(null); setFindings([]); setSummary(null)
    try {
      const data = await promise
      setJobId(data.job_id)
    } catch (e) { console.error(e); setStatus("failed") }
  }

  const showTimeline = status && status !== "failed"

  return (
    <div className="container">
      <header style={{ marginBottom: "2rem", display: "flex", alignItems: "center", gap: "1rem" }}>
        <Shield size={36} color="var(--accent)" />
        <div>
          <h1 className="text-gradient">HackerSec</h1>
          <p style={{ color: "var(--text-muted)", fontSize: "0.875rem", marginTop: "0.25rem" }}>
            AI-Driven Security Code Reviewer — findings confirmed by sandbox execution
          </p>
        </div>
      </header>

      <div className="layout">
        <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
          <UploadPanel status={status} onFile={(f) => start(uploadFile(f))} onRepo={(u) => start(analyzeRepo(u))} />
          {showTimeline && <PipelineTimeline status={status} stage={stage} />}
          {status === "complete" && <ScanSummary summary={summary} />}
          <MetricsPanel metrics={metrics} />
        </div>

        {findings.length > 0 ? (
          <FindingsList findings={findings} />
        ) : (
          <section className="glass-panel" style={{ padding: "2rem", minHeight: "600px", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <div style={{ color: "var(--text-muted)", textAlign: "center" }}>
              <FileWarning size={48} style={{ marginBottom: "1rem", opacity: 0.4 }} />
              <p>{status === "complete" ? "No findings for this submission." : "Submit a file or git repo to begin."}</p>
              <p style={{ fontSize: "0.8rem", marginTop: "0.5rem" }}>Python, JavaScript, Java, C/C++, Go</p>
            </div>
          </section>
        )}
      </div>
    </div>
  )
}
