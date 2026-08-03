import { useState } from "react"
import { UploadCloud, GitBranch, FileCode } from "lucide-react"

const busy = (s) => s === "pending" || s === "running"

export default function UploadPanel({ status, onFile, onRepo }) {
  const [mode, setMode] = useState("file")
  const [repoUrl, setRepoUrl] = useState("")

  const submitFile = (e) => {
    e.preventDefault()
    const file = e.target.file.files[0]
    if (file) onFile(file)
  }
  const submitRepo = (e) => {
    e.preventDefault()
    if (repoUrl.trim()) onRepo(repoUrl.trim())
  }

  return (
    <section className="glass-panel animate-fade-in" style={{ padding: "2rem" }}>
      <h2 style={{ marginBottom: "1rem", fontSize: "1.1rem" }}>Submit Code for Analysis</h2>

      <div className="seg-toggle">
        <button className={mode === "file" ? "active" : ""} onClick={() => setMode("file")}>
          <FileCode size={15} /> File
        </button>
        <button className={mode === "git" ? "active" : ""} onClick={() => setMode("git")}>
          <GitBranch size={15} /> Git URL
        </button>
      </div>

      {mode === "file" ? (
        <form onSubmit={submitFile} style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          <input type="file" name="file" className="input" accept=".py,.js,.java,.c,.cpp,.go" />
          <button type="submit" className="btn btn-primary" disabled={busy(status)}>
            <UploadCloud size={20} /> {busy(status) ? "Analyzing..." : "Analyze Code"}
          </button>
        </form>
      ) : (
        <form onSubmit={submitRepo} style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          <input
            className="input" placeholder="https://github.com/user/repo.git"
            value={repoUrl} onChange={(e) => setRepoUrl(e.target.value)}
          />
          <button type="submit" className="btn btn-primary" disabled={busy(status)}>
            <GitBranch size={20} /> {busy(status) ? "Analyzing..." : "Clone & Analyze"}
          </button>
        </form>
      )}
    </section>
  )
}
