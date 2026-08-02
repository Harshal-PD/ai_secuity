// Central API layer. Dev requests proxy to :8000 via vite.config.js.
const API_BASE = "/api"

async function json(res) {
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.json()
}

export function uploadFile(file) {
  const form = new FormData()
  form.append("file", file)
  return fetch(`${API_BASE}/upload`, { method: "POST", body: form }).then(json)
}

export function analyzeRepo(repoUrl) {
  return fetch(`${API_BASE}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ repo_url: repoUrl }),
  }).then(json)
}

export const getStatus = (id) => fetch(`${API_BASE}/status/${id}`).then(json)
export const getResults = (id) => fetch(`${API_BASE}/results/${id}`).then(json)
export const getMetrics = () => fetch(`${API_BASE}/metrics`).then(json)
