// Must match hackersec/analysis/pipeline.py::STAGES (+ the "static" prefix stage).
export const STAGES = [
  { key: "static", label: "Static Analysis" },
  { key: "cpg", label: "CPG Taint Flow" },
  { key: "rag", label: "RAG Grounding" },
  { key: "llm", label: "LLM Reasoning" },
  { key: "fusion", label: "ML Fusion" },
  { key: "verify", label: "Exploit Verify" },
  { key: "patch", label: "Patch Gen" },
]

export const SEVERITY_COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
}

export const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 }
