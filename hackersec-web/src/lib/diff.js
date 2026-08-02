// Parse a unified-diff string into typed lines for red/green rendering.
// Matches the output of hackersec/analysis/patch/differ.py::compute_diff.
export function parseDiff(patch) {
  if (!patch) return []
  return patch.split("\n").map((line) => {
    if (line.startsWith("+++") || line.startsWith("---") || line.startsWith("@@")) {
      return { type: "meta", text: line }
    }
    if (line.startsWith("+")) return { type: "add", text: line }
    if (line.startsWith("-")) return { type: "del", text: line }
    return { type: "ctx", text: line }
  })
}
