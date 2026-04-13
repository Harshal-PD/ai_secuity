import { useState, useEffect } from 'react'
import { UploadCloud, Shield, ShieldCheck, CheckCircle, AlertTriangle, XCircle, Activity, ChevronDown, ChevronUp, FileWarning, Info } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend, PieChart, Pie, Cell } from 'recharts'
import './index.css'

const API_BASE = "http://localhost:8000/api"

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
}

export default function App() {
  const [jobId, setJobId] = useState(null)
  const [status, setStatus] = useState(null)
  const [findings, setFindings] = useState([])
  const [metrics, setMetrics] = useState(null)
  const [severityFilter, setSeverityFilter] = useState('all')
  const [scanSummary, setScanSummary] = useState(null)
  
  // Polling Job Status
  useEffect(() => {
    let interval;
    if (jobId && status !== 'complete' && status !== 'failed') {
      interval = setInterval(async () => {
        try {
          const r = await fetch(`${API_BASE}/status/${jobId}`)
          if (r.ok) {
            const data = await r.json()
            setStatus(data.status)
            if (data.status === 'complete') fetchResults(jobId)
          }
        } catch (e) {
             console.error(e)
        }
      }, 2000)
    }
    return () => clearInterval(interval)
  }, [jobId, status])
  
  useEffect(() => {
      fetchMetrics()
  }, [])
  
  const fetchMetrics = async () => {
      try {
          const r = await fetch(`${API_BASE}/metrics`)
          if(r.ok) setMetrics(await r.json())
      } catch (e) { console.error(e) }
  }

  const fetchResults = async (id) => {
    try {
      const r = await fetch(`${API_BASE}/results/${id}`)
      if (r.ok) {
        const data = await r.json()
        const f = data.findings || []
        setFindings(f)
        
        // Build scan summary
        const counts = { critical: 0, high: 0, medium: 0, low: 0, true_positive: 0, false_positive: 0 }
        f.forEach(finding => {
          const sev = (finding.severity || '').toLowerCase()
          if (counts[sev] !== undefined) counts[sev]++
          if (finding.fusion_verdict === 'true_positive') counts.true_positive++
          else if (finding.fusion_verdict === 'false_positive') counts.false_positive++
        })
        setScanSummary({ total: f.length, ...counts })
      }
    } catch(e) { console.error(e) }
  }

  const handleFileUpload = async (e) => {
    e.preventDefault()
    const file = e.target.file.files[0]
    if (!file) return
    const formData = new FormData()
    formData.append('file', file)
    
    try {
      setStatus('pending')
      setFindings([])
      setScanSummary(null)
      setSeverityFilter('all')
      const response = await fetch(`${API_BASE}/upload`, {
        method: 'POST',
        body: formData,
      })
      if(response.ok) {
          const data = await response.json()
          setJobId(data.job_id)
      } else {
          setStatus('failed')
      }
    } catch(e) {
      setStatus('failed')
    }
  }

  const filteredFindings = severityFilter === 'all' 
    ? findings 
    : findings.filter(f => (f.severity || '').toLowerCase() === severityFilter)

  return (
    <div className="container">
      <header style={{ marginBottom: '2rem', display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <Shield size={36} color="var(--accent)" />
        <div>
          <h1 className="text-gradient">HackerSec</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginTop: '0.25rem' }}>
            AI-Driven Security Code Reviewer & Vulnerability Analysis
          </p>
        </div>
      </header>
      
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(300px, 1fr) 2fr', gap: '2rem', alignItems: 'start' }}>
        
        {/* Left Column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
            
          {/* Upload Card */}
          <section className="glass-panel animate-fade-in" style={{ padding: '2rem' }}>
            <h2 style={{ marginBottom: '1rem', fontSize: '1.1rem' }}>Submit Code for Analysis</h2>
            <form onSubmit={handleFileUpload} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <input type="file" name="file" className="input" accept=".py,.js,.java,.c,.cpp,.go" />
              <button type="submit" className="btn btn-primary" disabled={status === 'running' || status === 'pending'}>
                <UploadCloud size={20} /> {status === 'pending' || status === 'running' ? 'Analyzing...' : 'Analyze Code'}
              </button>
            </form>
            
            {status && (
              <div style={{ marginTop: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                {status === 'complete' ? (
                  <CheckCircle size={18} color="var(--success)" />
                ) : status === 'failed' ? (
                  <XCircle size={18} color="var(--danger)" />
                ) : (
                  <Activity size={18} style={{ animation: 'pulse 1.5s infinite' }} />
                )}
                <span style={{ 
                  textTransform: 'capitalize', 
                  color: status === 'failed' ? 'var(--danger)' : status === 'complete' ? 'var(--success)' : 'var(--accent)',
                  fontWeight: 500
                }}>
                  {status === 'pending' ? 'Queued for analysis...' : 
                   status === 'running' ? 'Pipeline running...' :
                   status === 'complete' ? 'Analysis complete' :
                   'Analysis failed'}
                </span>
              </div>
            )}
          </section>

          {/* Scan Summary Card — shown after completion */}
          {status === 'complete' && scanSummary && (
            <section className="glass-panel animate-fade-in" style={{ padding: '2rem' }}>
              {scanSummary.total === 0 ? (
                <div style={{ textAlign: 'center', padding: '1rem' }}>
                  <ShieldCheck size={48} color="var(--success)" style={{ marginBottom: '1rem' }} />
                  <h3 style={{ color: 'var(--success)', marginBottom: '0.5rem' }}>No Vulnerabilities Detected</h3>
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
                    Static analysis (Semgrep + Bandit) found no security issues in this file. 
                    The code appears to follow secure coding practices.
                  </p>
                </div>
              ) : (
                <>
                  <h3 style={{ marginBottom: '1rem', fontSize: '1rem' }}>Scan Results</h3>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                    <StatBox label="Total Findings" value={scanSummary.total} color="var(--text-main)" />
                    <StatBox label="True Positives" value={scanSummary.true_positive} color="var(--danger)" />
                    <StatBox label="Critical / High" value={scanSummary.critical + scanSummary.high} color="#f97316" />
                    <StatBox label="Medium / Low" value={scanSummary.medium + scanSummary.low} color="var(--accent)" />
                  </div>
                </>
              )}
            </section>
          )}
          
          {/* Metrics Chart */}
          {metrics && metrics.hackersec_metrics && metrics.hackersec_metrics.f1 > 0 && (
            <section className="glass-panel animate-fade-in" style={{ padding: '2rem' }}>
               <h3 style={{ marginBottom: '1rem', fontSize: '1rem' }}>Model Performance</h3>
               <div style={{ height: 220 }}>
                 <ResponsiveContainer width="100%" height="100%">
                   <BarChart data={[
                     { name: 'Precision', HackerSec: (metrics.hackersec_metrics.precision * 100).toFixed(1), Semgrep: (metrics.baseline_metrics.precision * 100).toFixed(1) },
                     { name: 'Recall', HackerSec: (metrics.hackersec_metrics.recall * 100).toFixed(1), Semgrep: (metrics.baseline_metrics.recall * 100).toFixed(1) },
                     { name: 'F1 Score', HackerSec: (metrics.hackersec_metrics.f1 * 100).toFixed(1), Semgrep: (metrics.baseline_metrics.f1 * 100).toFixed(1) }
                   ]}>
                     <XAxis dataKey="name" stroke="var(--text-muted)" fontSize={12} />
                     <YAxis stroke="var(--text-muted)" fontSize={12} unit="%" />
                     <Tooltip 
                       contentStyle={{ backgroundColor: 'var(--bg-dark)', border: '1px solid var(--border)', borderRadius: '8px' }}
                       formatter={(value) => `${value}%`}
                     />
                     <Legend />
                     <Bar dataKey="HackerSec" fill="var(--accent)" radius={[4, 4, 0, 0]} />
                     <Bar dataKey="Semgrep" fill="var(--text-muted)" radius={[4, 4, 0, 0]} />
                   </BarChart>
                 </ResponsiveContainer>
               </div>
            </section>
          )}
        </div>

        {/* Right Column: Findings */}
        <section className="glass-panel animate-fade-in" style={{ padding: '2rem', minHeight: '600px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
            <h2 style={{ fontSize: '1.2rem' }}>
              Analysis Findings {filteredFindings.length > 0 && <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>({filteredFindings.length})</span>}
            </h2>
            
            {findings.length > 0 && (
              <select 
                value={severityFilter} 
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="input"
                style={{ width: 'auto', padding: '0.5rem 1rem', fontSize: '0.875rem' }}
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            )}
          </div>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {/* Initial empty state */}
            {!status && findings.length === 0 && (
               <div style={{ color: 'var(--text-muted)', textAlign: 'center', marginTop: '4rem' }}>
                   <FileWarning size={48} style={{ marginBottom: '1rem', opacity: 0.4 }} />
                   <p>Upload a source file to begin security analysis.</p>
                   <p style={{ fontSize: '0.8rem', marginTop: '0.5rem' }}>Supports Python, JavaScript, Java, C/C++, and Go</p>
               </div>
            )}
            
            {/* Loading state */}
            {(status === 'pending' || status === 'running') && (
              <div style={{ color: 'var(--accent)', textAlign: 'center', marginTop: '4rem' }}>
                <div className="spinner" style={{ margin: '0 auto 1rem' }}></div>
                <p>Running security analysis pipeline...</p>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>
                  Semgrep → Bandit → Joern CPG → RAG Lookup → LLM Analysis → ML Fusion
                </p>
              </div>
            )}

            {/* Complete with no findings */}
            {status === 'complete' && findings.length === 0 && (
              <div style={{ textAlign: 'center', marginTop: '4rem' }}>
                <ShieldCheck size={64} color="var(--success)" style={{ marginBottom: '1rem' }} />
                <h3 style={{ color: 'var(--success)', marginBottom: '0.5rem' }}>Code Looks Clean!</h3>
                <p style={{ color: 'var(--text-muted)', maxWidth: '400px', margin: '0 auto' }}>
                  No security vulnerabilities were detected by the static analysis tools. 
                  You can try uploading a different file or a known-vulnerable test file.
                </p>
              </div>
            )}
            
            {filteredFindings.map((f, i) => <FindingCard key={i} finding={f} index={i} />)}
          </div>
        </section>

      </div>
    </div>
  )
}

function StatBox({ label, value, color }) {
  return (
    <div style={{ 
      padding: '0.75rem', 
      background: 'rgba(0,0,0,0.2)', 
      borderRadius: '8px', 
      textAlign: 'center',
      border: '1px solid var(--border)'
    }}>
      <div style={{ fontSize: '1.5rem', fontWeight: 700, color, fontFamily: "'Outfit', sans-serif" }}>{value}</div>
      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>{label}</div>
    </div>
  )
}

function FindingCard({ finding, index }) {
  const [expanded, setExpanded] = useState(false)
  
  const severity = (finding.severity || 'low').toLowerCase()
  const severityColor = SEVERITY_COLORS[severity] || SEVERITY_COLORS.low
  
  const badgeClass = severity === 'critical' || severity === 'high' ? 'badge-danger' 
    : severity === 'medium' ? 'badge-warning' 
    : 'badge-info'

  return (
    <div className="animate-fade-in" style={{ 
      border: '1px solid var(--border)', 
      borderRadius: '8px', 
      overflow: 'hidden', 
      borderLeft: `3px solid ${severityColor}`,
      animationDelay: `${index * 0.05}s`
    }}>
      <div 
        onClick={() => setExpanded(!expanded)}
        style={{ padding: '1rem', background: 'rgba(0,0,0,0.2)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                <span className={`badge ${badgeClass}`}>{severity}</span>
                <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>{finding.rule_id}</span>
                {finding.cwe_ids && finding.cwe_ids.length > 0 && (
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', background: 'rgba(255,255,255,0.05)', padding: '0.15rem 0.5rem', borderRadius: '4px' }}>
                    {finding.cwe_ids.join(', ')}
                  </span>
                )}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                <span>{finding.tool}</span>
                <span>•</span>
                <span>Line {finding.line_start}</span>
                <span>•</span>
                <span style={{ 
                    color: finding.fusion_verdict === 'true_positive' ? 'var(--danger)' : finding.fusion_verdict === 'false_positive' ? 'var(--success)' : 'var(--warning)', 
                    fontWeight: 600, textTransform: 'uppercase', fontSize: '0.75rem',
                    padding: '0.1rem 0.4rem', borderRadius: '3px',
                    background: finding.fusion_verdict === 'true_positive' ? 'rgba(239,68,68,0.1)' : finding.fusion_verdict === 'false_positive' ? 'rgba(34,197,94,0.1)' : 'rgba(234,179,8,0.1)'
                }}>
                    {finding.fusion_verdict || 'pending'}
                </span>
            </div>
        </div>
        {expanded ? <ChevronUp size={18} /> : <ChevronDown size={18} />}
      </div>
      
      {expanded && (
          <div style={{ padding: '1.5rem', background: 'var(--bg-panel)', borderTop: '1px solid var(--border)' }}>
             {/* Finding Message */}
             <p style={{ marginBottom: '1rem', color: 'var(--text-main)', lineHeight: 1.6 }}>{finding.message}</p>
             
             {/* LLM Analysis */}
             {finding.llm_analysis && finding.llm_analysis.explanation && (
               <div style={{ marginBottom: '1.25rem', padding: '1rem', background: 'rgba(59,130,246,0.05)', borderRadius: '8px', border: '1px solid rgba(59,130,246,0.1)' }}>
                 <h4 style={{ fontSize: '0.85rem', marginBottom: '0.5rem', color: 'var(--accent)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                   <Info size={14} /> AI Analysis
                 </h4>
                 <p style={{ fontSize: '0.85rem', color: 'var(--text-main)', lineHeight: 1.6 }}>{finding.llm_analysis.explanation}</p>
                 {finding.llm_analysis.root_cause && (
                   <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>
                     <strong>Root Cause:</strong> {finding.llm_analysis.root_cause}
                   </p>
                 )}
                 {finding.llm_analysis.fix_suggestion && (
                   <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                     <strong>Suggested Fix:</strong> {finding.llm_analysis.fix_suggestion}
                   </p>
                 )}
                 {finding.llm_analysis.confidence !== undefined && (
                   <div style={{ marginTop: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                     <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>LLM Confidence:</span>
                     <div style={{ flex: 1, maxWidth: '120px', height: '6px', background: 'rgba(255,255,255,0.1)', borderRadius: '3px' }}>
                       <div style={{ 
                         width: `${(finding.llm_analysis.confidence || 0) * 100}%`, 
                         height: '100%', 
                         background: 'var(--accent)', 
                         borderRadius: '3px',
                         transition: 'width 0.3s ease'
                       }} />
                     </div>
                     <span style={{ fontSize: '0.75rem', color: 'var(--accent)' }}>
                       {((finding.llm_analysis.confidence || 0) * 100).toFixed(0)}%
                     </span>
                   </div>
                 )}
               </div>
             )}

             {/* RAG Context */}
             {finding.rag_docs && finding.rag_docs.length > 0 && (
               <div style={{ marginBottom: '1.25rem' }}>
                 <h4 style={{ fontSize: '0.85rem', marginBottom: '0.5rem', color: 'var(--text-muted)' }}>Security References</h4>
                 {finding.rag_docs.map((doc, i) => (
                   <div key={i} style={{ 
                     fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.5rem',
                     padding: '0.5rem 0.75rem', background: 'rgba(0,0,0,0.2)', borderRadius: '6px',
                     borderLeft: '2px solid var(--accent)'
                   }}>
                     <strong style={{ color: 'var(--accent)' }}>{doc.id}</strong>: {(doc.text || '').substring(0, 200)}...
                   </div>
                 ))}
               </div>
             )}
             
             {/* SHAP Values */}
             {finding.llm_analysis && finding.llm_analysis.shap_values && (
               <div style={{ marginBottom: '1.25rem' }}>
                 <h4 style={{ fontSize: '0.85rem', marginBottom: '0.5rem', color: 'var(--text-muted)' }}>Decision Factors (SHAP)</h4>
                 <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                   {Object.entries(finding.llm_analysis.shap_values).map(([key, val]) => (
                     <span key={key} style={{ 
                       fontSize: '0.75rem', padding: '0.25rem 0.5rem', borderRadius: '4px',
                       background: val > 0 ? 'rgba(239,68,68,0.1)' : 'rgba(34,197,94,0.1)',
                       color: val > 0 ? 'var(--danger)' : 'var(--success)',
                       border: `1px solid ${val > 0 ? 'rgba(239,68,68,0.2)' : 'rgba(34,197,94,0.2)'}`
                     }}>
                       {key}: {val > 0 ? '+' : ''}{val.toFixed(3)}
                     </span>
                   ))}
                 </div>
               </div>
             )}

             {/* Patch */}
             {finding.patch && (
                 <div style={{ marginTop: '0.5rem' }}>
                   <h4 style={{ marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem' }}>
                      <CheckCircle size={14} color={finding.patch_status === 'fixed' ? 'var(--success)' : 'var(--warning)'} /> 
                      Generated Patch 
                      <span className={`badge ${finding.patch_status === 'fixed' ? 'badge-success' : 'badge-warning'}`} style={{ fontSize: '0.7rem' }}>
                        {finding.patch_status}
                      </span>
                   </h4>
                   <pre style={{ 
                       background: 'rgba(0,0,0,0.4)', padding: '1rem', borderRadius: '6px', overflowX: 'auto', 
                       border: '1px solid var(--border)', fontSize: '0.8rem', lineHeight: 1.5
                   }}>
                       <code style={{ fontFamily: "'Fira Code', 'Cascadia Code', monospace" }}>{finding.patch}</code>
                   </pre>
                 </div>
             )}
          </div>
      )}
    </div>
  )
}
