import { useState, useEffect } from 'react'
import { UploadCloud, Shield, CheckCircle, AlertTriangle, XCircle, Activity, ChevronDown, ChevronUp } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import './index.css'

const API_BASE = "http://localhost:8000/api"

export default function App() {
  const [jobId, setJobId] = useState(null)
  const [status, setStatus] = useState(null)
  const [findings, setFindings] = useState([])
  const [metrics, setMetrics] = useState(null)
  
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
        setFindings(data.findings || [])
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

  return (
    <div className="container">
      <header style={{ marginBottom: '2rem', display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <Shield size={36} color="var(--accent)" />
        <h1 className="text-gradient">HackerSec Analytics</h1>
      </header>
      
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(300px, 1fr) 2fr', gap: '2rem', alignItems: 'start' }}>
        
        {/* Left Column: Upload & Metrics */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
            
          <section className="glass-panel animate-fade-in" style={{ padding: '2rem' }}>
            <h2 style={{ marginBottom: '1rem' }}>Submit Code</h2>
            <form onSubmit={handleFileUpload} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <input type="file" name="file" className="input" accept=".py" />
              <button type="submit" className="btn btn-primary" disabled={status === 'running' || status === 'pending'}>
                <UploadCloud size={20} /> Analyze Code
              </button>
            </form>
            
            {status && (
              <div style={{ marginTop: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Activity size={18} className={status === 'complete' ? '' : 'animate-pulse'} />
                <span style={{ textTransform: 'capitalize', color: status === 'failed' ? 'var(--danger)' : 'var(--accent)'}}>
                  Job Status: {status}
                </span>
              </div>
            )}
          </section>
          
          {/* Analytics Dashboard */}
          {metrics && (
            <section className="glass-panel animate-fade-in" style={{ padding: '2rem' }}>
               <h2 style={{ marginBottom: '1rem' }}>Model Performance</h2>
               <div style={{ height: 250 }}>
                 <ResponsiveContainer width="100%" height="100%">
                   <BarChart data={[
                     { name: 'Precision', HackerSec: metrics.hackersec_metrics.precision, Semgrep: metrics.baseline_metrics.precision },
                     { name: 'Recall', HackerSec: metrics.hackersec_metrics.recall, Semgrep: metrics.baseline_metrics.recall },
                     { name: 'F1 Score', HackerSec: metrics.hackersec_metrics.f1, Semgrep: metrics.baseline_metrics.f1 }
                   ]}>
                     <XAxis dataKey="name" stroke="var(--text-muted)" />
                     <YAxis stroke="var(--text-muted)" />
                     <Tooltip contentStyle={{ backgroundColor: 'var(--bg-dark)', border: '1px solid var(--border)' }} />
                     <Legend />
                     <Bar dataKey="HackerSec" fill="var(--accent)" radius={[4, 4, 0, 0]} />
                     <Bar dataKey="Semgrep" fill="var(--text-muted)" radius={[4, 4, 0, 0]} />
                   </BarChart>
                 </ResponsiveContainer>
               </div>
            </section>
          )}
        </div>

        {/* Right Column: Findings Matrix */}
        <section className="glass-panel animate-fade-in" style={{ padding: '2rem', minHeight: '600px' }}>
          <h2>Analysis Findings {findings.length > 0 && `(${findings.length})`}</h2>
          
          <div style={{ marginTop: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {findings.length === 0 && status !== 'pending' && status !== 'running' && (
               <div style={{ color: 'var(--text-muted)', textAlign: 'center', marginTop: '3rem' }}>
                   No vulnerable findings mapped yet. Upload a python file to scan.
               </div>
            )}
            
            {findings.map((f, i) => <FindingCard key={i} finding={f} />)}
          </div>
        </section>

      </div>
    </div>
  )
}

function FindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false)
  
  const getSeverityBadge = () => {
      switch(finding.severity) {
          case 'CRITICAL':
          case 'HIGH': return <span className="badge badge-danger">High Severity</span>
          case 'MEDIUM': return <span className="badge badge-warning">Medium Severity</span>
          default: return <span className="badge badge-info">Low Severity</span>
      }
  }

  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: '8px', overflow: 'hidden', transition: 'all 0.2s' }}>
      <div 
        onClick={() => setExpanded(!expanded)}
        style={{ padding: '1rem', background: 'rgba(0,0,0,0.2)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                {getSeverityBadge()}
                <span style={{ fontWeight: 600 }}>{finding.rule_id}</span>
            </div>
            <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
                Line {finding.line_start} • Prediction: 
                <span style={{ 
                    color: finding.fusion_verdict === 'true_positive' ? 'var(--danger)' : finding.fusion_verdict === 'false_positive' ? 'var(--success)' : 'var(--warning)', 
                    marginLeft: 4, fontWeight: 'bold', textTransform: 'uppercase'
                }}>
                    {finding.fusion_verdict}
                </span>
            </span>
        </div>
        {expanded ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
      </div>
      
      {expanded && (
          <div style={{ padding: '1.5rem', background: 'var(--bg-panel)', borderTop: '1px solid var(--border)' }}>
             <p style={{ marginBottom: '1rem', color: 'var(--text-main)' }}>{finding.message}</p>
             
             {finding.patch && (
                 <div style={{ marginTop: '1.5rem' }}>
                   <h4 style={{ marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <CheckCircle size={16} color={finding.patch_status === 'fixed' ? 'var(--success)' : 'var(--warning)'} /> 
                      Generated Fix
                   </h4>
                   <pre style={{ 
                       background: 'rgba(0,0,0,0.4)', padding: '1rem', borderRadius: '6px', overflowX: 'auto', 
                       border: '1px solid var(--border)', fontSize: '0.875rem' 
                   }}>
                       <code style={{ fontFamily: 'monospace' }}>{finding.patch}</code>
                   </pre>
                 </div>
             )}
          </div>
      )}
    </div>
  )
}
