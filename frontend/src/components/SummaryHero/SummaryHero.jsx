import "./SummaryHero.css"
import { Radar, CheckCircle2, FileSearch, Clock } from "lucide-react"
import { timeAgo, formatTimestamp } from "../../utils/risk"

function SummaryHero() {
  let scannedFiles = 0
  let totalFindings = 0
  let lastScan = null
  try {
    const persisted = JSON.parse(localStorage.getItem("qbits_latest_analysis"))
    if (persisted) {
      scannedFiles = persisted.files_scanned || 0
      totalFindings = persisted.crypto_assets_found || (persisted.findings || []).length
      lastScan = persisted.scanned_at || null
    }
  } catch {
    /* ignore */
  }
  const relTime = lastScan ? timeAgo(lastScan) : "never"
  const exactTime = lastScan ? formatTimestamp(lastScan) : "-"

  return (
    <section className="hero">
      <div className="hero__content">
        <div className="hero__brand">
          <div className="hero__logo">
            <Radar size={22} strokeWidth={2} />
          </div>
          <div className="hero__title-group">
            <h1 className="hero__title">Q-BITS ECDAT</h1>
            <span className="hero__subtitle">Post-Quantum Cryptographic Risk Intelligence</span>
          </div>
        </div>

        <div className="hero__metrics">
          <div className="hero__metric">
            <FileSearch size={14} strokeWidth={2} className="hero__metric-icon" />
            <span className="hero__metric-value">{scannedFiles.toLocaleString()}</span>
            <span className="hero__metric-label">Files scanned</span>
          </div>
          <div className="hero__metric-sep" />
          <div className="hero__metric">
            <span className="hero__metric-value hero__metric-value--accent">{totalFindings}</span>
            <span className="hero__metric-label">Findings</span>
          </div>
          <div className="hero__metric-sep" />
          <div className="hero__metric">
            <Clock size={14} strokeWidth={2} className="hero__metric-icon" />
            <span className="hero__metric-value" title={exactTime}>{relTime}</span>
            <span className="hero__metric-label">Last scan</span>
          </div>
          <div className="hero__metric-sep" />
          <div className="hero__metric">
            <CheckCircle2 size={14} strokeWidth={2} className="hero__metric-icon hero__metric-icon--ok" />
            <span className="hero__metric-value hero__metric-value--ok">Completed</span>
            <span className="hero__metric-label">Status</span>
          </div>
        </div>
      </div>

      <div className="hero__glow" aria-hidden="true" />
    </section>
  )
}

export default SummaryHero
