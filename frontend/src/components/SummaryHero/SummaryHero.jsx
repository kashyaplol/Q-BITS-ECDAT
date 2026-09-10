import "./SummaryHero.css"
import { FolderGit2, CheckCircle2, FileSearch, Clock } from "lucide-react"
import { timeAgo, formatTimestamp } from "../../utils/risk"

function SummaryHero({ analysis }) {
  const scannedAt = analysis?.scannedAt
  const relTime = scannedAt ? timeAgo(scannedAt) : "Not scanned"
  const exactTime = scannedAt ? formatTimestamp(scannedAt) : ""
  
  const path = analysis?.scanned_path
  const repoName = path ? path.split(/[/\\]/).pop() || path : "No active scan"

  return (
    <section className="hero">
      <div className="hero__content">
        <div className="hero__brand">
          <div className="hero__logo">
            <FolderGit2 size={22} strokeWidth={2} />
          </div>

          <div className="hero__title-group">
            <h1 className="hero__title">{repoName}</h1>
            <span className="hero__subtitle">
              {path || "Run a new scan to assess cryptographic risk"}
            </span>
          </div>
        </div>

        <div className="hero__metrics">
          <div className="hero__metric">
            <FileSearch
              size={14}
              strokeWidth={2}
              className="hero__metric-icon"
            />
            <span className="hero__metric-value">
              {(analysis?.files_scanned ?? 0).toLocaleString()}
            </span>
            <span className="hero__metric-label">Files scanned</span>
          </div>

          <div className="hero__metric-sep" />

          <div className="hero__metric">
            <span className="hero__metric-value hero__metric-value--accent">
              {analysis?.finding_count ?? analysis?.crypto_assets_found ?? 0}
            </span>
            <span className="hero__metric-label">Findings</span>
          </div>

          <div className="hero__metric-sep" />

          <div className="hero__metric">
            <Clock
              size={14}
              strokeWidth={2}
              className="hero__metric-icon"
            />
            <span className="hero__metric-value" title={exactTime}>
              {relTime}
            </span>
            <span className="hero__metric-label">Last scan</span>
          </div>

          <div className="hero__metric-sep" />

          <div className="hero__metric">
            <CheckCircle2
              size={14}
              strokeWidth={2}
              className={`hero__metric-icon ${analysis ? "hero__metric-icon--ok" : ""}`}
            />
            <span className={`hero__metric-value ${analysis ? "hero__metric-value--ok" : ""}`}>
              {analysis ? "Completed" : "Awaiting scan"}
            </span>
            <span className="hero__metric-label">Status</span>
          </div>
        </div>
      </div>

      <div className="hero__glow" aria-hidden="true" />
    </section>
  )
}

export default SummaryHero