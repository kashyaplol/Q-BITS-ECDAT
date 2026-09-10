import "./Header.css"
import { Search, Play, CircleHelp } from "lucide-react"
import { MOCK_SUMMARY } from "../../data/mockFindings"
import { timeAgo, formatTimestamp } from "../../utils/risk"

function Header({ onRunScan, searchQuery, onSearchChange }) {
  const relTime = timeAgo(MOCK_SUMMARY.lastScan)
  const exactTime = formatTimestamp(MOCK_SUMMARY.lastScan)

  return (
    <header className="header">
      <div className="header__title">
        <h1>Security Dashboard</h1>
        <p className="header__subtitle">
          Cryptographic asset discovery &amp; risk assessment
          <span className="header__sep" />
          <span className="header__last-scan" title={exactTime}>
            Last scanned {relTime}
          </span>
          <span className="header__status-dot" aria-hidden="true" />
        </p>
      </div>

      <div className="header__actions">
        <div className="header__search">
          <Search size={15} strokeWidth={2} />
          <input
            type="search"
            placeholder="Search findings..."
            aria-label="Search findings"
            value={searchQuery}
            onChange={(event) => onSearchChange?.(event.target.value)}
          />
        </div>

        <button type="button" className="header__scan-btn" onClick={onRunScan}>
          <Play size={14} strokeWidth={2.2} fill="currentColor" />
          Run Scan
        </button>

        <button type="button" className="header__icon-btn" aria-label="Help">
          <CircleHelp size={17} strokeWidth={1.8} />
        </button>

        <div className="header__avatar" title="Analyst">
          AH
        </div>
      </div>
    </header>
  )
}

export default Header