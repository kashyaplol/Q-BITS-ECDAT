import './Header.css'
import MOCK_SUMMARY from '../../data/mockFindings'
import { timeAgo, formatTimestamp } from '../../utils/risk'

function Header({ onRunScan }) {
  const relTime = timeAgo(MOCK_SUMMARY.lastScan)
  const exactTime = formatTimestamp(MOCK_SUMMARY.lastScan)
  const scanStatus = MOCK_SUMMARY.scanStatus

  return (
    <header className="header">
      <div className="header__title">
        <div className="header__title-row">
          <h1>{MOCK_SUMMARY.repoName}</h1>
          <span className={`header__status header__status--${scanStatus}`}>
            <span className="header__status-dot" />
            {scanStatus}
          </span>
        </div>
        <p className="header__subtitle">
          Cryptographic asset discovery &amp; risk assessment &middot;{' '}
          <span className="header__last-scan" title={exactTime}>
            Last scanned {relTime}
          </span>
        </p>
      </div>

      <div className="header__actions">
        <div className="header__search">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="11" cy="11" r="7" />
            <path d="M21 21l-4.3-4.3" />
          </svg>
          <input type="search" placeholder="Search findings..." aria-label="Search findings" />
        </div>

        <button type="button" className="header__scan-btn" onClick={onRunScan}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 5v14" />
            <path d="M5 12h14" />
          </svg>
          Run Scan
        </button>

        <div className="header__avatar" title="Analyst">
          AH
        </div>
      </div>
    </header>
  )
}

export default Header