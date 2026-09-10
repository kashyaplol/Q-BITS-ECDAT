import React, { useState } from "react"
import { Boxes, ClipboardList, Gauge, MoveRight, ScanSearch } from "lucide-react"
import SeverityBadge from "../../components/SeverityBadge/SeverityBadge"
import { formatConfidence, toRelativeLocation } from "../../utils/risk"
import "./AnalysisPages.css"

function PageIntro({ icon: Icon, title, description, meta }) {
  return (
    <div className="analysis-page__intro">
      <div>
        <h1 className="analysis-page__title">
          <Icon size={19} /> {title}
        </h1>
        <p className="analysis-page__description">{description}</p>
      </div>
      {meta && <span className="analysis-page__meta">{meta}</span>}
    </div>
  )
}

function Empty({ message = "Run a scan to view real analysis data." }) {
  return (
    <main className="analysis-page">
      <section className="analysis-page__panel">
        <div className="analysis-page__empty">
          <ScanSearch size={32} strokeWidth={1.5} className="analysis-page__empty-icon" />
          <h3 className="analysis-page__empty-title">No data available</h3>
          <p className="analysis-page__empty-message">{message}</p>
        </div>
      </section>
    </main>
  )
}

function FindingDetail({ finding }) {
  if (!finding) return null

  const details = [
    ["Algorithm", finding.algorithm],
    ["Category", finding.category],
    ["File", finding.file],
    ["Line", finding.line],
    ["Column", finding.column],
    ["Language", finding.language],
    ["Confidence", formatConfidence(finding.confidence)],
    ["Detection", finding.detection_method],
    ["Library", finding.library],
    ["Context", finding.usage_context],
    ["Symbol", finding.symbol_name],
    ["Arguments", finding.arguments ? JSON.stringify(finding.arguments) : null],
  ].filter(([, value]) => value != null && value !== "")

  return (
    <div className="analysis-page__finding-detail">
      <div className="analysis-page__detail-grid">
        {details.map(([label, value]) => (
          <div className="analysis-page__detail-item" key={label}>
            <span className="analysis-page__detail-label">{label}</span>
            <span className="analysis-page__detail-value">{value}</span>
          </div>
        ))}
      </div>
      {finding.code_snippet && (
        <div className="analysis-page__snippet">
          <div className="analysis-page__snippet-header">Code snippet</div>
          <pre className="analysis-page__snippet-content">
            <code>{finding.code_snippet}</code>
          </pre>
        </div>
      )}
    </div>
  )
}

function riskByAlgorithm(analysis) {
  return Object.fromEntries(
    (analysis?.risk?.assessments || []).map((item) => [
      item.algorithm,
      item.risk_level,
    ])
  )
}

export function FindingsPage({
  analysis,
  searchQuery = "",
  onSearchChange,
}) {
  const [category, setCategory] = useState("all")
  const [risk, setRisk] = useState("all")
  const [langFilter, setLangFilter] = useState("all")
  const [selectedId, setSelectedId] = useState(null)

  if (!analysis) return <Empty />

  const risks = riskByAlgorithm(analysis)

  const findings = analysis.findings.map((item) => ({
    ...item,
    risk_level: risks[item.algorithm] || "MEDIUM",
  }))

  const categories = [
    ...new Set(findings.map((item) => item.category).filter(Boolean)),
  ]
  const languages = [
    ...new Set(findings.map((item) => item.language).filter(Boolean)),
  ]

  const query = searchQuery.trim().toLowerCase()

  const visible = findings.filter(
    (item) =>
      (!query ||
        [
          item.algorithm,
          item.file,
          item.language,
          item.category,
          item.detection_method,
        ].some((value) =>
          value?.toLowerCase().includes(query)
        )) &&
      (category === "all" || item.category === category) &&
      (risk === "all" ||
        item.risk_level.toLowerCase() === risk) &&
      (langFilter === "all" || item.language === langFilter)
  )

  const repoName = analysis.scanned_path ? analysis.scanned_path.split(/[/\\]/).pop() || analysis.scanned_path : "Unknown repository"

  return (
    <main className="analysis-page">
      <PageIntro
        icon={ClipboardList}
        title="Findings"
        description="Cryptographic usages detected during the latest repository scan."
        meta={`${repoName} • Showing ${visible.length} of ${findings.length} findings`}
      />

      <section className="analysis-page__panel">
        <div className="analysis-page__toolbar">
          <input
            className="analysis-page__filter"
            type="search"
            value={searchQuery}
            onChange={(event) =>
              onSearchChange?.(event.target.value)
            }
            placeholder="Search algorithm, file, language..."
            aria-label="Filter findings"
          />

          <select
            className="analysis-page__select"
            value={risk}
            onChange={(event) => setRisk(event.target.value)}
            aria-label="Filter by risk"
          >
            <option value="all">All risks</option>
            {["critical", "high", "medium", "low"].map(
              (item) => (
                <option key={item} value={item}>
                  {item[0].toUpperCase() + item.slice(1)}
                </option>
              )
            )}
          </select>

          <select
            className="analysis-page__select"
            value={category}
            onChange={(event) => setCategory(event.target.value)}
            aria-label="Filter by category"
          >
            <option value="all">All categories</option>
            {categories.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>

          <select
            className="analysis-page__select"
            value={langFilter}
            onChange={(event) => setLangFilter(event.target.value)}
            aria-label="Filter by language"
          >
            <option value="all">All languages</option>
            {languages.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
        </div>

        <div className="analysis-page__table-wrap">
          <table className="analysis-page__table analysis-page__table--findings">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Algorithm</th>
                <th>Location</th>
                <th>Language</th>
                <th>Confidence</th>
                <th>Detection</th>
                <th />
              </tr>
            </thead>

            <tbody>
              {visible.map((item) => {
                const isExpanded = selectedId === item.id
                return (
                  <React.Fragment key={item.id}>
                    <tr onClick={() => setSelectedId(isExpanded ? null : item.id)} className={isExpanded ? 'is-expanded' : ''}>
                      <td>
                        <SeverityBadge level={item.risk_level.toLowerCase()} />
                      </td>
                      <td>
                        <span className="analysis-page__mono">
                          {item.algorithm}
                        </span>
                        <span className="analysis-page__subtext">
                          {item.category}
                        </span>
                      </td>
                      <td className="analysis-page__file">
                        {toRelativeLocation(item)}
                      </td>
                      <td>{item.language}</td>
                      <td>
                        {formatConfidence(item.confidence)}
                      </td>
                      <td>{item.detection_method}</td>
                      <td className="analysis-page__act">
                        <button
                          className="analysis-page__button"
                          type="button"
                          aria-expanded={isExpanded}
                        >
                          {isExpanded ? "Close" : "View"}
                        </button>
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr className="analysis-page__row-detail">
                        <td colSpan={7}>
                          <FindingDetail finding={item} />
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                )
              })}
            </tbody>
          </table>

          {!visible.length && (
            <div className="analysis-page__empty">
              <ClipboardList size={32} strokeWidth={1.5} className="analysis-page__empty-icon" />
              <h3 className="analysis-page__empty-title">No findings match</h3>
              <p className="analysis-page__empty-message">Try adjusting your filters or search query.</p>
            </div>
          )}
        </div>
      </section>
    </main>
  )
}

export function RiskPage({ analysis }) {
  const [selectedId, setSelectedId] = useState(null)

  if (!analysis) return <Empty />

  const assessments = analysis.risk?.assessments || []
  const distribution = analysis.risk?.risk_distribution || {}
  
  const repoName = analysis.scanned_path ? analysis.scanned_path.split(/[/\\]/).pop() || analysis.scanned_path : "Unknown repository"
  const totalAssessed = analysis.risk?.assets_assessed ?? assessments.length

  const getRiskColor = (level) => {
    switch(level) {
      case 'CRITICAL': return 'var(--red)'
      case 'HIGH': return 'var(--orange)'
      case 'MEDIUM': return 'var(--amber)'
      case 'LOW': return 'var(--green)'
      default: return 'var(--text)'
    }
  }

  return (
    <main className="analysis-page">
      <PageIntro
        icon={Gauge}
        title="Risk Assessment"
        description="Deterministic risk assessment of cryptographic components identified during the latest scan."
        meta={`${repoName} • ${totalAssessed} components assessed`}
      />

      <div className="analysis-page__cards">
        {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((level) => (
          <div className="analysis-page__summary-card" key={level}>
            <div className="analysis-page__summary-value" style={{ color: getRiskColor(level) }}>
              {distribution[level] || 0}
            </div>
            <div className="analysis-page__summary-label">
              {level.charAt(0) + level.slice(1).toLowerCase()} risk
            </div>
          </div>
        ))}
      </div>

      <section className="analysis-page__panel">
        <div className="analysis-page__table-wrap">
          <table className="analysis-page__table analysis-page__table--findings">
            <thead>
              <tr>
                <th>Risk</th>
                <th>Algorithm</th>
                <th>Category</th>
                <th>Risk Score</th>
                <th>Quantum Relevance</th>
                <th>Migration Priority</th>
                <th>Affected Assets</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {assessments.length === 0 ? (
                <tr>
                  <td colSpan={8}>
                    <div className="analysis-page__empty" style={{ padding: '32px 16px' }}>
                      <Gauge size={32} strokeWidth={1.5} className="analysis-page__empty-icon" />
                      <h3 className="analysis-page__empty-title">Clean Assessment</h3>
                      <p className="analysis-page__empty-message">No cryptographic components requiring risk assessment were detected.</p>
                    </div>
                  </td>
                </tr>
              ) : (
                assessments.map((item) => {
                  const isExpanded = selectedId === item.identifier
                  return (
                    <React.Fragment key={item.identifier}>
                      <tr onClick={() => setSelectedId(isExpanded ? null : item.identifier)} className={isExpanded ? 'is-expanded' : ''}>
                        <td>
                          <SeverityBadge level={item.risk_level.toLowerCase()} />
                        </td>
                        <td className="analysis-page__mono">
                          {item.algorithm}
                          {item.key_sizes && item.key_sizes.length > 0 && (
                            <span className="analysis-page__subtext">{item.key_sizes.join(', ')}-bit</span>
                          )}
                        </td>
                        <td>{item.category || "Not reported"}</td>
                        <td>{item.risk_score}</td>
                        <td>
                          {item.quantum_relevance === 'HIGH' ? (
                            <span className="analysis-page__tag" style={{ borderColor: 'var(--amber)', color: 'var(--amber)' }}>HIGH</span>
                          ) : (
                            <span className="analysis-page__tag">{item.quantum_relevance || "UNKNOWN"}</span>
                          )}
                        </td>
                        <td>
                          <span className="analysis-page__tag">{item.migration_priority}</span>
                        </td>
                        <td>
                          <div className="analysis-page__file" title={item.affected_files?.join("\n")}>
                            {item.affected_files?.length > 0 
                              ? `${item.affected_files[0].split(/[/\\]/).pop()} ${item.affected_files.length > 1 ? `(+${item.affected_files.length - 1})` : ''}`
                              : "Not reported"}
                          </div>
                        </td>
                        <td className="analysis-page__act">
                          <button
                            className="analysis-page__button"
                            type="button"
                            aria-expanded={isExpanded}
                          >
                            {isExpanded ? "Close" : "View"}
                          </button>
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr className="analysis-page__row-detail">
                          <td colSpan={8}>
                            <RiskDetail assessment={item} />
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </section>
    </main>
  )
}

function RiskDetail({ assessment }) {
  if (!assessment) return null

  return (
    <div className="analysis-page__finding-detail">
      <div className="analysis-page__detail-grid">
        <div className="analysis-page__detail-item">
          <span className="analysis-page__detail-label">Algorithm</span>
          <span className="analysis-page__detail-value">{assessment.algorithm}</span>
        </div>
        <div className="analysis-page__detail-item">
          <span className="analysis-page__detail-label">Category</span>
          <span className="analysis-page__detail-value">{assessment.category || "Not reported"}</span>
        </div>
        <div className="analysis-page__detail-item">
          <span className="analysis-page__detail-label">Risk Score</span>
          <span className="analysis-page__detail-value">{assessment.risk_score}</span>
        </div>
        <div className="analysis-page__detail-item">
          <span className="analysis-page__detail-label">Recommendation</span>
          <span className="analysis-page__detail-value">{assessment.recommendation || "Review and replace"}</span>
        </div>
      </div>
      
      {assessment.reasons && assessment.reasons.length > 0 && (
        <div className="analysis-page__snippet">
          <div className="analysis-page__snippet-header">Risk Reasoning</div>
          <div className="analysis-page__snippet-content" style={{ whiteSpace: 'normal', fontFamily: 'inherit' }}>
            <ul style={{ margin: 0, paddingLeft: 16 }}>
              {assessment.reasons.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {assessment.affected_files && assessment.affected_files.length > 0 && (
        <div className="analysis-page__snippet">
          <div className="analysis-page__snippet-header">Affected Locations</div>
          <div className="analysis-page__snippet-content">
            {assessment.affected_files.join("\n")}
          </div>
        </div>
      )}
    </div>
  )
}

export function CbomPage({ analysis }) {
  if (!analysis) return <Empty />

  const cbom = analysis.cbom

  if (!cbom) {
    return (
      <Empty message="No CBOM was returned by the latest scan." />
    )
  }

  const references = Object.fromEntries(
    (cbom.source_references || []).map((item) => [
      item.reference_id,
      item,
    ])
  )

  return (
    <main className="analysis-page">
      <PageIntro
        icon={Boxes}
        title="CBOM inventory"
        description="Actual generated CBOM from the latest scan."
        meta={`${cbom.components?.length || 0} components`}
      />

      <section className="analysis-page__panel">
        <div className="analysis-page__table-wrap">
          <table className="analysis-page__table">
            <thead>
              <tr>
                <th>Algorithm</th>
                <th>Category</th>
                <th>Occurrences</th>
                <th>Key sizes</th>
                <th>Affected files / references</th>
              </tr>
            </thead>

            <tbody>
              {(cbom.components || []).map((component) => {
                const info =
                  component.cryptographic_information

                const sourceRefs = (
                  info.source_reference_ids || []
                )
                  .map((id) => references[id])
                  .filter(Boolean)

                return (
                  <tr
                    key={component.bom_ref}
                  >
                    <td className="analysis-page__mono">
                      {info.algorithm}
                    </td>

                    <td>
                      {info.category || "Not reported"}
                    </td>

                    <td>
                      {sourceRefs.reduce(
                        (sum, item) =>
                          sum + (item.occurrences || 0),
                        0
                      )}
                    </td>

                    <td>
                      {info.key_sizes?.join(", ") ||
                        "Not reported"}
                    </td>

                    <td>
                      {[
                        ...new Set(
                          sourceRefs.map(
                            (item) => item.file
                          )
                        ),
                      ].join(", ") || "Not reported"}{" "}
                      ({sourceRefs.length} references)
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </section>
    </main>
  )
}

export function MigrationPage({ analysis }) {
  if (!analysis) return <Empty />

  const items = [
    ...(analysis.risk?.assessments || []),
  ].sort(
    (a, b) => b.risk_score - a.risk_score
  )

  return (
    <main className="analysis-page">
      <PageIntro
        icon={MoveRight}
        title="Migration priorities"
        description="Backend recommendations ordered by deterministic risk score."
        meta={`${items.length} components`}
      />

      <section className="analysis-page__panel">
        <div className="analysis-page__table-wrap">
          <table className="analysis-page__table">
            <thead>
              <tr>
                <th>Asset locations</th>
                <th>Algorithm</th>
                <th>Risk / priority</th>
                <th>Backend recommendation</th>
                <th>Quantum relevance</th>
              </tr>
            </thead>

            <tbody>
              {items.map((item) => (
                <tr key={item.identifier}>
                  <td>
                    {item.affected_files?.join(", ") ||
                      "Not reported"}
                  </td>

                  <td className="analysis-page__mono">
                    {item.algorithm}
                  </td>

                  <td>
                    <SeverityBadge
                      level={item.risk_level.toLowerCase()}
                    />
                    <span className="analysis-page__subtext">
                      {item.migration_priority}
                    </span>
                  </td>

                  <td>
                    {item.recommendation ||
                      "Review usage and select an approved replacement"}
                  </td>

                  <td>
                    {item.quantum_relevance ||
                      "Not reported"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </main>
  )
}

export function ScanPage({
  scanState,
  error,
  onScan,
}) {
  const [path, setPath] = useState(
    "data/sample/demo-target"
  )

  const scanning = scanState === "scanning"

  return (
    <main className="analysis-page">
      <PageIntro
        icon={ScanSearch}
        title="New scan"
        description="Run the local backend scanner, then generate a CBOM and deterministic risk report."
        meta={
          scanning
            ? "Scanning…"
            : "Backend analysis"
        }
      />

      <section className="analysis-page__panel">
        <div className="analysis-page__detail">
          <h2 className="analysis-page__detail-title">
            Repository path
          </h2>

          <p className="analysis-page__description">
            The path must be accessible on the backend
            host.
          </p>

          <div className="analysis-page__scan-form">
            <input
              className="analysis-page__filter"
              value={path}
              onChange={(event) =>
                setPath(event.target.value)
              }
              placeholder="data/sample/demo-target"
              disabled={scanning}
            />
            <button
              className="analysis-page__button--primary"
              type="button"
              onClick={() => onScan(path)}
              disabled={scanning || !path.trim()}
            >
              {scanning ? "Scanning…" : "Run scan"}
            </button>
          </div>

          {error && (
            <p className="analysis-page__error">
              {error}
            </p>
          )}
        </div>
      </section>
    </main>
  )
}