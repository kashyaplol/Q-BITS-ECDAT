import { useState } from "react"
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
        <div className="analysis-page__empty">{message}</div>
      </section>
    </main>
  )
}

function FindingDetail({ finding }) {
  if (!finding) return null

  const details = [
    ["Source", toRelativeLocation(finding)],
    ["Language", finding.language],
    ["Category", finding.category],
    [
      "Key size",
      finding.key_size == null
        ? "Not reported"
        : `${finding.key_size}-bit`,
    ],
    ["Library", finding.library || "Not reported"],
    ["Detection", finding.detection_method],
    ["Confidence", formatConfidence(finding.confidence)],
    ["Usage context", finding.usage_context || "Not reported"],
    ["Code", finding.code_snippet || "Not reported"],
  ]

  return (
    <div className="analysis-page__detail">
      <h2 className="analysis-page__detail-title">
        {finding.algorithm} finding details
      </h2>

      <div className="analysis-page__detail-grid">
        {details.map(([label, value]) => (
          <div className="analysis-page__detail-item" key={label}>
            <span className="analysis-page__detail-label">{label}</span>
            <span className="analysis-page__detail-value">{value}</span>
          </div>
        ))}
      </div>
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
        item.risk_level.toLowerCase() === risk)
  )

  const selected = findings.find((item) => item.id === selectedId)

  return (
    <main className="analysis-page">
      <PageIntro
        icon={ClipboardList}
        title="Crypto findings"
        description="Cryptographic usages returned by the latest backend scan."
        meta={`${visible.length} of ${findings.length} findings`}
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
            value={risk}
            onChange={(event) => setRisk(event.target.value)}
            aria-label="Filter by risk"
          >
            <option value="all">All risk</option>
            {["critical", "high", "medium", "low"].map(
              (item) => (
                <option key={item} value={item}>
                  {item}
                </option>
              )
            )}
          </select>
        </div>

        <div className="analysis-page__table-wrap">
          <table className="analysis-page__table">
            <thead>
              <tr>
                <th>Algorithm</th>
                <th>Location</th>
                <th>Language</th>
                <th>Key size</th>
                <th>Confidence</th>
                <th>Detection</th>
                <th />
              </tr>
            </thead>

            <tbody>
              {visible.map((item) => (
                <tr key={item.id}>
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
                    {item.key_size == null
                      ? "---"
                      : `${item.key_size}-bit`}
                  </td>

                  <td>
                    {formatConfidence(item.confidence)}
                  </td>

                  <td>{item.detection_method}</td>

                  <td>
                    <button
                      className="analysis-page__button"
                      type="button"
                      onClick={() => setSelectedId(item.id)}
                    >
                      {selectedId === item.id
                        ? "Selected"
                        : "Details"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {!visible.length && (
            <div className="analysis-page__empty">
              No findings match the selected filters.
            </div>
          )}
        </div>

        <FindingDetail finding={selected} />
      </section>
    </main>
  )
}

export function RiskPage({ analysis }) {
  if (!analysis) return <Empty />

  const distribution = analysis.risk?.risk_distribution || {}

  return (
    <main className="analysis-page">
      <PageIntro
        icon={Gauge}
        title="Risk assessment"
        description="Deterministic backend risk assessment for the generated CBOM."
        meta="Latest backend assessment"
      />

      <div className="analysis-page__cards">
        {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(
          (level) => (
            <div
              className="analysis-page__summary-card"
              key={level}
            >
              <div className="analysis-page__summary-value">
                {distribution[level] || 0}
              </div>

              <div className="analysis-page__summary-label">
                {level} components
              </div>
            </div>
          )
        )}
      </div>

      <section className="analysis-page__panel">
        <div className="analysis-page__table-wrap">
          <table className="analysis-page__table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Algorithm</th>
                <th>Locations</th>
                <th>Reasons</th>
                <th>Priority / quantum</th>
              </tr>
            </thead>

            <tbody>
              {(analysis.risk?.assessments || []).map(
                (item) => (
                  <tr key={item.identifier}>
                    <td>
                      <SeverityBadge
                        level={item.risk_level.toLowerCase()}
                      />
                    </td>

                    <td className="analysis-page__mono">
                      {item.algorithm}
                    </td>

                    <td>
                      {item.affected_files?.join(", ") ||
                        "Not reported"}
                    </td>

                    <td>
                      {item.reasons?.join(" ") ||
                        "Not reported"}
                    </td>

                    <td>
                      {item.migration_priority} /{" "}
                      {item.quantum_relevance}
                    </td>
                  </tr>
                )
              )}
            </tbody>
          </table>
        </div>
      </section>
    </main>
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
            className="analysis-page__button"
            type="button"
            onClick={() => onScan(path)}
            disabled={scanning || !path.trim()}
          >
            {scanning ? "Scanning…" : "Run scan"}
          </button>

          {error && (
            <p className="analysis-page__empty">
              {error}
            </p>
          )}
        </div>
      </section>
    </main>
  )
}