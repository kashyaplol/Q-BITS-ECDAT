import { useMemo, useState } from "react"
import { Boxes, ClipboardList, Gauge, MoveRight, ScanSearch } from "lucide-react"
import SeverityBadge from "../../components/SeverityBadge/SeverityBadge"
import MOCK_FINDINGS, { MOCK_RISK_DISTRIBUTION } from "../../data/mockFindings"
import {
  formatConfidence,
  getRiskPriority,
  toRelativeLocation,
  toRiskLevel,
} from "../../utils/risk"
import "./AnalysisPages.css"

function PageIntro({ icon: Icon, title, description, meta }) {
  return (
    <div className="analysis-page__intro">
      <div>
        <h1 className="analysis-page__title"><Icon size={19} /> {title}</h1>
        <p className="analysis-page__description">{description}</p>
      </div>
      {meta && <span className="analysis-page__meta">{meta}</span>}
    </div>
  )
}

function FindingDetail({ finding }) {
  if (!finding) return null
  return (
    <div className="analysis-page__detail">
      <h2 className="analysis-page__detail-title">{finding.algorithm} finding details</h2>
      <div className="analysis-page__detail-grid">
        <DetailItem label="Source" value={toRelativeLocation(finding)} mono />
        <DetailItem label="Language" value={finding.language} />
        <DetailItem label="Category" value={finding.category} />
        <DetailItem label="Library" value={finding.library || "Not reported"} />
        <DetailItem label="Detection" value={finding.detection_method} />
        <DetailItem label="Confidence" value={formatConfidence(finding.confidence)} />
        <DetailItem label="Usage context" value={finding.usage_context || "Not reported"} />
        <DetailItem label="Code" value={finding.code_snippet} mono />
      </div>
    </div>
  )
}

function DetailItem({ label, value, mono = false }) {
  return (
    <div className="analysis-page__detail-item">
      <span className="analysis-page__detail-label">{label}</span>
      <span className={`analysis-page__detail-value${mono ? " analysis-page__mono" : ""}`}>{value}</span>
    </div>
  )
}

function filterFindings(findings, query, category, risk) {
  const normalizedQuery = query.trim().toLowerCase()
  return findings.filter((finding) => {
    const matchesQuery = !normalizedQuery || [
      finding.algorithm,
      finding.file,
      finding.language,
      finding.category,
      finding.detection_method,
    ].some((value) => value?.toLowerCase().includes(normalizedQuery))
    const matchesCategory = category === "all" || finding.category === category
    const matchesRisk = risk === "all" || toRiskLevel(finding) === risk
    return matchesQuery && matchesCategory && matchesRisk
  })
}

export function FindingsPage({ searchQuery = "", onSearchChange }) {
  const [category, setCategory] = useState("all")
  const [risk, setRisk] = useState("all")
  const [selectedId, setSelectedId] = useState(null)
  const categories = [...new Set(MOCK_FINDINGS.map((finding) => finding.category))]
  const findings = filterFindings(MOCK_FINDINGS, searchQuery, category, risk)
  const selected = MOCK_FINDINGS.find((finding) => finding.id === selectedId)

  return (
    <main className="analysis-page">
      <PageIntro icon={ClipboardList} title="Crypto findings" description="Inspect every cryptographic usage detected in the demo scan." meta={`${findings.length} of ${MOCK_FINDINGS.length} findings`} />
      <section className="analysis-page__panel">
        <div className="analysis-page__toolbar">
          <input className="analysis-page__filter" type="search" value={searchQuery} onChange={(event) => onSearchChange?.(event.target.value)} placeholder="Search algorithm, file, language..." aria-label="Filter findings" />
          <select className="analysis-page__select" value={category} onChange={(event) => setCategory(event.target.value)} aria-label="Filter by category">
            <option value="all">All categories</option>
            {categories.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
          <select className="analysis-page__select" value={risk} onChange={(event) => setRisk(event.target.value)} aria-label="Filter by risk">
            <option value="all">All risk</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
        <div className="analysis-page__table-wrap">
          <table className="analysis-page__table">
            <thead><tr><th>Algorithm</th><th>Location</th><th>Language</th><th>Key size</th><th>Confidence</th><th>Detection</th><th /></tr></thead>
            <tbody>
              {findings.map((finding) => (
                <tr key={finding.id}>
                  <td><span className="analysis-page__mono">{finding.algorithm}</span><span className="analysis-page__subtext">{finding.category}</span></td>
                  <td><span className="analysis-page__file">{toRelativeLocation(finding)}</span></td>
                  <td>{finding.language}</td>
                  <td>{finding.key_size != null ? `${finding.key_size}-bit` : <span className="analysis-page__muted">---</span>}</td>
                  <td>{formatConfidence(finding.confidence)}</td>
                  <td className="analysis-page__muted">{finding.detection_method}</td>
                  <td><button className="analysis-page__button" type="button" onClick={() => setSelectedId(finding.id)}>{selectedId === finding.id ? "Selected" : "Details"}</button></td>
                </tr>
              ))}
            </tbody>
          </table>
          {!findings.length && <div className="analysis-page__empty">No findings match the selected filters.</div>}
        </div>
        <FindingDetail finding={selected} />
      </section>
    </main>
  )
}

const RISK_CONTEXT = {
  high: "Weak or deprecated primitive identified in the demo risk model.",
  medium: "Public-key primitive is marked quantum-vulnerable by the demo risk model.",
  low: "No elevated risk classification in the demo risk model.",
}

export function RiskPage({ searchQuery = "" }) {
  const findings = filterFindings(MOCK_FINDINGS, searchQuery, "all", "all").sort((a, b) => getRiskPriority(a) - getRiskPriority(b))
  return (
    <main className="analysis-page">
      <PageIntro icon={Gauge} title="Risk assessment" description="Review the demo risk classification and migration priority for detected assets." meta="Demo assessment" />
      <div className="analysis-page__cards">
        {MOCK_RISK_DISTRIBUTION.map((item) => <div className="analysis-page__summary-card" key={item.label}><div className="analysis-page__summary-value" style={{ color: item.color }}>{item.value}</div><div className="analysis-page__summary-label">{item.label} risk findings</div></div>)}
      </div>
      <section className="analysis-page__panel">
        <div className="analysis-page__table-wrap">
          <table className="analysis-page__table">
            <thead><tr><th>Severity</th><th>Algorithm</th><th>Location</th><th>Reason / context</th><th>Priority</th></tr></thead>
            <tbody>{findings.map((finding) => { const level = toRiskLevel(finding); return <tr key={finding.id}><td><SeverityBadge level={level} /></td><td className="analysis-page__mono">{finding.algorithm}</td><td><span className="analysis-page__file">{toRelativeLocation(finding)}</span></td><td>{RISK_CONTEXT[level]}</td><td>{level === "high" ? "Immediate" : level === "medium" ? "Planned" : "Monitor"}</td></tr> })}</tbody>
          </table>
        </div>
      </section>
    </main>
  )
}

export function CbomPage() {
  const inventory = useMemo(() => Object.entries(MOCK_FINDINGS.reduce((result, finding) => {
    const current = result[finding.algorithm] || { algorithm: finding.algorithm, count: 0, keySizes: new Set(), files: new Set(), categories: new Set() }
    current.count += 1
    if (finding.key_size != null) current.keySizes.add(finding.key_size)
    current.files.add(finding.file)
    current.categories.add(finding.category)
    result[finding.algorithm] = current
    return result
  }, {})).map(([, item]) => ({ ...item, keySizes: [...item.keySizes].join(", ") || "---", files: item.files.size, categories: [...item.categories].join(", ") })), [])
  return (
    <main className="analysis-page">
      <PageIntro icon={Boxes} title="CBOM inventory" description="A structured view of cryptographic assets from the current demo findings." meta={`${inventory.length} algorithms`} />
      <section className="analysis-page__panel">
        <div className="analysis-page__table-wrap"><table className="analysis-page__table"><thead><tr><th>Algorithm</th><th>Category</th><th>Occurrences</th><th>Key sizes</th><th>Affected files</th></tr></thead><tbody>{inventory.map((item) => <tr key={item.algorithm}><td className="analysis-page__mono">{item.algorithm}</td><td>{item.categories}</td><td>{item.count}</td><td>{item.keySizes}</td><td>{item.files}</td></tr>)}</tbody></table></div>
      </section>
      <p className="analysis-page__meta">Demo inventory only; this is not a standards-compliant CBOM export.</p>
    </main>
  )
}

const MIGRATION_DIRECTION = {
  MD5: "Replace with a modern hash approved for the use case",
  "SHA-1": "Replace with a modern hash approved for the use case",
  DES: "Replace with a modern authenticated symmetric cipher",
  "3DES": "Replace with a modern authenticated symmetric cipher",
  Blowfish: "Evaluate a modern authenticated symmetric cipher",
  RSA: "Plan a post-quantum public-key replacement",
  ECC: "Plan a post-quantum public-key replacement",
  ECDSA: "Plan a post-quantum signature replacement",
  "Diffie-Hellman": "Plan a post-quantum key-establishment replacement",
}

export function MigrationPage({ searchQuery = "" }) {
  const findings = filterFindings(MOCK_FINDINGS, searchQuery, "all", "all").sort((a, b) => getRiskPriority(a) - getRiskPriority(b))
  return (
    <main className="analysis-page">
      <PageIntro icon={MoveRight} title="Migration priorities" description="Track suggested migration direction for assets identified in the demo scan." meta={`${findings.length} assets`} />
      <section className="analysis-page__panel">
        <div className="analysis-page__table-wrap"><table className="analysis-page__table"><thead><tr><th>Asset</th><th>Current algorithm</th><th>Risk / priority</th><th>Migration direction</th><th>Status</th></tr></thead><tbody>{findings.map((finding) => { const level = toRiskLevel(finding); return <tr key={finding.id}><td><span className="analysis-page__file">{toRelativeLocation(finding)}</span><span className="analysis-page__subtext">{finding.language}</span></td><td className="analysis-page__mono">{finding.algorithm}</td><td><SeverityBadge level={level} /><span className="analysis-page__subtext">{level === "high" ? "Immediate" : level === "medium" ? "Planned" : "Monitor"}</span></td><td>{MIGRATION_DIRECTION[finding.algorithm] || "Review usage and select an approved replacement"}</td><td><span className="analysis-page__muted">Not started</span></td></tr> })}</tbody></table></div>
      </section>
    </main>
  )
}

export function ScanPage() {
  return <main className="analysis-page"><PageIntro icon={ScanSearch} title="New scan" description="The scan workflow is ready for a backend contract, but remains demo-only for now." meta="Mock workflow" /><section className="analysis-page__panel"><div className="analysis-page__detail"><h2 className="analysis-page__detail-title">Scanner integration point</h2><p className="analysis-page__description">No endpoint is called. When the backend contract is finalized, this view can submit a source path and replace the mock findings with the returned CryptoFinding[].</p><button className="analysis-page__button" type="button" disabled>Backend scan unavailable</button></div></section></main>
}
