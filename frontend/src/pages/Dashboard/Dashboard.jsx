import "./Dashboard.css"
import { Atom, Braces, Files, ShieldAlert } from "lucide-react"
import SummaryHero from "../../components/SummaryHero/SummaryHero"
import StatCard from "../../components/StatCard/StatCard"
import RiskDistribution from "../../components/RiskDistribution/RiskDistribution"
import AlgorithmDistribution from "../../components/AlgorithmDistribution/AlgorithmDistribution"
import LanguageDistribution from "../../components/LanguageDistribution/LanguageDistribution"
import PriorityActions from "../../components/PriorityActions/PriorityActions"
import RecentFindings from "../../components/RecentFindings/RecentFindings"
import { computeAlgorithmDistribution, computeLanguageDistribution } from "../../utils/risk"

const RISK_COLORS = { CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#f59e0b", LOW: "#22c55e" }

function Dashboard({ analysis, searchQuery = "" }) {
  const findings = analysis?.findings || []
  const distribution = analysis?.risk?.risk_distribution || {}
  const riskData = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((label) => ({
    label: label[0] + label.slice(1).toLowerCase(), value: distribution[label] || 0, color: RISK_COLORS[label],
  }))
  const enriched = findings.map((finding) => ({ ...finding, risk_level: analysis?.risk?.assessments.find((item) => item.algorithm === finding.algorithm)?.risk_level }))
  const filtered = searchQuery.trim() ? enriched.filter((finding) => Object.values(finding).some((value) => String(value || "").toLowerCase().includes(searchQuery.toLowerCase()))) : enriched
  const highRisk = (distribution.CRITICAL || 0) + (distribution.HIGH || 0)
  const quantumRelevant = analysis?.risk?.assessments.filter((item) => item.quantum_relevance === "HIGH").length || 0

  return <main className="dashboard">
    <SummaryHero analysis={analysis} />
    <section className="dashboard__cards" aria-label="Key statistics">
      <StatCard title="Total Findings" value={findings.length} icon={Files} tone="accent" description="Cryptographic usages detected in the latest scan" />
      <StatCard title="High Risk" value={highRisk} icon={ShieldAlert} tone="red" description="Critical and high-risk CBOM components" />
      <StatCard title="Components" value={analysis?.cbom?.components.length || 0} icon={Braces} tone="cyan" description="Distinct cryptographic components in the CBOM" />
      <StatCard title="Quantum Relevant" value={quantumRelevant} icon={Atom} tone="amber" description="Components requiring PQC migration planning" />
    </section>
    {analysis ? <>
      <PriorityActions assessments={analysis.risk.assessments} limit={5} />
      <div className="dashboard__viz-row">
        <RiskDistribution data={riskData} total={analysis.risk.assets_assessed} />
        <AlgorithmDistribution data={computeAlgorithmDistribution(findings)} />
        <LanguageDistribution data={computeLanguageDistribution(findings)} />
      </div>
      <RecentFindings findings={filtered} limit={8} />
    </> : <section className="dashboard__empty">Run a scan to display real findings, CBOM inventory, and risk results.</section>}
  </main>
}

export default Dashboard
