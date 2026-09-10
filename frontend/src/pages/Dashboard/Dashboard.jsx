import "./Dashboard.css"
import { Files, ShieldAlert, Braces, Atom } from "lucide-react"
import SummaryHero from "../../components/SummaryHero/SummaryHero"
import StatCard from "../../components/StatCard/StatCard"
import RiskDistribution from "../../components/RiskDistribution/RiskDistribution"
import AlgorithmDistribution from "../../components/AlgorithmDistribution/AlgorithmDistribution"
import LanguageDistribution from "../../components/LanguageDistribution/LanguageDistribution"
import PriorityActions from "../../components/PriorityActions/PriorityActions"
import RecentFindings from "../../components/RecentFindings/RecentFindings"
import { MOCK_RISK_DISTRIBUTION } from "../../data/mockFindings"
import {
  toRiskLevel,
  isQuantumVulnerable,
  computeAlgorithmDistribution,
  computeLanguageDistribution,
} from "../../utils/risk"

function computeStats(findings) {
  const highRisk = findings.filter((f) => toRiskLevel(f) === "high").length
  const algorithms = new Set(findings.map((f) => f.algorithm)).size
  const quantumVulnerable = findings.filter(isQuantumVulnerable).length
  return { highRisk, algorithms, quantumVulnerable }
}

function Dashboard({ searchQuery = "", onSearchChange }) {
  let FINDINGS
  try {
    const persisted = JSON.parse(localStorage.getItem("qbits_latest_analysis"))
    FINDINGS = persisted?.findings || []
  } catch {
    FINDINGS = []
  }

  const stats = computeStats(FINDINGS)
  const algoDist = computeAlgorithmDistribution(FINDINGS)
  const langDist = computeLanguageDistribution(FINDINGS)

  const filteredFindings = searchQuery.trim()
    ? FINDINGS.filter((f) => {
        const q = searchQuery.toLowerCase()
        return (
          f.algorithm.toLowerCase().includes(q) ||
          f.file.toLowerCase().includes(q) ||
          (f.language || "").toLowerCase().includes(q) ||
          (f.category || "").toLowerCase().includes(q)
        )
      })
    : FINDINGS

  return (
    <main className="dashboard">
      <SummaryHero />

      <section className="dashboard__cards" aria-label="Key statistics">
        <StatCard
          title="Total Findings"
            value={FINDINGS.length}
          delta={8.4}
          icon={Files}
          tone="accent"
          description="Cryptographic primitives detected across all scanned source files"
        />
        <StatCard
          title="High Risk"
          value={stats.highRisk}
          delta={13.6}
          icon={ShieldAlert}
          tone="red"
          description="Weak or deprecated algorithms requiring immediate replacement"
        />
        <StatCard
          title="Algorithms"
          value={stats.algorithms}
          delta={4.2}
          icon={Braces}
          tone="cyan"
          description="Distinct cryptographic algorithms in use across the codebase"
        />
        <StatCard
          title="Quantum Vulnerable"
          value={stats.quantumVulnerable}
          delta={9.1}
          icon={Atom}
          tone="amber"
          description="Algorithms at risk from future quantum computing attacks"
        />
      </section>

      <PriorityActions findings={filteredFindings} limit={5} />

      <div className="dashboard__viz-row">
        <RiskDistribution data={(() => {
          try {
            const persisted = JSON.parse(localStorage.getItem("qbits_latest_analysis"))
            const pd = persisted?.summary?.priority_distribution
            if (pd) {
              return [
                { label: 'Critical', value: pd.CRITICAL || 0, color: '#b91c1c' },
                { label: 'High', value: pd.HIGH || 0, color: '#ef4444' },
                { label: 'Medium', value: pd.MEDIUM || 0, color: '#f59e0b' },
                { label: 'Low', value: pd.LOW || 0, color: '#0ea5a4' },
                { label: 'Immediate', value: pd.IMMEDIATE || 0, color: '#7c2d12' },
              ]
            }
          } catch {
            /* ignore */
          }
          return MOCK_RISK_DISTRIBUTION
        })()} />
        <AlgorithmDistribution data={algoDist} />
        <LanguageDistribution data={langDist} />
      </div>

      <RecentFindings
        findings={filteredFindings}
        totalCount={FINDINGS.length}
        limit={8}
        searchQuery={searchQuery}
        onSearchChange={onSearchChange}
      />
    </main>
  )
}

export default Dashboard
