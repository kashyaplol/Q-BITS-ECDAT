import "./Dashboard.css"
import { Files, ShieldAlert, Braces, Atom } from "lucide-react"
import SummaryHero from "../../components/SummaryHero/SummaryHero"
import StatCard from "../../components/StatCard/StatCard"
import RiskDistribution from "../../components/RiskDistribution/RiskDistribution"
import AlgorithmDistribution from "../../components/AlgorithmDistribution/AlgorithmDistribution"
import LanguageDistribution from "../../components/LanguageDistribution/LanguageDistribution"
import PriorityActions from "../../components/PriorityActions/PriorityActions"
import RecentFindings from "../../components/RecentFindings/RecentFindings"
import MOCK_FINDINGS, { MOCK_RISK_DISTRIBUTION } from "../../data/mockFindings"
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
  const stats = computeStats(MOCK_FINDINGS)
  const algoDist = computeAlgorithmDistribution(MOCK_FINDINGS)
  const langDist = computeLanguageDistribution(MOCK_FINDINGS)

  const filteredFindings = searchQuery.trim()
    ? MOCK_FINDINGS.filter((f) => {
        const q = searchQuery.toLowerCase()
        return (
          f.algorithm.toLowerCase().includes(q) ||
          f.file.toLowerCase().includes(q) ||
          f.language.toLowerCase().includes(q) ||
          f.category.toLowerCase().includes(q)
        )
      })
    : MOCK_FINDINGS

  return (
    <main className="dashboard">
      <SummaryHero />

      <section className="dashboard__cards" aria-label="Key statistics">
        <StatCard
          title="Total Findings"
          value={MOCK_FINDINGS.length}
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
        <RiskDistribution data={MOCK_RISK_DISTRIBUTION} />
        <AlgorithmDistribution data={algoDist} />
        <LanguageDistribution data={langDist} />
      </div>

      <RecentFindings
        findings={filteredFindings}
        totalCount={MOCK_FINDINGS.length}
        limit={8}
        searchQuery={searchQuery}
        onSearchChange={onSearchChange}
      />
    </main>
  )
}

export default Dashboard
