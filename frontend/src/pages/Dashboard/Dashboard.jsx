import './Dashboard.css'
import StatCard from '../../components/StatCard/StatCard'
import RiskDistribution from '../../components/RiskDistribution/RiskDistribution'
import AlgorithmDistribution from '../../components/AlgorithmDistribution/AlgorithmDistribution'
import PriorityActions from '../../components/PriorityActions/PriorityActions'
import RecentFindings from '../../components/RecentFindings/RecentFindings'
import MOCK_FINDINGS, { MOCK_RISK_DISTRIBUTION } from '../../data/mockFindings'
import { toRiskLevel, isQuantumVulnerable, computeAlgorithmDistribution } from '../../utils/risk'

const ICONS = {
  findings: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="18" height="18" rx="2" />
      <path d="M7 9h10" />
      <path d="M7 13h10" />
      <path d="M7 17h6" />
    </svg>
  ),
  highRisk: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.3 4.3a2 2 0 0 1 3.4 0l7 12.1A2 2 0 0 1 19 19.5H5a2 2 0 0 1-1.7-3.1l7-12.1z" />
      <path d="M12 9v4" />
      <path d="M12 17h.01" />
    </svg>
  ),
  algorithms: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="16 18 22 12 16 6" />
      <polyline points="8 6 2 12 8 18" />
    </svg>
  ),
  quantum: (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="2.5" />
      <path d="M5 17.5l4-6" />
      <path d="M15 12.5l4-6" />
      <path d="M12 2.5v4.5" />
      <path d="M12 17v4.5" />
    </svg>
  ),
}

function computeStats(findings) {
  const highRisk = findings.filter((f) => toRiskLevel(f) === 'high').length
  const algorithms = new Set(findings.map((f) => f.algorithm)).size
  const quantumVulnerable = findings.filter(isQuantumVulnerable).length
  return { highRisk, algorithms, quantumVulnerable }
}

function Dashboard() {
  const stats = computeStats(MOCK_FINDINGS)
  const algoDist = computeAlgorithmDistribution(MOCK_FINDINGS)

  return (
    <main className="dashboard">
      <section className="dashboard__cards">
        <StatCard
          title="Total Findings"
          value={MOCK_FINDINGS.length}
          delta={8.4}
          icon={ICONS.findings}
          tone="accent"
          description="Cryptographic primitives detected across all scanned source files"
        />
        <StatCard
          title="High Risk"
          value={stats.highRisk}
          delta={13.6}
          icon={ICONS.highRisk}
          tone="red"
          description="Weak or deprecated algorithms requiring immediate replacement"
        />
        <StatCard
          title="Algorithms"
          value={stats.algorithms}
          delta={4.2}
          icon={ICONS.algorithms}
          tone="cyan"
          description="Distinct cryptographic algorithms in use across the codebase"
        />
        <StatCard
          title="Quantum Vulnerable"
          value={stats.quantumVulnerable}
          delta={9.1}
          icon={ICONS.quantum}
          tone="amber"
          description="Algorithms at risk from future quantum computing attacks"
        />
      </section>

      <PriorityActions findings={MOCK_FINDINGS} limit={5} />

      <div className="dashboard__viz-row">
        <RiskDistribution data={MOCK_RISK_DISTRIBUTION} />
        <AlgorithmDistribution data={algoDist} />
      </div>

      <RecentFindings findings={MOCK_FINDINGS} limit={8} />
    </main>
  )
}

export default Dashboard
