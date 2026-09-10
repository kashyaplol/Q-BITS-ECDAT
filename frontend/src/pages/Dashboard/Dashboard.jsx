import "./Dashboard.css"
import { Atom, Braces, Files, ShieldAlert } from "lucide-react"
import SummaryHero from "../../components/SummaryHero/SummaryHero"
import StatCard from "../../components/StatCard/StatCard"
import RiskDistribution from "../../components/RiskDistribution/RiskDistribution"
import AlgorithmDistribution from "../../components/AlgorithmDistribution/AlgorithmDistribution"
import LanguageDistribution from "../../components/LanguageDistribution/LanguageDistribution"
import PriorityActions from "../../components/PriorityActions/PriorityActions"
import RecentFindings from "../../components/RecentFindings/RecentFindings"
import {
  computeAlgorithmDistribution,
  computeLanguageDistribution,
} from "../../utils/risk"

const RISK_COLORS = {
  CRITICAL: "var(--red)",
  HIGH: "var(--orange)",
  MEDIUM: "var(--amber)",
  LOW: "var(--green)",
}

function Dashboard({ analysis, searchQuery = "", onSearchChange }) {
  const findings = analysis?.findings || []
  const distribution = analysis?.risk?.risk_distribution || {}

  const riskData = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(
    (label) => ({
      label: label[0] + label.slice(1).toLowerCase(),
      value: distribution[label] || 0,
      color: RISK_COLORS[label],
    })
  )

  const assessments = analysis?.risk?.assessments || []

  const enriched = findings.map((finding) => ({
    ...finding,
    risk_level:
      assessments.find(
        (item) => item.algorithm === finding.algorithm
      )?.risk_level || null,
  }))

  const query = searchQuery.trim().toLowerCase()

  const filtered = query
    ? enriched.filter((finding) =>
        Object.values(finding).some((value) =>
          String(value || "")
            .toLowerCase()
            .includes(query)
        )
      )
    : enriched

  const highRisk =
    (distribution.CRITICAL || 0) +
    (distribution.HIGH || 0)

  const quantumRelevant = assessments.filter(
    (item) => item.quantum_relevance === "HIGH"
  ).length

  return (
    <main className="dashboard">
      <SummaryHero analysis={analysis} />

      <section
        className="dashboard__cards"
        aria-label="Key statistics"
      >
        <StatCard
          title="Total Findings"
          value={findings.length}
          icon={Files}
          tone="accent"
          description="Cryptographic usages detected in the latest scan"
        />

        <StatCard
          title="High Risk"
          value={highRisk}
          icon={ShieldAlert}
          tone="red"
          description="Critical and high-risk CBOM components"
        />

        <StatCard
          title="Components"
          value={analysis?.cbom?.components?.length || 0}
          icon={Braces}
          tone="cyan"
          description="Distinct cryptographic components in the CBOM"
        />

        <StatCard
          title="Quantum Relevant"
          value={quantumRelevant}
          icon={Atom}
          tone="amber"
          description="Components requiring PQC migration planning"
        />
      </section>

      {analysis ? (
        <>
          <PriorityActions
            assessments={assessments}
            limit={5}
          />

          <div className="dashboard__viz-row">
            <RiskDistribution
              data={riskData}
              total={analysis.risk?.assets_assessed || 0}
            />

            <AlgorithmDistribution
              data={computeAlgorithmDistribution(findings)}
            />

            <LanguageDistribution
              data={computeLanguageDistribution(findings)}
            />
          </div>

          <RecentFindings
            findings={filtered}
            totalCount={findings.length}
            limit={8}
            searchQuery={searchQuery}
            onSearchChange={onSearchChange}
          />
        </>
      ) : (
        <section className="dashboard__empty">
          Run a scan to display real findings, CBOM
          inventory, and risk results.
        </section>
      )}
    </main>
  )
}

export default Dashboard