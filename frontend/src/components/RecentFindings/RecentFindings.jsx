import "./RecentFindings.css"
import { ListChecks } from "lucide-react"
import SeverityBadge from "../SeverityBadge/SeverityBadge"
import { toRiskLevel, toRelativeLocation, formatConfidence } from "../../utils/risk"

function RecentFindings({ findings, limit }) {
  const rows = limit != null ? findings.slice(0, limit) : findings

  return (
    <section className="recent-findings">
      <div className="recent-findings__header">
        <div className="recent-findings__heading">
          <ListChecks size={15} strokeWidth={2} className="recent-findings__heading-icon" />
          <h2>Recent findings</h2>
        </div>
        <span className="recent-findings__hint">
          Latest {rows.length} of {findings.length}
        </span>
      </div>

      <div className="recent-findings__table-wrap">
        <table className="recent-findings__table">
          <thead>
            <tr>
              <th>Algorithm</th>
              <th>Category</th>
              <th>Location</th>
              <th>Key size</th>
              <th>Confidence</th>
              <th>Detection</th>
              <th>Risk</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((finding) => {
              const risk = toRiskLevel(finding)
              return (
                <tr key={finding.id}>
                  <td>
                    <span className="recent-findings__algo">{finding.algorithm}</span>
                    {finding.symbol_name && (
                      <span className="recent-findings__symbol">{finding.symbol_name}</span>
                    )}
                  </td>
                  <td>
                    <span className={`recent-findings__tag recent-findings__tag--${finding.category}`}>
                      {finding.category}
                    </span>
                  </td>
                  <td>
                    <div className="recent-findings__loc">
                      <span className="recent-findings__file">{toRelativeLocation(finding)}</span>
                      <span className="recent-findings__lang">{finding.language}</span>
                    </div>
                  </td>
                  <td className="recent-findings__keysize">
                    {finding.key_size != null ? `${finding.key_size}` : "---"}
                  </td>
                  <td>
                    <span className="recent-findings__conf">{formatConfidence(finding.confidence)}</span>
                  </td>
                  <td>
                    <span className="recent-findings__method" title={finding.code_snippet}>
                      {finding.detection_method}
                    </span>
                  </td>
                  <td>
                    <SeverityBadge level={risk} />
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </section>
  )
}

export default RecentFindings