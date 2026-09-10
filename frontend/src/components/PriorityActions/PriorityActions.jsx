import "./PriorityActions.css"
import { Eye, ShieldAlert } from "lucide-react"
import { toRiskLevel, toRelativeLocation } from "../../utils/risk"

const RISK_META = {
  high: { label: "High", class: "risk-badge--high" },
  medium: { label: "Medium", class: "risk-badge--medium" },
  low: { label: "Low", class: "risk-badge--low" },
}

const ACTION_TEXT = {
  high: "Replace with post-quantum alternative",
  medium: "Evaluate quantum resistance",
  low: "No immediate action required",
}

function PriorityActions({ findings, limit = 5 }) {
  const sorted = [...findings].sort((a, b) => {
    const order = { high: 0, medium: 1, low: 2 }
    return (order[toRiskLevel(a)] ?? 3) - (order[toRiskLevel(b)] ?? 3)
  }).slice(0, limit)

  return (
    <section className="priority-actions">
      <div className="priority-actions__header">
        <div className="priority-actions__heading">
          <ShieldAlert size={16} strokeWidth={2} className="priority-actions__heading-icon" />
          <h2>Priority actions</h2>
        </div>
        <span className="priority-actions__hint">Highest risk first</span>
      </div>

      <div className="priority-actions__table-wrap">
        <table className="priority-actions__table">
          <thead>
            <tr>
              <th className="priority-actions__col-sev">Severity</th>
              <th>Algorithm</th>
              <th>Source location</th>
              <th>Risk level</th>
              <th>Recommended action</th>
              <th className="priority-actions__col-act" aria-label="View" />
            </tr>
          </thead>
          <tbody>
            {sorted.map((finding) => {
              const risk = toRiskLevel(finding)
              const meta = RISK_META[risk]
              return (
                <tr key={finding.id} className={`priority-actions__row priority-actions__row--${risk}`}>
                  <td className="priority-actions__col-sev">
                    <span className="priority-actions__sev">
                      <span className={`priority-actions__dot priority-actions__dot--${risk}`} />
                    </span>
                  </td>
                  <td>
                    <div className="priority-actions__algo">
                      <span className="priority-actions__algo-name">{finding.algorithm}</span>
                      {finding.key_size != null && (
                        <span className="priority-actions__algo-size">{finding.key_size}-bit</span>
                      )}
                    </div>
                  </td>
                  <td>
                    <div className="priority-actions__loc">
                      <span className="priority-actions__file">{toRelativeLocation(finding)}</span>
                      <span className="priority-actions__lang">{finding.language}</span>
                    </div>
                  </td>
                  <td>
                    <span className={`risk-badge ${meta.class}`}>{meta.label}</span>
                  </td>
                  <td>
                    <span className="priority-actions__action">{ACTION_TEXT[risk]}</span>
                  </td>
                  <td className="priority-actions__col-act">
                    <button type="button" className="priority-actions__view" aria-label={`View ${finding.algorithm} finding`}>
                      <Eye size={14} strokeWidth={2} />
                      View
                    </button>
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

export default PriorityActions
