import "./PriorityActions.css"
import { Eye, ShieldAlert } from "lucide-react"
const RISK_META = {
  critical: { label: "Critical", class: "risk-badge--critical" },
  high: { label: "High", class: "risk-badge--high" },
  medium: { label: "Medium", class: "risk-badge--medium" },
  low: { label: "Low", class: "risk-badge--low" },
}

function PriorityActions({ assessments, limit = 5 }) {
  const sorted = [...assessments].sort((a, b) => a.risk_score - b.risk_score).reverse().slice(0, limit)

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
            {sorted.map((assessment) => {
              const risk = assessment.risk_level.toLowerCase()
              const meta = RISK_META[risk]
              return (
                <tr key={assessment.identifier} className={`priority-actions__row priority-actions__row--${risk}`}>
                  <td className="priority-actions__col-sev">
                    <span className="priority-actions__sev">
                      <span className={`priority-actions__dot priority-actions__dot--${risk}`} />
                    </span>
                  </td>
                  <td>
                    <div className="priority-actions__algo">
                      <span className="priority-actions__algo-name">{assessment.algorithm}</span>
                      {assessment.key_sizes.length > 0 && (
                        <span className="priority-actions__algo-size">{assessment.key_sizes.join(", ")}-bit</span>
                      )}
                    </div>
                  </td>
                  <td>
                    <div className="priority-actions__loc">
                      <span className="priority-actions__file">{assessment.affected_files.join(", ") || "Location unavailable"}</span>
                      <span className="priority-actions__lang">{assessment.migration_priority}</span>
                    </div>
                  </td>
                  <td>
                    <span className={`risk-badge ${meta.class}`}>{meta.label}</span>
                  </td>
                  <td>
                    <span className="priority-actions__action">{assessment.recommendation}</span>
                  </td>
                  <td className="priority-actions__col-act">
                    <button 
                      type="button" 
                      className="priority-actions__view" 
                      aria-label={`View ${assessment.algorithm} assessment`}
                      onClick={() => window.location.hash = 'migration'}
                    >
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
