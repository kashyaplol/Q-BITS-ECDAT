import './PriorityActions.css'
import { toRiskLevel, toRelativeLocation } from '../../utils/risk'

const RISK_LABEL = { high: 'High', medium: 'Medium', low: 'Low' }

const ACTIONS = {
  high: 'Replace with post-quantum alternative',
  medium: 'Evaluate quantum resistance & plan migration',
  low: 'No immediate action required',
}

function PriorityActions({ findings, limit = 5 }) {
  const sorted = [...findings]
    .sort((a, b) => {
      const order = { high: 0, medium: 1, low: 2 }
      return (order[toRiskLevel(a)] ?? 3) - (order[toRiskLevel(b)] ?? 3)
    })
    .slice(0, limit)

  return (
    <section className="priority-actions">
      <div className="panel-header">
        <h2>Priority actions</h2>
        <span className="panel-header__hint">Highest risk first</span>
      </div>

      <div className="priority-actions__list">
        {sorted.map((finding) => {
          const risk = toRiskLevel(finding)
          return (
            <div className="priority-actions__row" key={finding.id}>
              <div className={`priority-actions__severity priority-actions__severity--${risk}`}>
                <span className="priority-actions__severity-dot" />
              </div>
              <div className="priority-actions__algo">
                <span className="priority-actions__algo-name">{finding.algorithm}</span>
                {finding.key_size != null && (
                  <span className="priority-actions__algo-size">{finding.key_size}-bit</span>
                )}
              </div>
              <div className="priority-actions__loc">
                <span className="priority-actions__file">{toRelativeLocation(finding)}</span>
                <span className="priority-actions__lang">{finding.language}</span>
              </div>
              <span className={`risk-badge risk-badge--${risk}`}>{RISK_LABEL[risk]}</span>
              <span className="priority-actions__action">{ACTIONS[risk]}</span>
              <button type="button" className="priority-actions__view">View</button>
            </div>
          )
        })}
      </div>
    </section>
  )
}

export default PriorityActions
