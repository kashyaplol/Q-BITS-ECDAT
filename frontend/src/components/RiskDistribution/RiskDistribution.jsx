import './RiskDistribution.css'

function RiskDistribution({ data, total }) {
  const totalValue = data.reduce((sum, item) => sum + item.value, 0)

  const segments = data.reduce(
    (acc, item) => {
      const start = acc.total
      return {
        total: start + item.value,
        items: [...acc.items, { ...item, start }],
      }
    },
    { total: 0, items: [] },
  ).items

  const radius = 45
  const circumference = 2 * Math.PI * radius
  const paddedCircumference = circumference - segments.length * 6

  return (
    <section className="risk-distribution">
      <div className="panel-header">
        <h2>Risk distribution</h2>
        <span className="panel-header__hint">By severity</span>
      </div>

      <div className="risk-distribution__body">
        <div className="risk-distribution__chart">
          <svg viewBox="0 0 120 120" role="img" aria-label="Risk distribution donut chart">
            <circle cx="60" cy="60" r={radius} fill="none" stroke="var(--bg-surface)" strokeWidth="12" />
            {segments.map((seg) => {
              const startAngle = (seg.start / totalValue) * paddedCircumference
              const sweepAngle = (seg.value / totalValue) * paddedCircumference - 4
              const isFull = sweepAngle >= paddedCircumference
              return (
                <circle
                  key={seg.label}
                  cx="60"
                  cy="60"
                  r={radius}
                  fill="none"
                  stroke={seg.color}
                  strokeWidth="12"
                  strokeDasharray={`${isFull ? paddedCircumference : Math.max(sweepAngle, 1)} ${circumference}`}
                  strokeDashoffset={-startAngle}
                  strokeLinecap={isFull ? 'butt' : 'round'}
                  transform="rotate(-90 60 60)"
                />
              )
            })}
            <text x="60" y="56" textAnchor="middle" className="risk-distribution__total">
              {total ?? totalValue}
            </text>
            <text x="60" y="71" textAnchor="middle" className="risk-distribution__total-label">
              findings
            </text>
          </svg>
        </div>

        <ul className="risk-distribution__legend">
          {segments.map((seg) => (
            <li key={seg.label} className="risk-distribution__legend-item">
              <span className="risk-distribution__swatch" style={{ background: seg.color }} />
              <span className="risk-distribution__legend-label">{seg.label} risk</span>
              <span className="risk-distribution__legend-value">
                {seg.value}
                <span className="risk-distribution__legend-pct">
                  {Math.round((seg.value / totalValue) * 100)}%
                </span>
              </span>
            </li>
          ))}
        </ul>
      </div>
    </section>
  )
}

export default RiskDistribution