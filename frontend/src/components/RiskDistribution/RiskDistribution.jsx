import "./RiskDistribution.css"
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts"
import { ShieldCheck } from "lucide-react"

function CustomTooltip({ active, payload }) {
  if (!active || !payload?.length) return null
  const item = payload[0]
  return (
    <div className="risk-dist__tooltip">
      <span className="risk-dist__tooltip-swatch" style={{ background: item.payload.color }} />
      <span className="risk-dist__tooltip-label">{item.name} risk</span>
      <span className="risk-dist__tooltip-value">
        {item.value} ({item.payload.percentage}%)
      </span>
    </div>
  )
}

function RiskDistribution({ data, total }) {
  const totalValue = data.reduce((sum, item) => sum + item.value, 0)
  const withPct = data.map((item) => ({
    ...item,
    percentage: totalValue ? Math.round((item.value / totalValue) * 100) : 0,
  }))

  return (
    <section className="risk-dist">
      <div className="risk-dist__header">
        <div className="risk-dist__heading">
          <ShieldCheck size={15} strokeWidth={2} className="risk-dist__heading-icon" />
          <h2>Risk distribution</h2>
        </div>
        <span className="risk-dist__hint">By severity</span>
      </div>

      <div className="risk-dist__body">
        <div className="risk-dist__chart">
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={withPct}
                dataKey="value"
                nameKey="label"
                cx="50%"
                cy="50%"
                innerRadius={58}
                outerRadius={82}
                paddingAngle={4}
                strokeWidth={0}
              >
                {withPct.map((entry) => (
                  <Cell key={entry.label} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
            </PieChart>
          </ResponsiveContainer>
          <div className="risk-dist__center">
            <span className="risk-dist__center-value">{total ?? totalValue}</span>
            <span className="risk-dist__center-label">findings</span>
          </div>
        </div>

        <ul className="risk-dist__legend">
          {withPct.map((item) => (
            <li key={item.label} className="risk-dist__legend-item">
              <span className="risk-dist__swatch" style={{ background: item.color }} />
              <span className="risk-dist__legend-label">{item.label} risk</span>
              <div className="risk-dist__legend-meta">
                <span className="risk-dist__legend-pct">{item.percentage}%</span>
                <span className="risk-dist__legend-value">{item.value}</span>
              </div>
            </li>
          ))}
        </ul>
      </div>
    </section>
  )
}

export default RiskDistribution
