import "./AlgorithmDistribution.css"
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, Cell } from "recharts"
import { Cpu } from "lucide-react"

const BAR_COLORS = ["var(--accent)", "var(--cyan)"]

function CustomTooltip({ active, payload }) {
  if (!active || !payload?.length) return null
  const item = payload[0]
  return (
    <div className="algo-dist__tooltip">
      <span className="algo-dist__tooltip-label">{item.payload.algorithm}</span>
      <span className="algo-dist__tooltip-value">{item.value} finding{item.value === 1 ? "" : "s"}</span>
    </div>
  )
}

function AlgorithmDistribution({ data }) {
  return (
    <section className="algo-dist">
      <div className="algo-dist__header">
        <div className="algo-dist__heading">
          <Cpu size={15} strokeWidth={2} className="algo-dist__heading-icon" />
          <h2>Algorithm distribution</h2>
        </div>
        <span className="algo-dist__hint">{data.length} algorithms</span>
      </div>

      <div className="algo-dist__chart">
        <ResponsiveContainer width="100%" height={Math.max(200, data.length * 26 + 30)}>
          <BarChart data={data} layout="vertical" margin={{ top: 4, right: 28, bottom: 0, left: 8 }}>
            <XAxis type="number" hide />
            <YAxis
              type="category"
              dataKey="algorithm"
              width={84}
              tick={{ fill: "var(--text)", fontSize: 11.5, fontFamily: "var(--mono)" }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip content={<CustomTooltip />} cursor={{ fill: "var(--bg-surface-hover)" }} />
            <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={14}>
              {data.map((entry, i) => (
                <Cell key={entry.algorithm} fill={BAR_COLORS[i % BAR_COLORS.length]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </section>
  )
}

export default AlgorithmDistribution