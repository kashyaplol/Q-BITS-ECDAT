import "./LanguageDistribution.css"
import { BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip, Cell } from "recharts"
import { Code2 } from "lucide-react"

const LANG_COLORS = {
  Python: "#3572A5",
  Go: "#00ADD8",
  JavaScript: "#f1e05a",
  TypeScript: "#3178c6",
  Java: "#b07219",
  Rust: "#dea584",
  Ruby: "#CC342D",
  C: "#555555",
  "C++": "#f34b7d",
  PHP: "#4F5D95",
  Config: "#6e7681",
  JSON: "#6e7681",
}

const DEFAULT_COLOR = "var(--accent)"

function CustomTooltip({ active, payload }) {
  if (!active || !payload?.length) return null
  const item = payload[0]
  return (
    <div className="lang-dist__tooltip">
      <span className="lang-dist__tooltip-label">{item.payload.language}</span>
      <span className="lang-dist__tooltip-value">
        {item.value} finding{item.value === 1 ? "" : "s"}
      </span>
    </div>
  )
}

function LanguageDistribution({ data }) {
  return (
    <section className="lang-dist">
      <div className="lang-dist__header">
        <div className="lang-dist__heading">
          <Code2 size={15} strokeWidth={2} className="lang-dist__heading-icon" />
          <h2>Languages</h2>
        </div>
        <span className="lang-dist__hint">{data.length} languages</span>
      </div>

      <div className="lang-dist__chart">
        <ResponsiveContainer width="100%" height={Math.max(160, data.length * 28 + 24)}>
          <BarChart data={data} layout="vertical" margin={{ top: 4, right: 28, bottom: 0, left: 8 }}>
            <XAxis type="number" hide />
            <YAxis
              type="category"
              dataKey="language"
              width={80}
              tick={{ fill: "var(--text)", fontSize: 11.5, fontFamily: "var(--mono)" }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip content={<CustomTooltip />} cursor={{ fill: "var(--bg-surface-hover)" }} />
            <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={14}>
              {data.map((entry) => (
                <Cell key={entry.language} fill={LANG_COLORS[entry.language] || DEFAULT_COLOR} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </section>
  )
}

export default LanguageDistribution
