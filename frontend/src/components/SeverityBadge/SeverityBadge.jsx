import "./SeverityBadge.css"

const SEVERITY_META = {
  critical: { label: "Critical", class: "severity-badge--high" },
  high: { label: "High", class: "severity-badge--high" },
  medium: { label: "Medium", class: "severity-badge--medium" },
  low: { label: "Low", class: "severity-badge--low" },
  none: { label: "None", class: "severity-badge--none" },
}

function SeverityBadge({ level }) {
  const meta = SEVERITY_META[level] ?? SEVERITY_META.none
  return <span className={`severity-badge ${meta.class}`}>{meta.label}</span>
}

export default SeverityBadge
