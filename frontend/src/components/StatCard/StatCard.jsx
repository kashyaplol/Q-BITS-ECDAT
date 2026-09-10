import "./StatCard.css"

function StatCard({ title, value, delta, description, icon: Icon, tone = "accent" }) {
  const toneClass = `stat-card--${tone}`

  return (
    <div className={`stat-card ${toneClass}`}>
      <div className="stat-card__top">
        <div className="stat-card__icon">
          <Icon size={18} strokeWidth={2} />
        </div>
        {delta != null && (
          <span className={`stat-card__delta${delta >= 0 ? "" : " is-down"}`}>
            {delta >= 0 ? "+" : ""}
            {delta}%
          </span>
        )}
      </div>
      <div className="stat-card__value">{value}</div>
      <div className="stat-card__title">{title}</div>
      {description && <div className="stat-card__desc">{description}</div>}
    </div>
  )
}

export default StatCard
