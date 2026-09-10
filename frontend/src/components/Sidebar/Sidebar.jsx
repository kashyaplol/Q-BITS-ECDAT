import "./Sidebar.css"
import { LayoutDashboard, ScanSearch, ShieldAlert, Gauge, Boxes, MoveRight, Settings, Radar } from "lucide-react"

const NAV_GROUPS = [
  {
    label: "Overview",
    items: [
      { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
      { id: "scan", label: "New Scan", icon: ScanSearch },
    ],
  },
  {
    label: "Analysis",
    items: [
      { id: "findings", label: "Crypto Findings", icon: ShieldAlert },
      { id: "risk", label: "Risk Assessment", icon: Gauge },
      { id: "cbom", label: "CBOM", icon: Boxes },
      { id: "migration", label: "Migration", icon: MoveRight },
    ],
  },
  {
    label: "System",
    items: [{ id: "settings", label: "Settings", icon: Settings }],
  },
]

function Sidebar({ activeItem, onSelect, findingCount, scanState }) {
  return (
    <aside className="sidebar">
      <div className="sidebar__brand">
        <div className="sidebar__logo">
          <Radar size={20} strokeWidth={2.2} />
        </div>
        <div className="sidebar__brand-text">
          <span className="sidebar__brand-name">Q-BITS</span>
          <span className="sidebar__brand-sub">ECDAT</span>
        </div>
      </div>

      <nav className="sidebar__nav">
        {NAV_GROUPS.map((group) => (
          <div className="sidebar__group" key={group.label}>
            <div className="sidebar__group-label">{group.label}</div>
            <ul className="sidebar__items">
              {group.items.map((item) => {
                const Icon = item.icon
                return (
                  <li key={item.id}>
                    <button
                      type="button"
                      className={`sidebar__item${activeItem === item.id ? " is-active" : ""}`}
                      onClick={() => onSelect?.(item.id)}
                    >
                      <span className="sidebar__item-icon">
                        <Icon size={17} strokeWidth={1.8} />
                      </span>
                      <span className="sidebar__item-label">{item.label}</span>
                      {item.id === "findings" && findingCount != null && <span className="sidebar__item-badge">{findingCount}</span>}
                    </button>
                  </li>
                )
              })}
            </ul>
          </div>
        ))}
      </nav>

      <div className="sidebar__footer">
        <div className="sidebar__agent">
          <span className="sidebar__status-dot" />
          <div className="sidebar__agent-text">
            <span className="sidebar__agent-label">Agent status</span>
            <span className="sidebar__agent-state">{scanState === "scanning" ? "Scanning" : "Idle"}</span>
          </div>
        </div>
      </div>
    </aside>
  )
}

export default Sidebar
