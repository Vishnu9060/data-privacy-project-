const NAV_GROUPS = [
  {
    label: 'Footfall Analytics',
    items: [
      { id: 'footfall', icon: '👣', label: 'Shop Visitor Dashboard' },
    ],
  },
  {
    label: 'Security Operations',
    items: [
      { id: 'network', icon: '🛰️', label: 'Network Discovery' },
      { id: 'packets', icon: '🔍', label: 'Packet Sniffer' },
      { id: 'mac', icon: '🔒', label: 'MAC Address Tool' },
      { id: 'ports', icon: '⚠️', label: 'Port Scanner' },
    ],
  },
  {
    label: 'Intelligence',
    items: [
      { id: 'intelligence', icon: '🧠', label: 'Threat Analysis & AI Reports' },
    ],
  },
]

export default function Sidebar({ activePage, onNavigate, currentMac, onRandomize, macLoading }) {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <span className="brand-mark">◎</span>
        SHOPRADAR
      </div>

      {NAV_GROUPS.map((group) => (
        <div key={group.label}>
          <div className="sidebar-group-label">{group.label}</div>
          {group.items.map((item) => (
            <button
              key={item.id}
              className={activePage === item.id ? 'sidebar-link active' : 'sidebar-link'}
              onClick={() => onNavigate(item.id)}
            >
              <span className="link-icon">{item.icon}</span>
              {item.label}
            </button>
          ))}
        </div>
      ))}

      <div className="sidebar-spacer" />

      <div className="identity-card">
        <div className="identity-label">Current Identity</div>
        <div className="identity-mac">{currentMac || 'Not detected yet'}</div>
        <button className="identity-btn" onClick={onRandomize} disabled={macLoading}>
          {macLoading ? 'Randomizing…' : 'Randomize MAC'}
        </button>
      </div>
    </aside>
  )
}
