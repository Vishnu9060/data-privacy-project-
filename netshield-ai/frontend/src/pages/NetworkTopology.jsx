// Star-topology map: this machine at the center, each discovered host
// arranged around it with a line back to center — the classic "network map"
// view for a Network Discovery page. Hand-authored SVG (no charting/graph
// library) since this is a fixed small star layout, not a general graph.
//
// Node color follows host status (up/down) using the same tokens as the
// rest of the theme (currentColor + CSS classes), so it never drifts from
// a future palette change. Clicking a node scrolls to and briefly
// highlights its row in the table below, so the graph is a real navigation
// aid rather than a static picture.

const WIDTH = 640
const HEIGHT = 420
const CENTER_X = WIDTH / 2
const CENTER_Y = HEIGHT / 2
const RADIUS = Math.min(WIDTH, HEIGHT) / 2 - 70
const NODE_R = 20
const CENTER_NODE_R = 26

export default function NetworkTopology({ devices, onSelectHost }) {
  if (!devices || devices.length === 0) return null

  // Cap how many hosts get plotted directly around the hub — beyond this,
  // node labels start to overlap regardless of layout tricks. Extra hosts
  // are still in the table below; the graph is a map, not the source of
  // truth.
  const MAX_NODES = 16
  const shown = devices.slice(0, MAX_NODES)
  const overflow = devices.length - shown.length

  const nodes = shown.map((device, i) => {
    const angle = (2 * Math.PI * i) / shown.length - Math.PI / 2
    return {
      device,
      x: CENTER_X + RADIUS * Math.cos(angle),
      y: CENTER_Y + RADIUS * Math.sin(angle),
    }
  })

  return (
    <figure className="topology-figure">
      <svg
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        role="img"
        aria-label={`Network map: this machine connected to ${shown.length} discovered host${shown.length === 1 ? '' : 's'}`}
        className="topology-svg"
      >
        {/* Edges drawn first so nodes sit on top of the lines. */}
        {nodes.map(({ device, x, y }) => (
          <line
            key={`edge-${device.ip}`}
            x1={CENTER_X}
            y1={CENTER_Y}
            x2={x}
            y2={y}
            className={device.status === 'up' ? 'topo-edge topo-edge-up' : 'topo-edge topo-edge-down'}
          />
        ))}

        {/* Center hub = this machine. */}
        <circle cx={CENTER_X} cy={CENTER_Y} r={CENTER_NODE_R} className="topo-hub" />
        <text x={CENTER_X} y={CENTER_Y + 4} textAnchor="middle" className="topo-hub-label">
          YOU
        </text>

        {/* One node per discovered host. */}
        {nodes.map(({ device, x, y }) => {
          const isUp = device.status === 'up'
          const label = device.ip
          const sub = device.hostname && device.hostname !== 'unknown' ? device.hostname : ''
          return (
            <g
              key={device.ip}
              className="topo-node-group"
              onClick={() => onSelectHost && onSelectHost(device.ip)}
              tabIndex={0}
              role="button"
              aria-label={`Scan ${device.ip}${sub ? ` (${sub})` : ''}`}
              onKeyDown={(e) => {
                if ((e.key === 'Enter' || e.key === ' ') && onSelectHost) onSelectHost(device.ip)
              }}
            >
              <circle cx={x} cy={y} r={NODE_R} className={isUp ? 'topo-node topo-node-up' : 'topo-node topo-node-down'}>
                <title>{sub ? `${device.ip} (${sub})` : device.ip}</title>
              </circle>
              <text x={x} y={y + 4} textAnchor="middle" className="topo-node-icon">
                {isUp ? '●' : '○'}
              </text>
              <text x={x} y={y + NODE_R + 16} textAnchor="middle" className="topo-node-label">
                {label}
              </text>
            </g>
          )
        })}
      </svg>
      <figcaption className="topology-caption">
        Network map — {shown.filter((d) => d.status === 'up').length} of {shown.length} shown hosts responding.
        Click a node to scan it.
        {overflow > 0 && ` (${overflow} more host${overflow === 1 ? '' : 's'} in the table below.)`}
      </figcaption>
    </figure>
  )
}
