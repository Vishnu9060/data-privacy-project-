// Two small hand-authored SVG charts for the Wi-Fi Security page:
//   1. Risk distribution donut — HIGH/MEDIUM/LOW/INFO counts, using the
//      app's reserved status/risk color tokens (never a generic categorical
//      palette for a status encoding).
//   2. Band split bar — how many networks are on 2.4GHz vs 5GHz vs 6GHz.
// No charting library: both are small, fixed-shape visuals better done as
// plain SVG than pulled in as a dependency.

const RISK_ORDER = ['HIGH', 'MEDIUM', 'LOW', 'INFO']
const RISK_CLASS = {
  HIGH: 'risk-high',
  MEDIUM: 'risk-medium',
  LOW: 'risk-low',
  INFO: 'risk-info',
}

function polarPoint(cx, cy, r, angleRad) {
  return [cx + r * Math.cos(angleRad), cy + r * Math.sin(angleRad)]
}

function donutSlicePath(cx, cy, rOuter, rInner, startAngle, endAngle) {
  const largeArc = endAngle - startAngle > Math.PI ? 1 : 0
  const [x1, y1] = polarPoint(cx, cy, rOuter, startAngle)
  const [x2, y2] = polarPoint(cx, cy, rOuter, endAngle)
  const [x3, y3] = polarPoint(cx, cy, rInner, endAngle)
  const [x4, y4] = polarPoint(cx, cy, rInner, startAngle)
  return [
    `M ${x1} ${y1}`,
    `A ${rOuter} ${rOuter} 0 ${largeArc} 1 ${x2} ${y2}`,
    `L ${x3} ${y3}`,
    `A ${rInner} ${rInner} 0 ${largeArc} 0 ${x4} ${y4}`,
    'Z',
  ].join(' ')
}

export function RiskDonut({ riskCounts }) {
  const total = RISK_ORDER.reduce((sum, k) => sum + (riskCounts[k] || 0), 0)
  if (total === 0) return null

  const size = 200
  const cx = size / 2
  const cy = size / 2
  const rOuter = 82
  const rInner = 52

  let angle = -Math.PI / 2 // start at 12 o'clock
  const slices = RISK_ORDER.filter((k) => riskCounts[k] > 0).map((key) => {
    const count = riskCounts[key]
    const sweep = (count / total) * 2 * Math.PI
    const path = donutSlicePath(cx, cy, rOuter, rInner, angle, angle + sweep)
    angle += sweep
    return { key, count, path }
  })

  return (
    <div className="donut-wrap">
      <svg viewBox={`0 0 ${size} ${size}`} role="img" aria-label="Security risk distribution of nearby Wi-Fi networks" className="donut-svg">
        {slices.map((s) => (
          <path key={s.key} d={s.path} className={`donut-slice risk-fill-${RISK_CLASS[s.key]}`}>
            <title>{s.key}: {s.count} network{s.count === 1 ? '' : 's'}</title>
          </path>
        ))}
        <text x={cx} y={cy - 4} textAnchor="middle" className="donut-center-num">{total}</text>
        <text x={cx} y={cy + 16} textAnchor="middle" className="donut-center-label">networks</text>
      </svg>
      <ul className="donut-legend">
        {RISK_ORDER.filter((k) => riskCounts[k] > 0).map((key) => (
          <li key={key} className="donut-legend-item">
            <span className={`donut-swatch risk-fill-${RISK_CLASS[key]}`} />
            {key} ({riskCounts[key]})
          </li>
        ))}
      </ul>
    </div>
  )
}

export function BandBars({ bandCounts }) {
  const bands = ['2.4GHz', '5GHz', '6GHz'].filter((b) => bandCounts[b] > 0)
  if (bands.length === 0) return null
  const max = Math.max(...bands.map((b) => bandCounts[b]))

  return (
    <div className="band-bars">
      {bands.map((band) => (
        <div className="band-bar-row" key={band}>
          <span className="band-bar-label">{band}</span>
          <div className="band-bar-track">
            <div
              className="band-bar-fill"
              style={{ width: `${(bandCounts[band] / max) * 100}%` }}
            />
          </div>
          <span className="band-bar-value">{bandCounts[band]}</span>
        </div>
      ))}
    </div>
  )
}
