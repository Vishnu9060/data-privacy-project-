import { useEffect, useMemo, useState } from 'react'

// ============================================================
// Footfall Analytics dashboard.
//
// This shop has no cameras/IoT sensors — "visitors" are anonymized MAC
// addresses the project already observes elsewhere (Network Discovery's
// ARP sweep, the Packet Sniffer's captured frames). The same MAC seen
// again is treated as the same person returning. Backed by a local
// SQLite DB seeded with ~30 days of mock history so trends are visible
// immediately; every scan/capture you run elsewhere in the app adds real
// "live" sightings into the same dataset. See backend/footfall_db.py.
// ============================================================

function formatHour(h) {
  const hour = Number(h)
  const period = hour >= 12 ? 'PM' : 'AM'
  const display = hour % 12 === 0 ? 12 : hour % 12
  return `${display}${period}`
}

function formatDateShort(iso) {
  const d = new Date(iso + 'T00:00:00')
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

// ---- KPI tile ----
function KpiTile({ label, value, tone }) {
  return (
    <div className="stat-tile footfall-kpi-tile">
      <div className={`stat-tile-num${tone ? ' tone-' + tone : ''}`}>{value}</div>
      <div className="stat-tile-label">{label}</div>
    </div>
  )
}

// ---- Line + area chart: unique visitors per day ----
function VisitorTrendChart({ trend }) {
  const width = 720
  const height = 220
  const padL = 34
  const padR = 12
  const padT = 14
  const padB = 26
  const plotW = width - padL - padR
  const plotH = height - padT - padB

  const [hoverIdx, setHoverIdx] = useState(null)

  const maxVal = Math.max(1, ...trend.map((t) => t.unique_visitors))
  const step = trend.length > 1 ? plotW / (trend.length - 1) : 0

  const points = trend.map((t, i) => {
    const x = padL + i * step
    const y = padT + plotH - (t.unique_visitors / maxVal) * plotH
    return { x, y, ...t }
  })

  const linePath = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(' ')
  const areaPath = `${linePath} L ${points[points.length - 1].x.toFixed(1)} ${padT + plotH} L ${points[0].x.toFixed(1)} ${padT + plotH} Z`

  // Sparse x-axis labels so dates don't collide.
  const labelEvery = Math.ceil(trend.length / 6)

  const hovered = hoverIdx != null ? points[hoverIdx] : null

  return (
    <div className="chart-wrap">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="footfall-svg"
        role="img"
        aria-label="Unique visitors per day over the last 30 days"
        onMouseLeave={() => setHoverIdx(null)}
      >
        {[0, 0.5, 1].map((f) => {
          const y = padT + plotH * (1 - f)
          return (
            <g key={f}>
              <line x1={padL} x2={width - padR} y1={y} y2={y} className="chart-gridline" />
              <text x={padL - 8} y={y + 4} className="chart-axis-label" textAnchor="end">
                {Math.round(maxVal * f)}
              </text>
            </g>
          )
        })}

        {points.map((p, i) =>
          i % labelEvery === 0 ? (
            <text key={p.date} x={p.x} y={height - 6} className="chart-axis-label" textAnchor="middle">
              {formatDateShort(p.date)}
            </text>
          ) : null
        )}

        <path d={areaPath} className="chart-area-fill" />
        <path d={linePath} className="chart-line" />

        {hovered && (
          <line x1={hovered.x} x2={hovered.x} y1={padT} y2={padT + plotH} className="chart-crosshair" />
        )}

        {points.map((p, i) => (
          <circle
            key={p.date}
            cx={p.x}
            cy={p.y}
            r={hoverIdx === i ? 5 : 3}
            className="chart-dot"
            onMouseEnter={() => setHoverIdx(i)}
          />
        ))}
      </svg>

      {hovered && (
        <div
          className="chart-tooltip"
          style={{ left: `${(hovered.x / width) * 100}%`, top: `${(hovered.y / height) * 100}%` }}
        >
          <div className="chart-tooltip-title">{formatDateShort(hovered.date)}</div>
          <div><strong>{hovered.unique_visitors}</strong> unique visitors</div>
          <div className="chart-tooltip-sub">{hovered.total_visits} total visits</div>
        </div>
      )}
    </div>
  )
}

// ---- Sequential-shaded horizontal bar chart (frequency / dwell buckets) ----
function BucketBarChart({ data, valueKey, unitLabel }) {
  const max = Math.max(1, ...data.map((d) => d[valueKey]))
  return (
    <div className="bucket-bars">
      {data.map((d, i) => {
        const pct = (d[valueKey] / max) * 100
        const shade = 0.35 + (0.65 * (i + 1)) / data.length
        return (
          <div className="bucket-row" key={d.bucket}>
            <div className="bucket-label">{d.bucket}</div>
            <div className="bucket-track">
              <div
                className="bucket-fill"
                style={{ width: `${Math.max(pct, 3)}%`, opacity: shade }}
                title={`${d[valueKey]} ${unitLabel}`}
              />
            </div>
            <div className="bucket-value">{d[valueKey]}</div>
          </div>
        )
      })}
    </div>
  )
}

// ---- Peak-hours heatmap: day-of-week x hour ----
function PeakHoursHeatmap({ heatmap, hoursPresent }) {
  const allCounts = heatmap.flatMap((row) => hoursPresent.map((h) => row.hours[String(h)] || 0))
  const max = Math.max(1, ...allCounts)
  const [hoverCell, setHoverCell] = useState(null)

  return (
    <div className="heatmap-wrap">
      <div className="heatmap-grid" style={{ gridTemplateColumns: `52px repeat(${hoursPresent.length}, 1fr)` }}>
        <div className="heatmap-corner" />
        {hoursPresent.map((h) => (
          <div key={h} className="heatmap-hour-label">{formatHour(h)}</div>
        ))}
        {heatmap.map((row) => (
          <FragmentRow key={row.day} row={row} hoursPresent={hoursPresent} max={max} setHoverCell={setHoverCell} />
        ))}
      </div>
      {hoverCell && (
        <div className="heatmap-tooltip">
          <strong>{hoverCell.day} {formatHour(hoverCell.hour)}</strong> — {hoverCell.count} visits
        </div>
      )}
      <div className="heatmap-legend">
        <span className="chart-axis-label">Fewer</span>
        {[0.15, 0.35, 0.55, 0.75, 1].map((op) => (
          <span key={op} className="heatmap-legend-swatch" style={{ opacity: op }} />
        ))}
        <span className="chart-axis-label">More visits</span>
      </div>
    </div>
  )
}

function FragmentRow({ row, hoursPresent, max, setHoverCell }) {
  return (
    <>
      <div className="heatmap-day-label">{row.day}</div>
      {hoursPresent.map((h) => {
        const count = row.hours[String(h)] || 0
        const opacity = count === 0 ? 0 : 0.12 + 0.88 * (count / max)
        return (
          <div
            key={h}
            className="heatmap-cell"
            style={{ opacity: count === 0 ? 1 : 1, background: count === 0 ? undefined : `rgba(47, 111, 237, ${opacity})` }}
            onMouseEnter={() => setHoverCell({ day: row.day, hour: h, count })}
            onMouseLeave={() => setHoverCell(null)}
          />
        )
      })}
    </>
  )
}

export default function FootfallAnalyticsPage({ net }) {
  const { footfallData, footfallLoading, footfallError, handleLoadFootfall } = net

  useEffect(() => {
    if (!footfallData && !footfallLoading) {
      handleLoadFootfall()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const kpis = footfallData && !footfallData.empty ? footfallData.kpis : null

  const peakHourLabel = useMemo(() => {
    if (!kpis || kpis.peak_hour == null) return '—'
    return formatHour(kpis.peak_hour)
  }, [kpis])

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Shop Visitor Dashboard</h1>
        <p className="page-subtitle">
          Footfall analytics for the shop — visitor volume, repeat customers, peak hours, and dwell time, derived
          from anonymized device sightings (no cameras). Blends ~30 days of mock history with live scans/captures.
        </p>
      </div>

      <div className="field-row">
        <button className="btn" onClick={handleLoadFootfall} disabled={footfallLoading}>
          {footfallLoading && <span className="radar-spinner" />}
          Refresh Dashboard
        </button>
        {kpis && (
          <span className="status-note">
            {kpis.total_visits} total visits recorded · {kpis.live_sightings} from live scans/captures
          </span>
        )}
      </div>

      {footfallLoading && !footfallData && <p className="status-loading">Loading footfall data…</p>}
      {footfallError && <p className="status-error">Error: {footfallError}</p>}

      {kpis && (
        <>
          <div className="footfall-kpi-grid">
            <KpiTile label="Total Unique Visitors" value={kpis.total_unique_visitors} />
            <KpiTile label="Visitors Today" value={kpis.visitors_today} tone="ok" />
            <KpiTile label="Avg Visitors / Day" value={kpis.avg_visitors_per_day} />
            <KpiTile label="Repeat Visitor Rate" value={`${kpis.repeat_rate_pct}%`} tone="warn" />
            <KpiTile label="Avg Dwell Time" value={`${kpis.avg_dwell_minutes}m`} />
            <KpiTile label="Busiest Hour" value={peakHourLabel} />
          </div>

          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">1. People Visited — Daily Trend</span>
              <span className="panel-tag">last 30 days</span>
            </div>
            <VisitorTrendChart trend={footfallData.visitor_trend} />
          </div>

          <div className="page-grid">
            <div className="panel">
              <div className="panel-header">
                <span className="panel-title">2. Same-Person Repeat Frequency</span>
                <span className="panel-tag">{kpis.total_unique_visitors} visitors</span>
              </div>
              <p className="report-description">
                How many times each unique visitor has come back, all-time. A higher share in the 4+ visit buckets
                means a loyal customer base.
              </p>
              <BucketBarChart data={footfallData.frequency} valueKey="visitors" unitLabel="visitors" />
            </div>

            <div className="panel">
              <div className="panel-header">
                <span className="panel-title">Top Regular Customers</span>
              </div>
              {footfallData.top_regulars.length === 0 ? (
                <p className="empty-hint">No repeat visitors yet.</p>
              ) : (
                <ul className="log-list">
                  {footfallData.top_regulars.map((r) => (
                    <li key={r.visitor_id}>
                      <span className="mono">{r.masked_id}</span> · {r.vendor} —{' '}
                      <strong>{r.visits}</strong> visits
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>

          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">3. Peak Hours — When The Shop Is Busiest</span>
              <span className="panel-tag">by day of week &amp; hour</span>
            </div>
            <PeakHoursHeatmap heatmap={footfallData.peak_hours.heatmap} hoursPresent={footfallData.peak_hours.hours_present} />
          </div>

          <div className="panel">
            <div className="panel-header">
              <span className="panel-title">4. Dwell Time — How Long Visitors Stay</span>
              <span className="panel-tag">median {footfallData.dwell.median_minutes}m</span>
            </div>
            <BucketBarChart data={footfallData.dwell.buckets} valueKey="visits" unitLabel="visits" />
          </div>
        </>
      )}

      {footfallData && footfallData.empty && (
        <p className="empty-hint">No footfall data yet.</p>
      )}
    </>
  )
}
