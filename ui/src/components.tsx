// Small shared, dumb view components. None of these call the API or
// contain platform logic - they only render data passed in as props.
import type React from 'react'

// Five non-interchangeable states, matched in order (most specific first):
// PASS (calm), FAIL (real problem), BLOCKED (external precondition -
// deliberately its own hue, distinct from FAIL: a repo that's BLOCKED on
// registry access is not the same finding as one that FAILED a real
// check), UNAVAILABLE (this install can't provide the capability),
// SKIPPED/neutral (not applicable - falls through to the default).
// Existing callers (deny/allow/mocked/etc. from policy and provider
// status) are unaffected - same words, same buckets as before.
function statusColors(value: string): { fg: string; bg: string } {
  // Severity values (security/models.py::SecuritySeverity) never matched
  // any bucket before this - every finding rendered the same neutral
  // gray regardless of severity. Bucketed into the existing 5-state
  // palette rather than adding a 6th color.
  if (/^(critical|high)$/i.test(value)) return { fg: 'var(--fail)', bg: 'var(--fail-dim)' }
  if (/^medium$/i.test(value)) return { fg: 'var(--unavailable)', bg: 'var(--unavailable-dim)' }
  if (/^(low|info)$/i.test(value)) return { fg: 'var(--skipped)', bg: 'var(--skipped-dim)' }

  if (/allow|success|healthy|ok|published|real|^pass$/i.test(value)) {
    return { fg: 'var(--pass)', bg: 'var(--pass-dim)' }
  }
  if (/deny|fail|error|^fail$/i.test(value)) {
    return { fg: 'var(--fail)', bg: 'var(--fail-dim)' }
  }
  if (/^blocked$/i.test(value)) {
    return { fg: 'var(--blocked)', bg: 'var(--blocked-dim)' }
  }
  if (/unavailable|approval|warn|pending|mocked/i.test(value)) {
    return { fg: 'var(--unavailable)', bg: 'var(--unavailable-dim)' }
  }
  return { fg: 'var(--skipped)', bg: 'var(--skipped-dim)' } // SKIPPED/UNKNOWN/NOT_APPLICABLE/default
}

export function StatusBadge({ value }: { value: string }) {
  const { fg, bg } = statusColors(value)
  return (
    <span className="badge" style={{ background: bg, color: fg }}>
      <span className="dot" style={{ background: fg }} />
      {value}
    </span>
  )
}

export function Table({ columns, rows }: { columns: string[]; rows: (string | number | React.ReactNode)[][] }) {
  return (
    <table>
      <thead>
        <tr>{columns.map((c) => <th key={c}>{c}</th>)}</tr>
      </thead>
      <tbody>
        {rows.map((row, i) => (
          <tr key={i}>{row.map((cell, j) => <td key={j}>{cell}</td>)}</tr>
        ))}
      </tbody>
    </table>
  )
}

export function ErrorBox({ message }: { message: string }) {
  return (
    <div className="badge" style={{ background: 'var(--fail-dim)', color: 'var(--fail)', padding: '8px 12px' }}>
      Error: {message}
    </div>
  )
}

export function Loading() {
  return <div style={{ padding: 8, color: 'var(--text-faint)', fontSize: 13 }}>Loading…</div>
}
