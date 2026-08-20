// Small shared, dumb view components. None of these call the API or
// contain platform logic - they only render data passed in as props.
import type React from 'react'
export function StatusBadge({ value }: { value: string }) {
  const color =
    /allow|success|healthy|ok|published|real/i.test(value) ? '#1a7f37'
    : /deny|fail|error|blocked/i.test(value) ? '#cf222e'
    : /approval|warn|pending|mocked/i.test(value) ? '#9a6700'
    : '#57606a'
  return (
    <span style={{
      display: 'inline-block', padding: '2px 8px', borderRadius: 12,
      fontSize: 12, fontWeight: 600, color: '#fff', background: color,
    }}>{value}</span>
  )
}

export function Table({ columns, rows }: { columns: string[]; rows: (string | number | React.ReactNode)[][] }) {
  return (
    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 14 }}>
      <thead>
        <tr>{columns.map((c) => (
          <th key={c} style={{ textAlign: 'left', borderBottom: '2px solid #d0d7de', padding: 6 }}>{c}</th>
        ))}</tr>
      </thead>
      <tbody>
        {rows.map((row, i) => (
          <tr key={i}>{row.map((cell, j) => (
            <td key={j} style={{ borderBottom: '1px solid #eaeef2', padding: 6 }}>{cell}</td>
          ))}</tr>
        ))}
      </tbody>
    </table>
  )
}

export function ErrorBox({ message }: { message: string }) {
  return <div style={{ color: '#cf222e', padding: 8 }}>Error: {message}</div>
}

export function Loading() {
  return <div style={{ padding: 8, color: '#57606a' }}>Loading...</div>
}
