import { Table } from './components'

// Reused by both TaskDetail and the standalone Evidence browser page - one
// component, not two, per the Stage D spec.
export function EvidenceView({ evidence }: { evidence: any[] }) {
  if (!evidence || evidence.length === 0) return <p>No evidence recorded.</p>
  return (
    <Table
      columns={['Type', 'Summary', 'Recorded At']}
      rows={evidence.map((e) => [
        e.kind ?? e.type ?? '-',
        <pre style={{ margin: 0, whiteSpace: 'pre-wrap', maxWidth: 500 }}>
          {JSON.stringify(e.detail ?? e.data ?? e, null, 2)}
        </pre>,
        e.recorded_at ?? e.created_at ?? '-',
      ])}
    />
  )
}
