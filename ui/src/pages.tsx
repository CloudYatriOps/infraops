import { useEffect, useState } from 'react'
import { api } from './api'
import { StatusBadge, Table, ErrorBox, Loading } from './components'
import { EvidenceView } from './EvidenceView'

function useAsync<T>(fn: () => Promise<T>, deps: any[] = []) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const reload = () => {
    setLoading(true)
    setError(null)
    fn().then(setData).catch((e) => setError(e.message)).finally(() => setLoading(false))
  }
  useEffect(reload, deps) // eslint-disable-line react-hooks/exhaustive-deps
  return { data, error, loading, reload }
}

// ---- Dashboard --------------------------------------------------------
export function Dashboard() {
  const { data, error, loading, reload } = useAsync(() => api.systemStatusFast())
  const [full, setFull] = useState<any>(null)
  const [computing, setComputing] = useState(false)

  const computeFresh = async () => {
    setComputing(true)
    try {
      setFull(await api.systemStatusFull())
    } catch (e: any) {
      alert(e.message)
    } finally {
      setComputing(false)
    }
  }

  return (
    <div>
      <div className="glass">
        <p style={{ marginBottom: 0 }}>Engineering progress, demo readiness, and deployability are
          three separate concepts, computed live by the platform - never hand-typed
          percentages.</p>
      </div>
      <div className="glass">
        {loading && <Loading />}
        {error && <ErrorBox message={error} />}
        {data && (
          <div>
            <p><strong style={{ color: 'var(--text)' }}>Status:</strong> {data.status ?? 'unknown'}</p>
            {data.reason && <p>{data.reason}</p>}
          </div>
        )}
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={reload}>Refresh</button>
          <button onClick={computeFresh} disabled={computing}>
            {computing ? 'Computing fresh (this runs the full test suite, ~9-11 min)...' : 'Compute fresh'}
          </button>
        </div>
        {full && (
          <div style={{ marginTop: 14, paddingTop: 14, borderTop: '1px solid var(--border)' }}>
            <p><strong style={{ color: 'var(--text)' }}>Overall progress:</strong> {full.overall_percent}%</p>
            <p style={{ marginBottom: 0 }}><strong style={{ color: 'var(--text)' }}>Deployability:</strong> <StatusBadge value={full.deployability} /></p>
          </div>
        )}
      </div>
    </div>
  )
}

// ---- Project intelligence (health / cost / remediation) ---------------
function ProjectIntel({ projectId }: { projectId: string }) {
  const { data: health } = useAsync(() => api.healthScore(projectId), [projectId])
  const { data: cost } = useAsync(() => api.costIntelligence(projectId), [projectId])
  const { data: remediation } = useAsync(() => api.remediationDecisions(projectId), [projectId])
  const healthItem = health?.items?.[0]

  return (
    <div style={{ marginTop: 16, display: 'grid', gridTemplateColumns: '1.3fr 1fr', gap: 16, alignItems: 'start' }}>
      <div className="glass">
        <h4>Engineering health</h4>
        {healthItem ? (
          <div>
            <p><StatusBadge value={healthItem.overall_state} /></p>
            {Object.entries(healthItem.subsystem_states || {}).map(([sub, s]: [string, any]) => (
              <p key={sub}><code>{sub}</code> <StatusBadge value={s.state} /> {s.evidence}</p>
            ))}
            {(healthItem.top_risks || []).map((risk: any, i: number) => (
              <p key={i}>{typeof risk === 'string' ? risk : JSON.stringify(risk)}</p>
            ))}
          </div>
        ) : <Loading />}
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div className="glass">
          <h4>Cost intelligence</h4>
          {cost ? (
            <div>
              {(cost.signals || []).map((s: any, i: number) => (
                <p key={i}>
                  <code>{s.provider}</code> <StatusBadge value={s.status} /> {s.reason}
                </p>
              ))}
            </div>
          ) : <Loading />}
        </div>

        <div className="glass">
          <h4>Remediation decisions</h4>
          {remediation ? (
            <div>
              {remediation.items.length === 0 && <p style={{ marginBottom: 0 }}>No open findings.</p>}
              {remediation.items.map((d: any) => (
                <p key={d.finding_id}>
                  <code>{d.finding_id}</code> <StatusBadge value={d.decision} />{' '}
                  {d.policy_reference && <em>{d.policy_reference}</em>} {d.explanation}
                </p>
              ))}
            </div>
          ) : <Loading />}
        </div>
      </div>
    </div>
  )
}

// ---- Projects -----------------------------------------------------------
export function Projects(_props: { onOpen: (id: string) => void }) {
  const { data, error, loading, reload } = useAsync(() => api.listProjects())
  const [name, setName] = useState('')
  const [repoPath, setRepoPath] = useState('')
  const [creating, setCreating] = useState(false)
  const [selected, setSelected] = useState<any>(null)
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const create = async () => {
    setCreating(true)
    try {
      await api.createProject({ name, repo_path: repoPath })
      setName('')
      setRepoPath('')
      reload()
    } catch (e: any) {
      alert(e.message)
    } finally {
      setCreating(false)
    }
  }

  return (
    <div>
      <div className="glass" style={{ display: 'flex', gap: 8 }}>
        <input placeholder="name" value={name} onChange={(e) => setName(e.target.value)} />
        <input placeholder="repo_path" value={repoPath} onChange={(e) => setRepoPath(e.target.value)} />
        <button onClick={create} disabled={creating || !name || !repoPath}>Create</button>
      </div>
      <div className="glass">
        {loading && <Loading />}
        {error && <ErrorBox message={error} />}
        {data && (
          <Table
            columns={['Name', 'Repo Path', 'Posture', '']}
            rows={data.map((p: any) => [
              p.name, p.repo_path, <StatusBadge value={p.default_posture} />,
              <button onClick={async () => { setSelected(await api.getRepository(p.id)); setSelectedId(p.id) }}>View</button>,
            ])}
          />
        )}
      </div>
      {selected && (
        <div>
          <div className="glass">
            <h3 style={{ marginBottom: 10 }}>Repository</h3>
            <pre style={{ margin: 0 }}>{JSON.stringify(selected, null, 2)}</pre>
          </div>
          {selectedId && <ProjectIntel projectId={selectedId} />}
        </div>
      )}
    </div>
  )
}

// ---- Task execution -------------------------------------------------
export function TaskExecution({ onCreated }: { onCreated: (taskId: string) => void }) {
  const { data: projects } = useAsync(() => api.listProjects())
  const [projectId, setProjectId] = useState('')
  const [taskType, setTaskType] = useState('recon')
  const [payload, setPayload] = useState('{}')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async () => {
    setSubmitting(true)
    setError(null)
    try {
      const parsed = JSON.parse(payload || '{}')
      const task = await api.createTask({ project_id: projectId, type: taskType, payload: parsed })
      onCreated(task.id)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="glass" style={{ maxWidth: 480 }}>
      <div style={{ display: 'grid', gap: 10 }}>
        <label>Project
          <select value={projectId} onChange={(e) => setProjectId(e.target.value)} style={{ display: 'block', width: '100%', marginTop: 4 }}>
            <option value="">-- select --</option>
            {(projects ?? []).map((p: any) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
        </label>
        <label>Task type
          <input value={taskType} onChange={(e) => setTaskType(e.target.value)} style={{ display: 'block', width: '100%', marginTop: 4 }} />
        </label>
        <label>Payload (JSON)
          <textarea rows={4} value={payload} onChange={(e) => setPayload(e.target.value)} style={{ display: 'block', width: '100%', marginTop: 4, fontFamily: 'var(--mono)' }} />
        </label>
        {error && <ErrorBox message={error} />}
        <button onClick={submit} disabled={submitting || !projectId}>
          {submitting ? 'Running (goes through the real orchestrator)...' : 'Submit task'}
        </button>
      </div>
    </div>
  )
}

// ---- Task detail ------------------------------------------------------
export function TaskDetail({ taskId }: { taskId: string }) {
  const { data: task, error, loading } = useAsync(() => api.getTask(taskId), [taskId])
  const { data: evidenceResp } = useAsync(() => api.taskEvidence(taskId), [taskId])

  if (loading) return <Loading />
  if (error) return <ErrorBox message={error} />
  if (!task) return null

  return (
    <div>
      <div className="glass">
        <h3 className="mono" style={{ marginBottom: 10 }}>{task.id}</h3>
        <p><strong style={{ color: 'var(--text)' }}>Type:</strong> {task.type} &nbsp; <strong style={{ color: 'var(--text)' }}>Status:</strong> <StatusBadge value={task.status} /></p>
        <p><strong style={{ color: 'var(--text)' }}>Project:</strong> {task.project_id} &nbsp; <strong style={{ color: 'var(--text)' }}>Owner agent:</strong> {task.owner_agent}</p>
        <p style={{ marginBottom: 0 }}><strong style={{ color: 'var(--text)' }}>Approval status:</strong> {task.approval_status ?? 'n/a'}</p>
      </div>
      <div className="glass">
        <h4>Payload</h4>
        <pre style={{ margin: 0 }}>{JSON.stringify(task.payload, null, 2)}</pre>
      </div>
      <div className="glass" style={{ marginBottom: 0 }}>
        <h4>Evidence</h4>
        <EvidenceView evidence={evidenceResp?.evidence ?? []} />
      </div>
    </div>
  )
}

// ---- Security findings ---------------------------------------------
export function Findings() {
  const { data, error, loading } = useAsync(() => api.findings())
  return (
    <div className="glass">
      {loading && <Loading />}
      {error && <ErrorBox message={error} />}
      {data && (
        <Table
          columns={['Severity', 'Category', 'Resource', 'Status', 'Description']}
          rows={data.map((f: any) => [
            <StatusBadge value={f.severity} />, f.category, f.resource, <StatusBadge value={f.status} />, f.description,
          ])}
        />
      )}
    </div>
  )
}

// ---- Incidents ----------------------------------------------------
export function Incidents() {
  const [projectId, setProjectId] = useState('')
  const { data: projects } = useAsync(() => api.listProjects())
  const { data, error, loading, reload } = useAsync(
    () => (projectId ? api.incidents(projectId) : Promise.resolve(null)), [projectId])

  return (
    <div>
      <div className="glass" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <select value={projectId} onChange={(e) => setProjectId(e.target.value)}>
          <option value="">-- select project --</option>
          {(projects ?? []).map((p: any) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
        <button onClick={reload} disabled={!projectId}>Refresh</button>
      </div>
      <div className="glass" style={{ marginBottom: 0 }}>
        {loading && <Loading />}
        {error && <ErrorBox message={error} />}
        {data && (
          <Table
            columns={['Id', 'Summary', 'Status']}
            rows={data.incidents.map((i: any) => [i.id, i.summary ?? '-', <StatusBadge value={i.status ?? '-'} />])}
          />
        )}
      </div>
    </div>
  )
}

// ---- Approvals ------------------------------------------------------
export function Approvals() {
  const { data, error, loading, reload } = useAsync(() => api.approvals())

  const act = async (id: string, fn: (id: string) => Promise<any>) => {
    try {
      await fn(id)
      reload()
    } catch (e: any) {
      alert(e.message)
    }
  }

  return (
    <div>
      <div className="glass">
        <p style={{ marginBottom: 0 }}>Tasks blocked on approval (real PolicyEngine transitions only -
          approving/rejecting here calls the same Orchestrator.approve()/
          reject() the CLI uses).</p>
      </div>
      <div className="glass" style={{ marginBottom: 0 }}>
        {loading && <Loading />}
        {error && <ErrorBox message={error} />}
        {data && (
          <Table
            columns={['Task', 'Type', 'Project', '']}
            rows={data.map((t: any) => [
              t.id, t.type, t.project_id,
              <span style={{ display: 'flex', gap: 6 }}>
                <button onClick={() => act(t.id, api.approveTask)}>Approve</button>
                <button onClick={() => act(t.id, (id) => api.rejectTask(id))}>Reject</button>
              </span>,
            ])}
          />
        )}
      </div>
    </div>
  )
}

// ---- Runtime status -------------------------------------------------
export function RuntimeStatus() {
  const { data, error, loading, reload } = useAsync(() => api.runtimeStatus())
  return (
    <div className="glass" style={{ marginBottom: 0 }}>
      {loading && <Loading />}
      {error && <ErrorBox message={error} />}
      {data && <pre>{JSON.stringify(data, null, 2)}</pre>}
      <button onClick={reload}>Refresh</button>
    </div>
  )
}

// ---- Evidence browser -------------------------------------------------
export function EvidenceBrowser() {
  const [taskId, setTaskId] = useState('')
  const { data, error, loading, reload } = useAsync(
    () => (taskId ? api.taskEvidence(taskId) : Promise.resolve(null)), [taskId])
  return (
    <div>
      <div className="glass" style={{ display: 'flex', gap: 8 }}>
        <input placeholder="task id" value={taskId} onChange={(e) => setTaskId(e.target.value)} />
        <button onClick={reload} disabled={!taskId}>Load</button>
      </div>
      <div className="glass" style={{ marginBottom: 0 }}>
        {loading && <Loading />}
        {error && <ErrorBox message={error} />}
        {data && <EvidenceView evidence={data.evidence} />}
      </div>
    </div>
  )
}

// ---- AI provider status -----------------------------------------------
export function Providers() {
  const { data, error, loading } = useAsync(() => api.providers())
  return (
    <div className="glass" style={{ marginBottom: 0 }}>
      <p>Never renders a credential value - only status/model names.</p>
      {loading && <Loading />}
      {error && <ErrorBox message={error} />}
      {data && <pre style={{ margin: 0 }}>{JSON.stringify(data, null, 2)}</pre>}
    </div>
  )
}
