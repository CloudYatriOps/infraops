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

// ---- In-product documentation (product spec Part 16) -------------------
// Plain <details>/<summary> - no JS state, no dumping the full
// ARCHITECTURE.md into the UI. Placed near the screens each question is
// actually relevant to, not as one giant help page.
const FAQ: Record<string, { q: string; a: string }[]> = {
  projects: [
    { q: 'What does AEP do?', a: 'Detects what a repository actually is, then runs only the security/infrastructure checks that apply to it - read-only, no external service required.' },
    { q: 'Does AEP modify my repository?', a: 'No. A scan only reads files. Remediation is always a separate, explicit action - AEP never changes, commits, or deploys your code as a side effect of scanning it.' },
    { q: 'Can AEP delete my source code?', a: 'No. "Delete Project" only removes AEP\u2019s own record of the project - it never touches files on disk, your Git history, or anything outside AEP\u2019s own database.' },
  ],
  scan: [
    { q: 'How does a project scan work?', a: 'AEP inspects the repository for evidence (file types, manifests, IaC files, CI config), then runs each applicable analyzer once and records the result.' },
    { q: 'What happens during a scan?', a: 'Only reading: detecting capabilities, then running the secret/SAST/dependency/IaC/container analyzers that apply. Nothing is installed, written, or executed in your repository.' },
    { q: 'What does RERUN do?', a: 'Runs the exact same scan again as a brand-new, separately-recorded run. Your previous scan and its findings are kept, never overwritten - the Timeline and history always show every run.' },
  ],
  findings: [
    { q: 'What does PASS mean?', a: 'The check applies to this repository, it ran, and found nothing.' },
    { q: 'What does SKIPPED mean?', a: 'The check does not apply here at all - e.g. no Terraform files, so IaC has nothing to check. Nothing is wrong.' },
    { q: 'What does BLOCKED mean?', a: 'The check applies, but something outside AEP (registry access, credentials) prevents it from running right now.' },
  ],
  report: [
    { q: 'What does RERUN do?', a: 'Creates a new scan record and compares it against the previous one, so you can see what\u2019s new, unchanged, or resolved.' },
  ],
}

function HelpNote({ topic }: { topic: keyof typeof FAQ }) {
  return (
    <details style={{ marginTop: 10 }}>
      <summary style={{ cursor: 'pointer', color: 'var(--text-dim)', fontSize: 12.5 }}>Help</summary>
      <div style={{ marginTop: 8, display: 'grid', gap: 8 }}>
        {FAQ[topic].map((item) => (
          <div key={item.q}>
            <div style={{ color: 'var(--text)', fontWeight: 600, fontSize: 12.5 }}>{item.q}</div>
            <div style={{ color: 'var(--text-dim)', fontSize: 12.5 }}>{item.a}</div>
          </div>
        ))}
      </div>
    </details>
  )
}

function downloadBlob(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = filename
  document.body.appendChild(a); a.click(); document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

const ANALYSIS_STATE_LABEL: Record<string, string> = {
  NEVER_SCANNED: 'not configured', QUEUED: 'blocked', SCANNING: 'blocked',
  COMPLETED: 'healthy', COMPLETED_WITH_FINDINGS: 'medium', FAILED: 'fail', CANCELLED: 'not configured',
}

// ---- Project Detail (product spec Part 7): scan lifecycle, findings, ---
// report, timeline - all reading/writing through the SAME `aep scan`
// engine and persisted records the CLI produces, never a second UI-only
// scanner or a client-side-only view of unsaved data.
function ProjectDetail({ project, onBack, onDeleted }: { project: any; onBack: () => void; onDeleted: () => void }) {
  const [proj, setProj] = useState(project)
  const [scansData, setScansData] = useState<any>(null)
  const [selectedScan, setSelectedScan] = useState<any>(null)
  const [selectedFinding, setSelectedFinding] = useState<any>(null)
  const [scanning, setScanning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [confirmDelete, setConfirmDelete] = useState(false)

  const reloadAll = async (selectId?: string) => {
    const [freshProj, scans] = await Promise.all([api.getProject(proj.id), api.listScans(proj.id)])
    setProj(freshProj)
    setScansData(scans)
    const targetId = selectId ?? scans.scans[0]?.scan_id
    setSelectedScan(targetId ? await api.getScan(proj.id, targetId) : null)
  }

  useEffect(() => { reloadAll() }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const scanNow = async () => {
    setScanning(true); setError(null)
    try {
      const result = await api.scanNow(proj.id)
      await reloadAll(result.task_id)
    } catch (e: any) {
      setError(e.message)
    } finally {
      setScanning(false)
    }
  }

  const doDelete = async () => {
    await api.deleteProject(proj.id)
    onDeleted()
  }

  const downloadReport = async (format: 'json' | 'markdown') => {
    if (format === 'json') {
      const report = await api.getReport(proj.id)
      downloadBlob(JSON.stringify(report, null, 2), `${proj.name}-report.json`, 'application/json')
    } else {
      const md = await api.getReportMarkdown(proj.id)
      downloadBlob(md, `${proj.name}-report.md`, 'text/markdown')
    }
  }

  const hasScans = (scansData?.scans?.length ?? 0) > 0
  const report = selectedScan?.report
  const analyzers = report?.analyzers ?? []
  const findings = analyzers.flatMap((a: any) => (a.findings || []).map((f: any) => ({ ...f, analyzer: a.analyzer })))
  const skipped = analyzers.filter((a: any) => a.status === 'SKIPPED')
  const blocked = analyzers.filter((a: any) => a.status === 'BLOCKED' || a.status === 'UNAVAILABLE')
  const analyzed = analyzers.filter((a: any) => a.status === 'PASS' || a.status === 'FAIL')

  return (
    <div>
      <button onClick={onBack} style={{ marginBottom: 12 }}>&larr; Back to Projects</button>

      {/* TOP */}
      <div className="glass">
        <h3 style={{ marginBottom: 6 }}>{proj.name}</h3>
        <p style={{ marginBottom: 4 }}><strong style={{ color: 'var(--text)' }}>Repository:</strong> {proj.repo_path}</p>
        <p style={{ marginBottom: 4 }}>
          <strong style={{ color: 'var(--text)' }}>Detected capabilities:</strong>{' '}
          {proj.detected_capabilities?.length ? proj.detected_capabilities.join(', ') : '(none detected)'}
        </p>
        <p style={{ marginBottom: 4 }}>
          <strong style={{ color: 'var(--text)' }}>Last scan:</strong>{' '}
          {proj.last_scan_at ? new Date(proj.last_scan_at).toLocaleString() : 'Never'}
        </p>
        <p style={{ marginBottom: 12 }}>
          <strong style={{ color: 'var(--text)' }}>Analysis:</strong>{' '}
          <StatusBadge value={ANALYSIS_STATE_LABEL[proj.analysis_state] ?? proj.analysis_state} />{' '}
          <span style={{ color: 'var(--text-dim)' }}>{proj.analysis_state}</span>
        </p>
        {error && <ErrorBox message={error} />}
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={scanNow} disabled={scanning}>
            {scanning ? 'Scanning...' : hasScans ? 'Rerun Scan' : 'Scan Now'}
          </button>
          <button onClick={() => setConfirmDelete(true)}>Delete Project</button>
        </div>
        {confirmDelete && (
          <div className="badge" style={{ marginTop: 12, background: 'var(--fail-dim)', color: 'var(--fail)',
                                           padding: '10px 14px', display: 'block' }}>
            <p style={{ marginBottom: 8 }}>Remove project from AEP? This does NOT delete files from disk,
              your Git repository, or scan history.</p>
            <div style={{ display: 'flex', gap: 8 }}>
              <button onClick={doDelete}>Confirm delete</button>
              <button onClick={() => setConfirmDelete(false)}>Cancel</button>
            </div>
          </div>
        )}
        <HelpNote topic="projects" />
      </div>

      {!hasScans && (
        <div className="glass">
          <h4>NOT YET SCANNED</h4>
          <p>Repository detected: {proj.detected_capabilities?.length ? proj.detected_capabilities.join(', ') : '(nothing detected yet)'}</p>
          <p style={{ marginBottom: 0 }}>Click <strong style={{ color: 'var(--text)' }}>Scan Now</strong> above to run AEP's read-only analysis.</p>
          <HelpNote topic="scan" />
        </div>
      )}

      {hasScans && report && (
        <>
          {/* ANALYSIS SUMMARY */}
          <div className="glass">
            <h4>Analysis summary</h4>
            <p><strong style={{ color: 'var(--text)' }}>Detected:</strong> {report.project.capabilities.join(', ') || '(none)'}</p>
            <p><strong style={{ color: 'var(--text)' }}>Analyzed:</strong> {analyzed.map((a: any) => a.analyzer).join(', ') || '(none)'}</p>
            <p><strong style={{ color: 'var(--text)' }}>Skipped:</strong> {skipped.map((a: any) => a.analyzer).join(', ') || '(none)'}</p>
            {blocked.length > 0 && (
              <p style={{ marginBottom: 0 }}><strong style={{ color: 'var(--text)' }}>Blocked:</strong> {blocked.map((a: any) => a.analyzer).join(', ')}</p>
            )}
          </div>

          {/* SECURITY POSTURE */}
          <div className="glass">
            <h4>Security posture</h4>
            <Table
              columns={['Check', 'Status', 'Reason']}
              rows={analyzers.map((a: any) => [a.analyzer, <StatusBadge value={a.status} />, a.reason])}
            />
            <HelpNote topic="findings" />
          </div>

          {/* FINDINGS */}
          <div className="glass">
            <h4>Findings ({report.total_findings})</h4>
            {findings.length === 0 && <p style={{ marginBottom: 0 }}>No findings.</p>}
            {findings.length > 0 && (
              <Table
                columns={['Severity', 'Category', 'File', 'Line', 'Description', '']}
                rows={findings.map((f: any, i: number) => [
                  <StatusBadge value={f.severity} />, f.analyzer, f.file, f.line, f.description,
                  <button onClick={() => setSelectedFinding(f)}>Details</button>,
                ])}
              />
            )}
          </div>
          {selectedFinding && (
            <div className="glass">
              <h4>Finding detail</h4>
              <p><strong style={{ color: 'var(--text)' }}>Location:</strong> {selectedFinding.file}:{selectedFinding.line}</p>
              <p><strong style={{ color: 'var(--text)' }}>Severity:</strong> <StatusBadge value={selectedFinding.severity} /></p>
              <p><strong style={{ color: 'var(--text)' }}>Rule:</strong> {selectedFinding.rule}</p>
              <p><strong style={{ color: 'var(--text)' }}>Explanation:</strong> {selectedFinding.description}</p>
              <p style={{ marginBottom: 0 }}><strong style={{ color: 'var(--text)' }}>Recommended next action:</strong>{' '}
                Review and remediate manually - AEP never applies a fix automatically.</p>
              <button onClick={() => setSelectedFinding(null)} style={{ marginTop: 10 }}>Close</button>
            </div>
          )}

          {/* REPORT */}
          <div className="glass">
            <h4>Report</h4>
            <p>Security readiness: <StatusBadge value={report.security_readiness} /> <span style={{ color: 'var(--text-faint)' }}>(read-only - AEP made no changes)</span></p>
            <div style={{ display: 'flex', gap: 8 }}>
              <button onClick={() => downloadReport('json')}>Download report (JSON)</button>
              <button onClick={() => downloadReport('markdown')}>Download report (Markdown)</button>
            </div>
            <HelpNote topic="report" />
          </div>

          {/* TIMELINE */}
          <div className="glass" style={{ marginBottom: 0 }}>
            <h4>Timeline</h4>
            <Table
              columns={['Time', 'Event']}
              rows={(selectedScan.timeline || []).map((e: any) => [
                new Date(e.timestamp).toLocaleTimeString(), e.action,
              ])}
            />
            {scansData.scans.length > 1 && (
              <div style={{ marginTop: 16 }}>
                <h4>Scan history</h4>
                <Table
                  columns={['Scan', 'Status', 'Findings', 'Started', '']}
                  rows={scansData.scans.map((s: any, i: number) => [
                    `#${scansData.scans.length - i}`, <StatusBadge value={s.analysis_state} />, s.finding_count,
                    new Date(s.started_at).toLocaleString(),
                    <button onClick={async () => setSelectedScan(await api.getScan(proj.id, s.scan_id))}>
                      {s.scan_id === selectedScan.scan_id ? 'Viewing' : 'View'}
                    </button>,
                  ])}
                />
                {scansData.comparison && (
                  <p style={{ marginTop: 10, marginBottom: 0 }}>
                    Vs. previous scan: {scansData.comparison.new_findings.length} new,{' '}
                    {scansData.comparison.resolved_findings.length} resolved,{' '}
                    {scansData.comparison.unchanged.length} unchanged.
                  </p>
                )}
              </div>
            )}
          </div>
        </>
      )}

      <ProjectIntel projectId={proj.id} />
    </div>
  )
}

// ---- Projects -----------------------------------------------------------
export function Projects(_props: { onOpen: (id: string) => void }) {
  const { data, error, loading, reload } = useAsync(() => api.listProjects())
  const [name, setName] = useState('')
  const [repoPath, setRepoPath] = useState('')
  const [creating, setCreating] = useState(false)
  const [openProject, setOpenProject] = useState<any>(null)

  const create = async () => {
    setCreating(true)
    try {
      const created = await api.createProject({ name, repo_path: repoPath })
      setName('')
      setRepoPath('')
      reload()
      setOpenProject(created)
    } catch (e: any) {
      alert(e.message)
    } finally {
      setCreating(false)
    }
  }

  if (openProject) {
    return (
      <ProjectDetail
        project={openProject}
        onBack={() => { setOpenProject(null); reload() }}
        onDeleted={() => { setOpenProject(null); reload() }}
      />
    )
  }

  return (
    <div>
      <div className="glass">
        <h4>Add / analyze an existing project</h4>
        <p>Enter the local path to a repository already on this machine.
          AEP auto-detects what it is and runs only the checks that
          apply - it never modifies the repository.</p>
        <div style={{ display: 'flex', gap: 8 }}>
          <input placeholder="name" value={name} onChange={(e) => setName(e.target.value)} />
          <input placeholder="local repository path, e.g. C:\path\to\project" value={repoPath}
                 onChange={(e) => setRepoPath(e.target.value)} style={{ flex: 1 }} />
          <button onClick={create} disabled={creating || !name || !repoPath}>Create</button>
        </div>
        <HelpNote topic="projects" />
      </div>
      <div className="glass" style={{ marginBottom: 0 }}>
        {loading && <Loading />}
        {error && <ErrorBox message={error} />}
        {data && (
          <Table
            columns={['Name', 'Repo Path', 'Analysis', '']}
            rows={data.map((p: any) => [
              p.name, p.repo_path,
              <StatusBadge value={ANALYSIS_STATE_LABEL[p.analysis_state] ?? p.analysis_state} />,
              <button onClick={() => setOpenProject(p)}>Open</button>,
            ])}
          />
        )}
      </div>
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

// ---- Local core / AI provider status -----------------------------------
// AEP's real architecture has exactly one AI integration point - a single
// configurable OmniRoute gateway (AI_BASE_URL/AI_CREDENTIAL/AI_PROVIDER) -
// not separate Claude/Gemini/OpenAI adapters, so this screen is honest
// about that rather than inventing three independent "configured" slots
// that don't exist in the code.
export function Providers() {
  const { data, error, loading } = useAsync(() => api.providers())
  const omni = data?.omniroute
  const aiBadgeValue = omni?.status === 'healthy' ? 'healthy'
    : omni?.status === 'unreachable' ? 'blocked'
    : 'not configured'

  return (
    <div>
      <div className="glass">
        <p style={{ marginBottom: 0 }}>
          AEP works without an AI provider. Local engineering - project
          detection, security/infrastructure scanning, engineering
          intelligence, and evidence/memory - never depends on one. AI
          providers are optional, used only for AI-assisted reasoning and
          routing. Never renders a credential value - only status/model names.
        </p>
      </div>

      <div className="glass" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <div>
          <h4>Local Core</h4>
          <StatusBadge value="ready" />
        </div>
        <div>
          <h4>AI Provider</h4>
          {loading && <Loading />}
          {error && <ErrorBox message={error} />}
          {data && (
            <div>
              <p style={{ marginBottom: 4 }}><StatusBadge value={aiBadgeValue} /></p>
              <p style={{ marginBottom: 0, color: 'var(--text-dim)' }}>{omni?.detail}</p>
            </div>
          )}
        </div>
      </div>

      <div className="glass">
        <h4>Optional AI providers</h4>
        <p>AEP integrates AI through a single configurable gateway rather
          than separate per-vendor credentials - set <code>AI_BASE_URL</code>,{' '}
          <code>AI_CREDENTIAL</code>, and optionally <code>AI_PROVIDER</code>{' '}
          (a display label, e.g. <code>anthropic</code>/<code>openai</code>/
          <code>gemini</code>) as environment variables before starting{' '}
          <code>aep</code> to route to Claude, Gemini, OpenAI, or any
          OmniRoute-compatible endpoint. This UI provides no credential
          input field on purpose - configuration happens via environment,
          never through a form that could store a secret in the browser.</p>
        <Table
          columns={['Configured via', 'Status']}
          rows={[['OmniRoute', <StatusBadge value={aiBadgeValue} />]]}
        />
      </div>

      {data && (
        <div className="glass" style={{ marginBottom: 0 }}>
          <h4>Registered models</h4>
          <pre style={{ margin: 0 }}>{JSON.stringify(data.providers, null, 2)}</pre>
        </div>
      )}
    </div>
  )
}
