// Thin fetch wrapper over the Wave 1 Flask API (src/aep/api/app.py). No
// business logic lives here - every function is a 1:1 call to one API
// route. Set VITE_API_BASE / VITE_API_KEY via ui/.env.local (see
// ui/README.md); with the API running under AEP_API_DEV_MODE=1 no key is
// needed for local development.
// `??` not `||`: an EMPTY VITE_API_BASE is meaningful - it means
// same-origin relative URLs, which is what the packaged build served by
// the Flask backend uses. Only an unset value falls back to the dev
// server's cross-origin default.
const BASE = import.meta.env.VITE_API_BASE ?? 'http://localhost:5000'
const API_KEY = import.meta.env.VITE_API_KEY || ''

async function request(path: string, options: RequestInit = {}) {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> | undefined),
  }
  if (API_KEY) headers['Authorization'] = `Bearer ${API_KEY}`
  const resp = await fetch(`${BASE}${path}`, { ...options, headers })
  const body = await resp.json().catch(() => null)
  if (!resp.ok) {
    throw new Error((body && body.error) || `${resp.status} ${resp.statusText}`)
  }
  return body
}

export const api = {
  health: () => request('/health'),
  systemStatusFast: () => request('/system/status'), // does NOT pass ?confirm=true
  systemStatusFull: () => request('/system/status?confirm=true'), // ~9-11 min
  listProjects: () => request('/projects'),
  createProject: (body: { name: string; repo_path: string }) =>
    request('/projects', { method: 'POST', body: JSON.stringify(body) }),
  getProject: (id: string) => request(`/projects/${id}`),
  getRepository: (projectId: string) => request(`/repositories/${projectId}`),
  deleteProject: (projectId: string) => request(`/projects/${projectId}`, { method: 'DELETE' }),
  // Scan lifecycle - same read-only `aep scan` engine, persisted server-side.
  scanNow: (projectId: string) => request(`/projects/${projectId}/scan`, { method: 'POST' }),
  listScans: (projectId: string) => request(`/projects/${projectId}/scans`),
  getScan: (projectId: string, scanId: string) => request(`/projects/${projectId}/scans/${scanId}`),
  getReport: (projectId: string) => request(`/projects/${projectId}/report`),
  getReportMarkdown: async (projectId: string): Promise<string> => {
    const headers: Record<string, string> = {}
    if (API_KEY) headers['Authorization'] = `Bearer ${API_KEY}`
    const resp = await fetch(`${BASE}/projects/${projectId}/report?format=markdown`, { headers })
    if (!resp.ok) throw new Error(`${resp.status} ${resp.statusText}`)
    return resp.text()
  },
  listAgents: () => request('/agents'),
  listSkills: () => request('/skills'),
  getSkill: (id: string) => request(`/skills/${id}`),
  providers: () => request('/providers'),
  findings: (projectId?: string) =>
    request(`/findings${projectId ? `?project_id=${projectId}` : ''}`),
  incidents: (projectId: string) => request(`/incidents/${projectId}`),
  deployments: (projectId: string) => request(`/deployments/${projectId}`),
  createTask: (body: { project_id: string; type: string; owner_agent?: string; payload?: object }) =>
    request('/tasks', { method: 'POST', body: JSON.stringify(body) }),
  getTask: (id: string) => request(`/tasks/${id}`),
  taskEvidence: (id: string) => request(`/tasks/${id}/evidence`),
  approvals: (projectId?: string) =>
    request(`/approvals${projectId ? `?project_id=${projectId}` : ''}`),
  approveTask: (id: string) => request(`/approvals/${id}/approve`, { method: 'POST' }),
  rejectTask: (id: string, reason?: string) =>
    request(`/approvals/${id}/reject`, { method: 'POST', body: JSON.stringify({ reason }) }),
  runtimeStatus: () => request('/runtime/status'),
  healthScore: (projectId: string) => request(`/intelligence/health-score?project_id=${projectId}`),
  costIntelligence: (projectId: string) => request(`/intelligence/cost?project_id=${projectId}`),
  remediationDecisions: (projectId: string) => request(`/intelligence/remediation-decision?project_id=${projectId}`),
}
