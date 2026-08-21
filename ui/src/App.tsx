import { useState } from 'react'
import type React from 'react'
import {
  Dashboard, Projects, TaskExecution, TaskDetail, Findings, Incidents,
  Approvals, RuntimeStatus, EvidenceBrowser, Providers,
} from './pages'

// Deliberately no router library - a handful of tab-switched views with
// plain useState is all this small a UI needs (ponytail: smallest correct
// change). Every page below is a thin view over one API response; none of
// them contain skill resolution, policy evaluation, or routing logic.
const TABS = [
  'Dashboard', 'Projects', 'Task Execution', 'Task Detail', 'Findings',
  'Incidents', 'Approvals', 'Runtime', 'Evidence', 'Providers',
] as const
type Tab = typeof TABS[number]

// One stroke-SVG icon per nav item, 17x17, consistent 1.8 stroke weight -
// matches the design concept exactly (see the published canvas). Kept
// inline (not a shared icon library dependency) since it's ~10 small paths.
const ICONS: Record<Tab, React.ReactNode> = {
  'Dashboard': <path d="M3 3h7v9H3zM14 3h7v5h-7zM14 12h7v9h-7zM3 16h7v5H3z" />,
  'Projects': <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />,
  'Task Execution': <><rect x="3" y="4" width="18" height="16" rx="2" /><path d="m8 9 3 3-3 3M13 15h4" /></>,
  'Task Detail': <><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M7 9h6M7 13h10M7 17h7" /></>,
  'Findings': <><path d="M12 3 4 6v6c0 4.5 3 7.7 8 9 5-1.3 8-4.5 8-9V6z" /><path d="m9.5 12 2 2 3.5-4" /></>,
  'Incidents': <><path d="M12 3 2 20h20z" /><path d="M12 10v4M12 17h.01" /></>,
  'Approvals': <><path d="m9 12 2 2 4-4" /><circle cx="12" cy="12" r="9" /></>,
  'Runtime': <path d="M3 12h4l2-7 4 14 2-7h6" />,
  'Evidence': <><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" /><path d="M14 3v5h5m-9 4 2 2 3.5-4" /></>,
  'Providers': <><rect x="7" y="7" width="10" height="10" rx="1.5" /><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.5 4.5l2 2M17.5 17.5l2 2M4.5 19.5l2-2M17.5 6.5l2-2" /></>,
}

function App() {
  const [tab, setTab] = useState<Tab>('Dashboard')
  const [taskId, setTaskId] = useState('')

  const openTask = (id: string) => { setTaskId(id); setTab('Task Detail') }

  return (
    <div className="aep-shell">
      <div className="aep-sidebar">
        <div className="aep-brand">
          <div className="aep-brand-mark">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#0b0d12" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 2 3 7v10l9 5 9-5V7z" /><path d="M12 12 3 7m9 5 9-5m-9 5v10" />
            </svg>
          </div>
          <div>
            <div className="aep-brand-name">AEP</div>
            <div className="aep-brand-sub">Engineering Platform</div>
          </div>
        </div>

        <nav style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          {TABS.map((t) => (
            <button key={t} className={`aep-navlink${t === tab ? ' active' : ''}`} onClick={() => setTab(t)}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                {ICONS[t]}
              </svg>
              {t}
            </button>
          ))}
        </nav>
      </div>

      <div className="aep-main">
        <div className="aep-topbar">
          <h2>{tab}</h2>
        </div>
        <div className="aep-content">
          {tab === 'Dashboard' && <Dashboard />}
          {tab === 'Projects' && <Projects onOpen={() => { setTab('Incidents') }} />}
          {tab === 'Task Execution' && <TaskExecution onCreated={openTask} />}
          {tab === 'Task Detail' && (
            <div>
              <input placeholder="task id" value={taskId} onChange={(e) => setTaskId(e.target.value)} />
              {taskId && <div style={{ marginTop: 16 }}><TaskDetail taskId={taskId} /></div>}
            </div>
          )}
          {tab === 'Findings' && <Findings />}
          {tab === 'Incidents' && <Incidents />}
          {tab === 'Approvals' && <Approvals />}
          {tab === 'Runtime' && <RuntimeStatus />}
          {tab === 'Evidence' && <EvidenceBrowser />}
          {tab === 'Providers' && <Providers />}
        </div>
      </div>
    </div>
  )
}

export default App
