/**
 * ThreatBox Demo Engine
 * 
 * Manages client-side simulated detonation lifecycle, progress subscriptions,
 * scenario assignment, and lightweight localStorage persistence for demo mode.
 * 
 * TRANSPARENCY GUARANTEE:
 * - No file contents or bytes are ever read, transmitted, or executed.
 * - Only safe display metadata (file.name, file.size) is read for presentation.
 * - Telemetry is mapped from curated illustrative profiles.
 */

import { DEMO_PROFILES, getInitialDemoJobs, getDemoJobDetailsById } from './demoData'

const STORAGE_KEY_JOBS = 'threatbox_demo_jobs_v1'
const STORAGE_KEY_CUSTOM_REPORTS = 'threatbox_demo_reports_v1'
const MAX_PERSISTED_JOBS = 20

// In-memory active simulations: Map<jobId, { timerIds: number[], listeners: Set<Function>, jobData: Object }>
const activeSimulations = new Map()

/**
 * Safely loads demo jobs from localStorage combined with bundled initial profiles.
 */
export function getStoredDemoJobs() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY_JOBS)
    if (!raw) {
      return getInitialDemoJobs()
    }
    const parsed = JSON.parse(raw)
    if (!Array.isArray(parsed)) {
      return getInitialDemoJobs()
    }
    // Self-healing: if an interrupted job was saved as 'running' or 'pending', normalize to 'completed'
    const normalized = parsed.map((j) => {
      if (j.status === 'running' || j.status === 'pending') {
        return { ...j, status: 'completed' }
      }
      return j
    })
    return normalized
  } catch (err) {
    console.warn('[DemoEngine] Error reading demo jobs from localStorage, resetting:', err)
    return getInitialDemoJobs()
  }
}

/**
 * Persists a capped list of demo jobs into localStorage.
 */
function persistDemoJobs(jobs) {
  try {
    const trimmed = jobs.slice(0, MAX_PERSISTED_JOBS)
    localStorage.setItem(STORAGE_KEY_JOBS, JSON.stringify(trimmed))
  } catch (err) {
    console.warn('[DemoEngine] Failed to persist demo jobs to localStorage:', err)
  }
}

/**
 * Safely loads custom generated demo reports by jobId.
 */
function getStoredReport(jobId) {
  try {
    const raw = localStorage.getItem(STORAGE_KEY_CUSTOM_REPORTS)
    if (!raw) return null
    const map = JSON.parse(raw)
    return map?.[jobId] || null
  } catch {
    return null
  }
}

/**
 * Persists a generated demo report.
 */
function persistCustomReport(jobId, report) {
  try {
    const raw = localStorage.getItem(STORAGE_KEY_CUSTOM_REPORTS)
    const map = raw ? JSON.parse(raw) : {}
    map[jobId] = report
    // Keep max reports in check
    const keys = Object.keys(map)
    if (keys.length > MAX_PERSISTED_JOBS) {
      delete map[keys[0]]
    }
    localStorage.setItem(STORAGE_KEY_CUSTOM_REPORTS, JSON.stringify(map))
  } catch (err) {
    console.warn('[DemoEngine] Failed to persist custom report:', err)
  }
}

/**
 * Clears demo history and resets back to standard bundled fixtures.
 */
export function resetDemoHistory() {
  try {
    localStorage.removeItem(STORAGE_KEY_JOBS)
    localStorage.removeItem(STORAGE_KEY_CUSTOM_REPORTS)
    // Clear any active simulations
    activeSimulations.forEach((sim) => {
      sim.timerIds.forEach(clearTimeout)
    })
    activeSimulations.clear()
    return getInitialDemoJobs()
  } catch (err) {
    console.warn('[DemoEngine] Failed to reset demo history:', err)
    return getInitialDemoJobs()
  }
}

/**
 * Generates an illustrative scenario report mapped to the user's uploaded filename & size.
 */
function buildSimulatedReport(jobId, fileName, fileSize, options = {}) {
  // Select baseline template (default to ransomware profile for dramatic showcase, or preset selection)
  const template = DEMO_PROFILES[0]
  const report = JSON.parse(JSON.stringify(template))

  report.id = jobId
  report.filename = fileName || 'Uploaded_Sample.exe'
  report.file_size = typeof fileSize === 'number' && fileSize > 0 ? fileSize : 524288
  report.created_at = new Date().toISOString()
  report.started_at = new Date(Date.now() + 1500).toISOString()
  report.completed_at = new Date(Date.now() + 7500).toISOString()
  report.status = 'completed'

  // Update sample metadata with explicit illustrative tags
  if (report.analysis_result?.sample) {
    report.analysis_result.sample.file_size = report.file_size
    report.analysis_result.sample.sha256 = 'simulated_demo_' + Math.random().toString(16).substring(2, 14) + '00000000'
  }
  report.sha256 = report.analysis_result?.sample?.sha256 || 'simulated_demo_hash'

  report.provenance = {
    type: 'illustrative_synthetic',
    scenario: 'Simulated Detonation Showcase',
    description: `Client-side simulated analysis of ${fileName}. Display metadata applied to illustrative behavioral template. No file was sent to a server or executed.`
  }

  // Update top root process name to match uploaded file
  if (report.analysis_result?.processes?.[0]) {
    report.analysis_result.processes[0].Name = fileName
    report.analysis_result.processes[0].ImageFileName = `C:\\Users\\WDAGUtilityAccount\\Desktop\\${fileName}`
    report.analysis_result.processes[0].CommandLine = `"C:\\Users\\WDAGUtilityAccount\\Desktop\\${fileName}"`
  }

  return report
}

/**
 * Simulates sample upload in Demo Mode.
 * Returns { job_id, status: 'pending' } immediately, then progresses asynchronously.
 */
export async function demoUploadSample(file, options = {}) {
  const jobId = `demo-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`
  const fileName = file?.name || 'unknown_sample.exe'
  const fileSize = file?.size || 0

  // Initial Job record
  const newJob = {
    id: jobId,
    filename: fileName,
    status: 'pending',
    created_at: new Date().toISOString(),
    started_at: null,
    completed_at: null,
    score: null,
    sha256: 'calculating...',
    file_size: fileSize,
    provenance: {
      type: 'illustrative_synthetic',
      scenario: 'Live Detonation Simulation',
      description: 'Simulated client-side execution in progress.'
    }
  }

  // Store in persistent jobs list
  const currentJobs = getStoredDemoJobs()
  persistDemoJobs([newJob, ...currentJobs])

  // Build the final completed report
  const finalReport = buildSimulatedReport(jobId, fileName, fileSize, options)

  // Register in-memory simulation tracking
  const listeners = new Set()
  const timerIds = []

  const broadcastEvent = (stage, statusText, jobStatus = 'running') => {
    // Update stored job status
    const list = getStoredDemoJobs()
    const target = list.find((j) => j.id === jobId)
    if (target) {
      target.status = jobStatus
      if (jobStatus === 'running' && !target.started_at) {
        target.started_at = new Date().toISOString()
      }
      if (jobStatus === 'completed') {
        target.completed_at = new Date().toISOString()
        target.score = finalReport.score
        target.sha256 = finalReport.sha256
      }
      persistDemoJobs(list)
    }

    const payload = {
      type: 'status_update',
      jobId,
      stage,
      status: jobStatus,
      statusText,
      timestamp: new Date().toISOString()
    }

    listeners.forEach((fn) => {
      try {
        fn(payload)
      } catch (err) {
        console.warn('[DemoEngine] Listener error:', err)
      }
    })
  }

  // Schedule simulated lifecycle:
  // 0s: QUEUED
  timerIds.push(
    setTimeout(() => {
      broadcastEvent('QUEUED', 'Sample submitted to analysis queue', 'pending')
    }, 100)
  )

  // 1.5s: PREPARING_SANDBOX
  timerIds.push(
    setTimeout(() => {
      broadcastEvent('PREPARING_SANDBOX', 'Provisioning isolated Windows Sandbox VM...', 'running')
    }, 1500)
  )

  // 3.5s: EXECUTING
  timerIds.push(
    setTimeout(() => {
      broadcastEvent('EXECUTING', 'Detonating executable and capturing kernel ETW telemetry...', 'running')
    }, 3500)
  )

  // 6.0s: ANALYZING
  timerIds.push(
    setTimeout(() => {
      broadcastEvent('ANALYZING', 'Analyzing process hierarchy and correlating MITRE techniques...', 'running')
    }, 6000)
  )

  // 7.5s: COMPLETED
  timerIds.push(
    setTimeout(() => {
      // Persist full report
      persistCustomReport(jobId, finalReport)
      broadcastEvent('COMPLETED', 'Analysis complete! Forensic report ready.', 'completed')
      activeSimulations.delete(jobId)
    }, 7500)
  )

  activeSimulations.set(jobId, { timerIds, listeners, finalReport })

  return {
    job_id: jobId,
    status: 'pending',
    message: 'Demo mode: simulation initialized successfully. No file was sent to a server.'
  }
}

/**
 * Retrieves the list of demo jobs (combining initial profiles and completed custom simulations).
 */
export async function demoGetJobs() {
  return getStoredDemoJobs()
}

/**
 * Retrieves full job details and analysis results in Demo Mode.
 */
export async function demoGetJobDetails(jobId) {
  if (!jobId) throw new Error('jobId is required')

  // 1. Check if active simulation is currently running
  const active = activeSimulations.get(jobId)
  if (active) {
    const list = getStoredDemoJobs()
    const found = list.find((j) => j.id === jobId)
    return {
      id: jobId,
      filename: found?.filename || 'sample.exe',
      status: found?.status || 'running',
      created_at: found?.created_at || new Date().toISOString(),
      started_at: found?.started_at || null,
      completed_at: null,
      score: null,
      sha256: found?.sha256 || 'pending',
      file_size: found?.file_size || 0,
      analysis_result: null
    }
  }

  // 2. Check bundled profiles
  const bundled = getDemoJobDetailsById(jobId)
  if (bundled) return bundled

  // 3. Check custom persisted reports
  const custom = getStoredReport(jobId)
  if (custom) return custom

  // 4. Fallback search in stored job headers
  const list = getStoredDemoJobs()
  const fallbackHeader = list.find((j) => j.id === jobId)
  if (fallbackHeader) {
    // Generate compatible placeholder report
    return buildSimulatedReport(jobId, fallbackHeader.filename, fallbackHeader.file_size)
  }

  throw new Error(`Demo job not found: ${jobId}`)
}

/**
 * Connects to the simulated WebSocket stream for a demo job.
 */
export function demoSubscribeJobStream(jobId, onEvent, onClose, onError) {
  const active = activeSimulations.get(jobId)

  const simulatedSocket = {
    readyState: 1, // OPEN
    close: () => {
      if (active) {
        active.listeners.delete(onEvent)
      }
      if (onClose) onClose()
    }
  }

  if (active && onEvent) {
    active.listeners.add(onEvent)
  } else {
    // If not active, fire an immediate complete event
    setTimeout(() => {
      if (onEvent) {
        onEvent({
          type: 'status_update',
          jobId,
          stage: 'COMPLETED',
          status: 'completed',
          statusText: 'Analysis completed.'
        })
      }
      if (onClose) onClose()
    }, 50)
  }

  return simulatedSocket
}
