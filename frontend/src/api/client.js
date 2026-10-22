/**
 * ThreatBox API Client & Adapter
 * 
 * Centralized client for communicating with ThreatBox backend services or
 * delegating to the client-side Demo Engine when VITE_DEMO_MODE is active.
 * 
 * NON-NEGOTIABLE ARCHITECTURE RULES:
 * - Live Mode uses the Go REST/WebSocket server as-is.
 * - Live Mode NEVER silently falls back to demo mode on network errors.
 * - Demo Mode runs 100% in-browser with zero backend / network requests.
 * - All function signatures, parameters, and return types remain identical.
 */

import {
  demoUploadSample,
  demoGetJobs,
  demoGetJobDetails,
  demoSubscribeJobStream,
  resetDemoHistory as engineResetDemoHistory
} from '../demo/demoEngine'

export const IS_DEMO_MODE = import.meta.env.VITE_DEMO_MODE === 'true'

const API_BASE = '/api'
const WS_BASE = (typeof window !== 'undefined' && window.location.protocol === 'https:' ? 'wss://' : 'ws://') +
  (typeof window !== 'undefined' ? window.location.host : 'localhost:8080') +
  '/ws'

/**
 * Upload an executable file for detonation and analysis.
 * @param {File} file - The executable file to analyze
 * @param {Object} options - Detonation options (networkMonitoring, registryMonitoring, etc.)
 * @returns {Promise<{ job_id: string, status: string, message?: string, is_duplicate?: boolean }>}
 */
export async function uploadSample(file, options = {}) {
  if (IS_DEMO_MODE) {
    return demoUploadSample(file, options)
  }

  const formData = new FormData()
  formData.append('file', file)

  if (options && Object.keys(options).length > 0) {
    formData.append('options', JSON.stringify(options))
  }

  const response = await fetch(`${API_BASE}/samples`, {
    method: 'POST',
    body: formData,
  })

  if (!response.ok) {
    const errorText = await response.text()
    throw new Error(errorText || `Upload failed with HTTP status ${response.status}`)
  }

  return response.json()
}

/**
 * Fetch a list of multiple jobs for history and dashboard lists.
 * @returns {Promise<Array<{ id: string, filename: string, status: string, created_at: string, score?: number }>>}
 */
export async function getJobs() {
  if (IS_DEMO_MODE) {
    return demoGetJobs()
  }

  const response = await fetch(`${API_BASE}/jobs`, {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
    },
  })

  if (!response.ok) {
    const errorText = await response.text()
    throw new Error(errorText || `Failed to fetch jobs (HTTP ${response.status})`)
  }

  return response.json()
}

/**
 * Fetch detailed analysis results and lifecycle status for a specific job.
 * @param {string} jobId
 * @returns {Promise<{ id: string, filename: string, status: string, created_at: string, score?: number, analysis_result?: object }>}
 */
export async function getJobDetails(jobId) {
  if (!jobId) {
    throw new Error('jobId is required')
  }

  if (IS_DEMO_MODE) {
    return demoGetJobDetails(jobId)
  }

  const response = await fetch(`${API_BASE}/jobs/${encodeURIComponent(jobId)}`, {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
    },
  })

  if (!response.ok) {
    const errorText = await response.text()
    throw new Error(errorText || `Failed to fetch job details for ${jobId} (HTTP ${response.status})`)
  }

  return response.json()
}

/**
 * Update a job's status manually (e.g. aborting or patching state).
 * @param {string} jobId
 * @param {string} status
 */
export async function updateJobStatus(jobId, status) {
  if (IS_DEMO_MODE) {
    return { id: jobId, status }
  }

  const response = await fetch(`${API_BASE}/jobs/${encodeURIComponent(jobId)}`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ status }),
  })

  if (!response.ok) {
    const errorText = await response.text()
    throw new Error(errorText || `Failed to update job status (HTTP ${response.status})`)
  }

  return response.json()
}

/**
 * Connect to live WebSocket telemetry stream during active execution.
 * @param {string} jobId
 * @param {(event: object) => void} onEvent
 * @param {() => void} [onClose]
 * @param {(err: Event) => void} [onError]
 * @returns {WebSocket|{ readyState: number, close: Function }}
 */
export function subscribeJobStream(jobId, onEvent, onClose, onError) {
  if (IS_DEMO_MODE) {
    return demoSubscribeJobStream(jobId, onEvent, onClose, onError)
  }

  const socket = new WebSocket(`${WS_BASE}/analysis/${encodeURIComponent(jobId)}`)

  socket.onmessage = (msg) => {
    try {
      const data = JSON.parse(msg.data)
      if (onEvent) onEvent(data)
    } catch {
      if (onEvent) onEvent(msg.data)
    }
  }

  if (onClose) socket.onclose = onClose
  if (onError) socket.onerror = onError

  return socket
}

/**
 * Reset demo history (only effective in Demo Mode).
 */
export function resetDemoHistory() {
  if (IS_DEMO_MODE) {
    return engineResetDemoHistory()
  }
}
