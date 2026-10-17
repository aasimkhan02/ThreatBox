/**
 * ThreatBox API Client
 * Centralized client for communicating with the ThreatBox backend services.
 */

const API_BASE = '/api'
const WS_BASE = (window.location.protocol === 'https:' ? 'wss://' : 'ws://') + window.location.host + '/ws'

/**
 * Upload an executable file for detonation and analysis.
 * @param {File} file - The executable file to analyze
 * @param {Object} options - Detonation options (networkMonitoring, registryMonitoring, etc.)
 * @returns {Promise<{ job_id: string, status: string, message?: string, is_duplicate?: boolean }>}
 */
export async function uploadSample(file, options = {}) {
  const formData = new FormData()
  formData.append('file', file)

  // Append any analysis options if needed
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
 * @returns {WebSocket}
 */
export function subscribeJobStream(jobId, onEvent, onClose, onError) {
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
