/**
 * Data Transformer & Formatter for ThreatBox Forensic Dashboard
 * Normalizes backend JobDetailsResponse & result_data into clean, predictable UI structures.
 */

export function transformAnalysisData(rawJob, fallbackData = {}) {
  if (!rawJob) return fallbackData

  const res = rawJob.analysis_result || rawJob.rawDetails?.analysis_result || null
  const threatScoreObj = res?.threat_score || {}
  const score = threatScoreObj.score != null ? threatScoreObj.score : (rawJob.score != null ? rawJob.score : 0)
  
  let verdict = 'Clean'
  if (score >= 80) verdict = 'Malicious'
  else if (score >= 40) verdict = 'Suspicious'

  const reasons = Array.isArray(threatScoreObj.reasons) ? threatScoreObj.reasons : []
  const techniques = Array.isArray(res?.techniques) ? res.techniques : []
  const files = Array.isArray(res?.files) ? res.files : []
  const network = Array.isArray(res?.network) ? res.network : []
  const registry = Array.isArray(res?.registry) ? res.registry : []
  const dns = Array.isArray(res?.dns) ? res.dns : []
  const images = Array.isArray(res?.images) ? res.images : []
  const processes = res?.processes || []

  // Count processes
  let processCount = 0
  const countNodes = (node) => {
    if (!node) return
    processCount++
    if (Array.isArray(node.Children)) {
      node.Children.forEach(countNodes)
    }
  }
  if (Array.isArray(processes)) {
    processes.forEach(countNodes)
  } else if (processes && typeof processes === 'object') {
    Object.values(processes).forEach(countNodes)
  }

  // Submitted date
  const submittedFormatted = rawJob.created_at
    ? new Date(rawJob.created_at).toLocaleString('en-US', {
        month: 'short',
        day: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      })
    : (rawJob.submitted || 'Not available')

  // Calculate analysis duration from actual start and completion timestamps if present
  let analysisDuration = 'Not available'
  const startedAt = rawJob.started_at || res?.started_at || rawJob.rawDetails?.started_at
  const completedAt = rawJob.completed_at || res?.completed_at || rawJob.rawDetails?.completed_at

  if (startedAt && completedAt) {
    const start = new Date(startedAt).getTime()
    const end = new Date(completedAt).getTime()
    if (!isNaN(start) && !isNaN(end) && end >= start) {
      const diffSecs = Math.round((end - start) / 1000)
      if (diffSecs < 60) {
        analysisDuration = `${diffSecs}s`
      } else {
        const mins = Math.floor(diffSecs / 60)
        const remSecs = diffSecs % 60
        analysisDuration = `${mins}m ${remSecs}s`
      }
    }
  }

  // Real SHA-256
  const sha256 = rawJob.sha256 || res?.sample?.sha256 || rawJob.rawDetails?.sha256 || 'Not available'

  // File size
  const rawSize = rawJob.file_size || res?.sample?.file_size || rawJob.rawDetails?.file_size
  const fileSize = rawSize ? formatBytes(rawSize) : 'Not available'

  // File type
  const filename = rawJob.filename || rawJob.fileName || ''
  let fileType = 'Not available'
  if (filename) {
    const lower = filename.toLowerCase()
    if (lower.endsWith('.dll')) fileType = 'Dynamic Link Library (DLL)'
    else if (lower.endsWith('.exe')) fileType = 'Executable (EXE)'
    else if (lower.endsWith('.sys')) fileType = 'System Driver (SYS)'
    else fileType = 'Binary File'
  }

  return {
    jobId: rawJob.id || rawJob.job_id || 'N/A',
    fileName: filename || 'Unknown sample',
    status: verdict,
    score: score,
    scoreSeverity: threatScoreObj.severity || verdict,
    reasons: reasons,
    sha256: sha256,
    fileType: fileType,
    fileSize: fileSize,
    analysisTime: analysisDuration,
    submitted: submittedFormatted,
    environment: 'Windows Sandbox',
    hasRealData: Boolean(res),

    // Telemetry Collections
    processes: processes,
    processCount: processCount,
    files: files,
    fileCount: files.length,
    network: network,
    networkCount: network.length,
    registry: registry,
    registryCount: registry.length,
    dns: dns,
    dnsCount: dns.length,
    images: images,
    imageCount: images.length,
    techniques: techniques,
    techniqueCount: techniques.length,

    rawJson: res ? JSON.stringify(res, null, 2) : null
  }
}

/**
 * Format bytes into human-readable strings (KB, MB, etc.)
 */
export function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
}
