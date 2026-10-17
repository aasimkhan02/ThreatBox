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
    : (rawJob.submitted || 'Just now')

  return {
    jobId: rawJob.id || rawJob.job_id || 'N/A',
    fileName: rawJob.filename || rawJob.fileName || 'sample.exe',
    status: verdict,
    score: score,
    scoreSeverity: threatScoreObj.severity || verdict,
    reasons: reasons,
    sha256: rawJob.sha256 || res?.sample?.sha256 || 'N/A',
    fileType: (rawJob.filename || rawJob.fileName || '').toLowerCase().endsWith('.dll') ? 'DLL (Dynamic Link)' : 'PE32+ (Executable)',
    fileSize: rawJob.file_size ? `${(rawJob.file_size / 1024).toFixed(1)} KB` : '412 KB',
    analysisTime: '15s - 2m',
    submitted: submittedFormatted,
    environment: 'Windows Sandbox',
    hasRealData: Boolean(res),

    // Telemetry Collections
    processes: processes,
    processCount: processCount || (processes.length ? processes.length : 1),
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
