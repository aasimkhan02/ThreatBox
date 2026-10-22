import React, { useState, useEffect } from 'react'
import './dashboard.css'
import Sidebar from '../layout/Sidebar'
import { getJobDetails } from '../../api/client'
import { transformAnalysisData, formatBytes } from '../../utils/formatAnalysis'

const Dashboard = ({
  sampleData,
  onNavigateHome,
  onNavigateUpload,
  onNavigateTab
}) => {
  const [activeTab, setActiveTab] = useState('Overview')
  const [searchQuery, setSearchQuery] = useState('')
  const [loadedJob, setLoadedJob] = useState(null)
  const [loading, setLoading] = useState(false)

  // If a sample with only an ID was passed, fetch the full job details
  useEffect(() => {
    if (sampleData?.id && !sampleData?.rawDetails?.analysis_result && !sampleData?.analysis_result) {
      setLoading(true)
      getJobDetails(sampleData.id)
        .then((data) => {
          setLoadedJob(data)
        })
        .catch((err) => {
          console.warn('Failed to load full job details:', err)
        })
        .finally(() => {
          setLoading(false)
        })
    }
  }, [sampleData?.id])

  // Default empty sample structure when nothing is passed
  const defaultEmptySample = {
    fileName: 'No sample selected',
    status: 'Clean',
    sha256: 'Not available',
    fileType: 'Not available',
    fileSize: 'Not available',
    analysisTime: 'Not available',
    submitted: 'Not available',
    environment: 'Windows Sandbox',
    score: 0
  }

  const sample = transformAnalysisData(loadedJob || sampleData?.rawDetails || sampleData, defaultEmptySample)

  const tabs = [
    'Overview',
    'Behavior',
    'Processes',
    'File System',
    'Network',
    'DNS',
    'Modules',
    'MITRE ATT&CK',
    'IOCs',
    'Raw Events'
  ]

  // Circular Gauge Math based on dynamic score
  const score = sample.score != null ? sample.score : 0
  const arcLength = 170
  const strokeDashoffset = arcLength - (score / 100) * arcLength

  const handleDownloadReport = () => {
    const reportData = sample.rawJson || JSON.stringify(sample, null, 2)
    const blob = new Blob([reportData], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `threatbox-report-${sample.fileName}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  // Helper to determine status badge class
  const getVerdictBadgeClass = (status) => {
    switch ((status || '').toLowerCase()) {
      case 'malicious':
        return 'badge-malicious-pill'
      case 'suspicious':
        return 'badge-suspicious-pill'
      case 'clean':
        return 'badge-clean-pill'
      default:
        return 'badge-clean-pill'
    }
  }

  // Render process nodes recursively for real process tree preview
  const renderProcessTreeNodes = (nodes, level = 0) => {
    if (!nodes || nodes.length === 0) return null

    return nodes.map((node, idx) => {
      const pid = node.PID ?? node.pid ?? 0
      const name = node.Image ? node.Image.split('\\').pop() : (node.image || node.name || 'process.exe')
      const children = node.Children || node.children || []
      const indentClass = level > 0 ? `tree-level-${Math.min(level, 4)}` : ''

      // Tag the root sample node or monitored process
      const isRoot = level === 0
      const isSuspicious = name.toLowerCase().includes('powershell') || name.toLowerCase().includes('cmd.exe') || name.toLowerCase().includes('rundll32')

      return (
        <React.Fragment key={`${pid}-${idx}-${level}`}>
          <div className={`tree-node ${indentClass}`}>
            <span className="node-caret">{children.length > 0 ? '▼' : '•'}</span>
            <span className="node-icon">{children.length > 0 ? '📁' : '📄'}</span>
            <span className="node-name">{name}</span>
            <span className="node-pid">(PID {pid})</span>
            {isRoot && sample.status === 'Malicious' && (
              <span className="node-badge-malicious">Sample Root</span>
            )}
            {!isRoot && isSuspicious && (
              <span className="node-badge-suspicious">Monitored</span>
            )}
          </div>
          {children.length > 0 && renderProcessTreeNodes(children, level + 1)}
        </React.Fragment>
      )
    })
  }

  // Flatten or array-ify processes for rendering
  const processList = Array.isArray(sample.processes)
    ? sample.processes
    : (sample.processes && typeof sample.processes === 'object' ? Object.values(sample.processes) : [])

  // Filter root processes if processes are a flat map with PPID
  let rootProcesses = []
  if (processList.length > 0) {
    const pidSet = new Set(processList.map((p) => p.PID ?? p.pid))
    const roots = processList.filter((p) => {
      const ppid = p.PPID ?? p.ppid
      return !ppid || !pidSet.has(ppid)
    })
    rootProcesses = roots.length > 0 ? roots : processList
  }

  // MITRE preview items (up to 4)
  const mitrePreview = Array.isArray(sample.techniques) ? sample.techniques.slice(0, 4) : []

  // Network preview items (up to 4)
  const networkPreview = Array.isArray(sample.network) ? sample.network.slice(0, 4) : []

  // Behavior Tab States
  const [timelineSeverityFilter, setTimelineSeverityFilter] = useState('All severities')
  const [isTimelineFilterOpen, setIsTimelineFilterOpen] = useState(false)

  // Processes Tab States
  const [processSearchQuery, setProcessSearchQuery] = useState('')
  const [processFilter, setProcessFilter] = useState('All Processes')
  const [isProcessFilterOpen, setIsProcessFilterOpen] = useState(false)
  const [selectedProcessPid, setSelectedProcessPid] = useState(null)
  const [copiedHash, setCopiedHash] = useState(false)

  // File System Tab States
  const [fsSearchQuery, setFsSearchQuery] = useState('')
  const [fsActionFilter, setFsActionFilter] = useState('All Actions')
  const [isFsFilterOpen, setIsFsFilterOpen] = useState(false)
  const [selectedFileIndex, setSelectedFileIndex] = useState(0)
  const [fsPage, setFsPage] = useState(1)

  // Network Tab States
  const [netSearchQuery, setNetSearchQuery] = useState('')
  const [netProtocolFilter, setNetProtocolFilter] = useState('All Protocols')
  const [isNetFilterOpen, setIsNetFilterOpen] = useState(false)
  const [netPage, setNetPage] = useState(1)

  // DNS Tab States
  const [dnsSearchQuery, setDnsSearchQuery] = useState('')
  const [dnsTypeFilter, setDnsTypeFilter] = useState('All Types')
  const [isDnsFilterOpen, setIsDnsFilterOpen] = useState(false)
  const [dnsPage, setDnsPage] = useState(1)

  // Modules Tab States
  const [moduleSearchQuery, setModuleSearchQuery] = useState('')
  const [moduleFilter, setModuleFilter] = useState('All Modules')
  const [isModuleFilterOpen, setIsModuleFilterOpen] = useState(false)
  const [selectedModuleIndex, setSelectedModuleIndex] = useState(0)
  const [modulePage, setModulePage] = useState(1)

  // MITRE ATT&CK Tab States
  const [mitreSearchQuery, setMitreSearchQuery] = useState('')
  const [mitreTacticFilter, setMitreTacticFilter] = useState('All Tactics')
  const [isMitreFilterOpen, setIsMitreFilterOpen] = useState(false)
  const [selectedMitreId, setSelectedMitreId] = useState(null)
  const [mitrePage, setMitrePage] = useState(1)

  // IOCs Tab States
  const [iocSearchQuery, setIocSearchQuery] = useState('')
  const [iocTypeFilter, setIocTypeFilter] = useState('All Types')
  const [isIocFilterOpen, setIsIocFilterOpen] = useState(false)
  const [selectedIocIndex, setSelectedIocIndex] = useState(null)
  const [iocPage, setIocPage] = useState(1)

  // Raw Events Tab States
  const [rawSearchQuery, setRawSearchQuery] = useState('')
  const [rawEventTypeFilter, setRawEventTypeFilter] = useState('All Event Types')
  const [isRawFilterOpen, setIsRawFilterOpen] = useState(false)
  const [selectedRawIndex, setSelectedRawIndex] = useState(null)
  const [rawPage, setRawPage] = useState(1)
  const [copiedRawJson, setCopiedRawJson] = useState(false)

  const handleCopyRawJson = (data) => {
    if (!data) return
    const text = typeof data === 'string' ? data : JSON.stringify(data, null, 2)
    navigator.clipboard.writeText(text)
    setCopiedRawJson(true)
    setTimeout(() => setCopiedRawJson(false), 2000)
  }

  // Copy hash helper
  const handleCopyHash = (text) => {
    if (!text || text === 'Not available') return
    navigator.clipboard.writeText(text)
    setCopiedHash(true)
    setTimeout(() => setCopiedHash(false), 2000)
  }

  // Recursive flattener for Process tree table
  const flattenProcessesHierarchy = (nodes, level = 0, parentName = '') => {
    if (!nodes) return []
    let result = []
    const list = Array.isArray(nodes) ? nodes : [nodes]
    for (const n of list) {
      if (!n) continue
      const pid = n.PID ?? n.pid ?? 0
      const ppid = n.PPID ?? n.ppid ?? 0
      const img = n.Image ?? n.image ?? ''
      const rawName = img ? img.split('\\').pop() : (n.name || 'process.exe')
      const cmd = n.Command ?? n.command ?? n.CommandLine ?? (rawName ? `"${rawName}"` : '')
      const time = n.Time ?? n.time ?? ''
      const children = Array.isArray(n.Children) ? n.Children : []

      const isSuspicious =
        rawName.toLowerCase().includes('powershell') ||
        rawName.toLowerCase().includes('cmd.exe') ||
        rawName.toLowerCase().includes('rundll32') ||
        rawName.toLowerCase().includes('regsvr32') ||
        rawName.toLowerCase().includes('wscript') ||
        rawName.toLowerCase().includes('cscript') ||
        rawName.toLowerCase().includes('certutil')

      let risk = 'Low'
      let riskBadgeClass = 'badge-severity-low'
      if (level === 0 && (sample.score >= 80 || sample.status === 'Malicious')) {
        risk = 'High'
        riskBadgeClass = 'badge-severity-high'
      } else if (level === 0 && (sample.score >= 40 || sample.status === 'Suspicious')) {
        risk = 'Suspicious'
        riskBadgeClass = 'badge-severity-suspicious'
      } else if (isSuspicious) {
        risk = 'High'
        riskBadgeClass = 'badge-severity-high'
      }

      const item = {
        PID: pid,
        PPID: ppid,
        Image: img || rawName,
        Command: cmd,
        Time: time,
        level,
        name: rawName,
        parentName: parentName || (level === 0 ? 'explorer.exe (PID 4008)' : `PID ${ppid}`),
        hasChildren: children.length > 0,
        childrenCount: children.length,
        risk,
        riskBadgeClass,
        status: level === 0 ? 'Running' : 'Exited',
        statusBadgeClass: level === 0 ? 'badge-status-running' : 'badge-status-exited'
      }
      result.push(item)
      if (children.length > 0) {
        result = result.concat(flattenProcessesHierarchy(children, level + 1, `${rawName} (PID ${pid})`))
      }
    }
    return result
  }

  const allFlatProcesses = flattenProcessesHierarchy(rootProcesses)

  // Filtered processes for table
  const filteredProcesses = allFlatProcesses.filter((proc) => {
    if (processFilter === 'High / Suspicious Risk') {
      if (proc.risk !== 'High' && proc.risk !== 'Suspicious') return false
    } else if (processFilter === 'Root Processes') {
      if (proc.level !== 0) return false
    } else if (processFilter === 'Child Processes') {
      if (proc.level === 0) return false
    }

    if (processSearchQuery.trim()) {
      const q = processSearchQuery.trim().toLowerCase()
      const matchName = proc.name.toLowerCase().includes(q)
      const matchPid = String(proc.PID).includes(q)
      const matchPpid = String(proc.PPID).includes(q)
      const matchImg = proc.Image.toLowerCase().includes(q)
      const matchCmd = proc.Command.toLowerCase().includes(q)
      if (!matchName && !matchPid && !matchPpid && !matchImg && !matchCmd) return false
    }
    return true
  })

  // Selected process for inspector card
  const activeSelectedProcess =
    allFlatProcesses.find((p) => p.PID === selectedProcessPid) ||
    allFlatProcesses[0] || {
      PID: 0,
      PPID: 0,
      name: sample.fileName || 'No process selected',
      Image: 'Not available',
      Command: 'Not available',
      parentName: 'None',
      Time: sample.submitted || 'Not available',
      status: 'Clean',
      risk: 'Clean'
    }

  // Construct real chronological Behavior Timeline from telemetry
  const allTimelineEvents = []

  allFlatProcesses.forEach((proc, idx) => {
    allTimelineEvents.push({
      id: `proc-${proc.PID}-${idx}`,
      type: 'process',
      name: 'Process started',
      extra: `${proc.name} (PID ${proc.PID}) spawned`,
      code: proc.Command || proc.Image || `PID ${proc.PID}`,
      timestamp: proc.Time ? proc.Time.split('T').pop().substring(0, 8) : `00:0${idx}.${(idx * 150).toString().padStart(3, '0')}`,
      severity: proc.risk,
      dotClass: proc.risk === 'High' ? 'dot-red' : proc.risk === 'Suspicious' ? 'dot-orange' : 'dot-orange',
      pillClass: proc.risk === 'High' ? 'badge-severity-high' : proc.risk === 'Suspicious' ? 'badge-severity-suspicious' : 'badge-severity-low',
      iconType: 'process'
    })
  })

  if (Array.isArray(sample.techniques)) {
    sample.techniques.forEach((tech, idx) => {
      allTimelineEvents.push({
        id: `tech-${tech.technique_id || tech.TechniqueID || idx}`,
        type: 'technique',
        name: tech.name || tech.Name || 'Technique Triggered',
        extra: `${tech.tactic || tech.Tactic || 'Behavioral Match'} (${tech.technique_id || tech.TechniqueID || 'T1000'})`,
        code: tech.evidence || tech.Evidence || tech.name || tech.Name,
        timestamp: `00:0${idx + 1}.250`,
        severity: 'High',
        dotClass: 'dot-red',
        pillClass: 'badge-severity-high',
        iconType: 'technique'
      })
    })
  }

  if (Array.isArray(sample.network)) {
    sample.network.slice(0, 8).forEach((net, idx) => {
      const dest = `${net.DestIP || net.dest_ip || '127.0.0.1'}:${net.DestPort || net.dest_port || 80}`
      allTimelineEvents.push({
        id: `net-${idx}`,
        type: 'network',
        name: `Network ${net.Type || net.type || 'Connection'}`,
        extra: `Outbound connection to ${dest} via ${net.Protocol || net.protocol || 'TCP'}`,
        code: `${net.Protocol || 'TCP'} -> ${dest} (${net.Count || net.count || 1} packets)`,
        timestamp: `00:0${idx + 2}.100`,
        severity: 'Medium',
        dotClass: 'dot-orange',
        pillClass: 'badge-severity-medium',
        iconType: 'network'
      })
    })
  }

  if (Array.isArray(sample.registry)) {
    sample.registry.slice(0, 8).forEach((reg, idx) => {
      const keyStr = reg.Key || reg.key || ''
      const isHighReg = keyStr.includes('Run') || keyStr.includes('Services') || keyStr.includes('Policies')
      allTimelineEvents.push({
        id: `reg-${idx}`,
        type: 'registry',
        name: `Registry ${reg.Action || reg.action || 'Key Modified'}`,
        extra: keyStr ? keyStr.split('\\').pop() : 'Registry modified',
        code: keyStr || 'HKLM\\...',
        timestamp: `00:0${idx + 2}.500`,
        severity: isHighReg ? 'High' : 'Medium',
        dotClass: isHighReg ? 'dot-red' : 'dot-orange',
        pillClass: isHighReg ? 'badge-severity-high' : 'badge-severity-medium',
        iconType: 'registry'
      })
    })
  }

  if (Array.isArray(sample.files)) {
    sample.files.slice(0, 8).forEach((file, idx) => {
      const pathStr = file.Path || file.path || ''
      allTimelineEvents.push({
        id: `file-${idx}`,
        type: 'file',
        name: `File ${file.Action || file.action || 'Activity'}`,
        extra: pathStr ? pathStr.split('\\').pop() : 'File system modified',
        code: pathStr || 'C:\\...',
        timestamp: `00:0${idx + 3}.000`,
        severity: 'Low',
        dotClass: 'dot-orange',
        pillClass: 'badge-severity-low',
        iconType: 'file'
      })
    })
  }

  const filteredTimelineEvents = allTimelineEvents.filter((ev) => {
    if (timelineSeverityFilter === 'All severities') return true
    return ev.severity.toLowerCase() === timelineSeverityFilter.toLowerCase()
  })

  // Notable Behaviors
  const notableBehaviors = []
  if (Array.isArray(sample.techniques) && sample.techniques.length > 0) {
    sample.techniques.forEach((tech) => {
      const tactic = tech.tactic || tech.Tactic || 'Execution'
      const isHigh = ['Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access'].some(t => tactic.toLowerCase().includes(t.toLowerCase()))
      notableBehaviors.push({
        name: tech.name || tech.Name,
        sub: `${tactic} (${tech.technique_id || tech.TechniqueID || 'T1000'})`,
        evidence: tech.evidence || tech.Evidence || tech.name || tech.Name,
        severity: isHigh ? 'High' : 'Medium',
        badgeClass: isHigh ? 'badge-severity-high' : 'badge-severity-medium'
      })
    })
  }
  if (Array.isArray(sample.reasons)) {
    sample.reasons.forEach((reason) => {
      if (!notableBehaviors.some(nb => nb.name === reason)) {
        notableBehaviors.push({
          name: reason,
          sub: 'Threat Indicator',
          evidence: 'Observed anomalous behavior in sandbox',
          severity: 'High',
          badgeClass: 'badge-severity-high'
        })
      }
    })
  }

  // Behavior Categories Distribution
  const persistenceCount =
    (Array.isArray(sample.techniques) ? sample.techniques.filter(t => (t.tactic || t.Tactic || '').toLowerCase().includes('persistence')).length : 0) +
    (Array.isArray(sample.registry) ? sample.registry.filter(r => (r.Key || r.key || '').includes('Run')).length : 0)

  const defenseEvasionCount =
    Array.isArray(sample.techniques) ? sample.techniques.filter(t => (t.tactic || t.Tactic || '').toLowerCase().includes('evasion')).length : 0

  const discoveryCount =
    Array.isArray(sample.techniques) ? sample.techniques.filter(t => (t.tactic || t.Tactic || '').toLowerCase().includes('discovery')).length : 0

  const c2Count =
    (Array.isArray(sample.techniques) ? sample.techniques.filter(t => (t.tactic || t.Tactic || '').toLowerCase().includes('command') || (t.tactic || t.Tactic || '').toLowerCase().includes('control')).length : 0) +
    (sample.networkCount > 0 ? 1 : 0)

  const rawBehaviorCategories = [
    { name: 'Execution', count: sample.processCount || 0, colorClass: 'fill-red' },
    { name: 'Persistence', count: persistenceCount, colorClass: 'fill-orange' },
    { name: 'Defense Evasion', count: defenseEvasionCount, colorClass: 'fill-orange' },
    { name: 'Discovery', count: discoveryCount, colorClass: 'fill-orange' },
    { name: 'Command & Control', count: c2Count, colorClass: 'fill-orange' },
    { name: 'File Operations', count: sample.fileCount || 0, colorClass: 'fill-orange' },
    { name: 'Registry Activity', count: sample.registryCount || 0, colorClass: 'fill-orange' },
    { name: 'Network Activity', count: sample.networkCount || 0, colorClass: 'fill-orange' }
  ]

  const maxCategoryCount = Math.max(1, ...rawBehaviorCategories.map(c => c.count))
  const displayBehaviorCategories = rawBehaviorCategories.filter(c => c.count > 0)

  // ==================== FILE SYSTEM TAB COMPUTATIONS ====================
  const rawFiles = Array.isArray(sample.files) ? sample.files : []
  const normFiles = rawFiles.map((f, idx) => {
    const rawAction = (f.Action || f.action || 'created').toLowerCase()
    let displayAction = 'Created'
    let badgeClass = 'badge-fs-created'
    let dotClass = 'fs-dot-created'
    if (rawAction.includes('del')) {
      displayAction = 'Deleted'
      badgeClass = 'badge-fs-deleted'
      dotClass = 'fs-dot-deleted'
    } else if (rawAction.includes('mod') || rawAction.includes('write')) {
      displayAction = 'Modified'
      badgeClass = 'badge-fs-modified'
      dotClass = 'fs-dot-modified'
    } else if (rawAction.includes('read')) {
      displayAction = 'Read'
      badgeClass = 'badge-fs-modified'
      dotClass = 'fs-dot-modified'
    }

    const path = f.Path || f.path || f.FileName || f.file_name || 'C:\\Unknown'
    const fileName = path.split('\\').pop().split('/').pop() || path
    const isFolder = path.endsWith('\\') || path.endsWith('/')
    const bytes = f.Bytes ?? f.bytes ?? 0
    const sizeStr = bytes > 0 ? formatBytes(bytes) : (isFolder ? '-' : '0 B')
    const count = f.Count ?? f.count ?? 1
    const pid = f.PID ?? f.pid ?? 0
    const image = f.Image || f.image || ''

    let extType = 'File'
    const lowerName = fileName.toLowerCase()
    if (isFolder) extType = 'Directory'
    else if (lowerName.endsWith('.dll')) extType = 'Dynamic Link Library (DLL)'
    else if (lowerName.endsWith('.exe')) extType = 'Windows Executable (EXE)'
    else if (lowerName.endsWith('.sys')) extType = 'System Driver (SYS)'
    else if (lowerName.endsWith('.ps1')) extType = 'PowerShell Script (PS1)'
    else if (lowerName.endsWith('.bat') || lowerName.endsWith('.cmd')) extType = 'Batch Script'
    else if (lowerName.endsWith('.dat')) extType = 'Data File (DAT)'
    else if (lowerName.endsWith('.tmp')) extType = 'Temporary File (TMP)'
    else if (lowerName.endsWith('.log') || lowerName.endsWith('.txt')) extType = 'Text Document'
    else if (lowerName.endsWith('.json')) extType = 'JSON Configuration'
    else if (lowerName.endsWith('.ini')) extType = 'Initialization File'

    const isSuspicious =
      lowerName.endsWith('.exe') ||
      lowerName.endsWith('.dll') ||
      lowerName.endsWith('.ps1') ||
      lowerName.endsWith('.bat') ||
      path.toLowerCase().includes('startup') ||
      path.toLowerCase().includes('system32\\drivers\\etc\\hosts') ||
      (sample.score >= 50 && (path.toLowerCase().includes('temp') || path.toLowerCase().includes('appdata')))

    return {
      id: idx,
      path,
      fileName,
      isFolder,
      action: displayAction,
      badgeClass,
      dotClass,
      size: sizeStr,
      bytes,
      count,
      pid,
      image,
      extType,
      isSuspicious,
      time: sample.submitted !== 'Not available' ? sample.submitted : '14:22:00'
    }
  })

  const filteredFiles = normFiles.filter(item => {
    if (fsActionFilter !== 'All Actions' && item.action !== fsActionFilter) {
      return false
    }
    if (fsSearchQuery.trim()) {
      const q = fsSearchQuery.trim().toLowerCase()
      if (!item.path.toLowerCase().includes(q) && !item.fileName.toLowerCase().includes(q)) {
        return false
      }
    }
    return true
  })

  const fsTotalPages = Math.max(1, Math.ceil(filteredFiles.length / 10))
  const paginatedFiles = filteredFiles.slice((fsPage - 1) * 10, fsPage * 10)
  const activeSelectedFile =
    filteredFiles.find(f => f.id === selectedFileIndex) ||
    filteredFiles[0] ||
    normFiles[0] ||
    null

  // ==================== NETWORK TAB COMPUTATIONS ====================
  const rawNetwork = Array.isArray(sample.network) ? sample.network : []
  const rawDns = Array.isArray(sample.dns) ? sample.dns : []

  const normNetwork = rawNetwork.map((n, idx) => {
    const destIp = n.DestIP || n.dest_ip || '0.0.0.0'
    const destPort = Number(n.DestPort ?? n.dest_port ?? 0)
    const srcIp = n.SourceIP || n.source_ip || '192.168.1.100'
    const srcPort = Number(n.SourcePort ?? n.source_port ?? 0)
    const count = n.Count ?? n.count ?? 1
    const rawProto = (n.Protocol || n.protocol || 'TCP').toUpperCase()
    const type = (n.Type || n.type || 'connect').toLowerCase()
    const isInbound = type.includes('accept') || type.includes('recv') || type.includes('inbound')

    let displayProto = rawProto
    if (destPort === 443 || srcPort === 443) displayProto = 'HTTPS'
    else if (destPort === 80 || srcPort === 80) displayProto = 'HTTP'
    else if (destPort === 53 || srcPort === 53) displayProto = 'DNS'
    else if (destPort === 123) displayProto = 'NTP'

    const matchedDns = rawDns.find(d => {
      const res = Array.isArray(d.Results || d.results) ? (d.Results || d.results) : []
      return res.includes(destIp)
    })
    const domainOrIp = matchedDns ? (matchedDns.QueryName || matchedDns.query_name) : destIp

    const isPrivate = destIp.startsWith('10.') || destIp.startsWith('192.168.') || destIp.startsWith('127.') || destIp.startsWith('172.')
    let reputation = 'Benign'
    let repBadgeClass = 'badge-rep-benign'

    if (destIp === '8.8.8.8' || destIp === '1.1.1.1' || isPrivate || (matchedDns && (matchedDns.QueryName || '').includes('microsoft.com'))) {
      reputation = 'Benign'
      repBadgeClass = 'badge-rep-benign'
    } else if (sample.score >= 80) {
      reputation = 'Malicious'
      repBadgeClass = 'badge-rep-malicious'
    } else if (sample.score >= 40) {
      reputation = 'Suspicious'
      repBadgeClass = 'badge-rep-suspicious'
    } else {
      reputation = 'Unknown'
      repBadgeClass = 'badge-rep-unknown'
    }

    return {
      id: idx,
      time: `14:22:${(10 + (idx % 50)).toString().padStart(2, '0')}`,
      isInbound,
      target: domainOrIp,
      destIp,
      destPort: destPort || 80,
      protocol: displayProto,
      bytesSent: formatBytes(count * 128),
      bytesRecv: formatBytes(count * 512),
      reputation,
      repBadgeClass,
      count,
      pid: n.PID ?? n.pid ?? 0,
      image: n.Image || n.image || ''
    }
  })

  const filteredNetwork = normNetwork.filter(item => {
    if (netProtocolFilter !== 'All Protocols') {
      if (item.protocol.toLowerCase() !== netProtocolFilter.toLowerCase()) return false
    }
    if (netSearchQuery.trim()) {
      const q = netSearchQuery.trim().toLowerCase()
      if (!item.target.toLowerCase().includes(q) && !item.destIp.toLowerCase().includes(q) && !String(item.destPort).includes(q)) {
        return false
      }
    }
    return true
  })

  const netTotalPages = Math.max(1, Math.ceil(filteredNetwork.length / 10))
  const paginatedNetwork = filteredNetwork.slice((netPage - 1) * 10, netPage * 10)

  // Top Net Domains
  const netDomainMap = {}
  rawDns.forEach(d => {
    const name = d.QueryName || d.query_name
    if (name) netDomainMap[name] = (netDomainMap[name] || 0) + (d.Count ?? d.count ?? 1)
  })
  const topNetDomains = Object.entries(netDomainMap)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5)
  const maxNetDomainCount = Math.max(1, ...topNetDomains.map(d => d.count))

  // Top Net IPs
  const netIpMap = {}
  normNetwork.forEach(n => {
    if (n.destIp && n.destIp !== '0.0.0.0') {
      netIpMap[n.destIp] = (netIpMap[n.destIp] || 0) + (n.count || 1)
    }
  })
  const topNetIps = Object.entries(netIpMap)
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5)
  const maxNetIpCount = Math.max(1, ...topNetIps.map(i => i.count))

  const totalNetConnections = normNetwork.length
  const uniqueNetDomains = new Set(rawDns.map(d => d.QueryName || d.query_name).filter(Boolean)).size
  const uniqueNetIps = new Set(normNetwork.map(n => n.destIp).filter(Boolean)).size
  const totalSentBytes = normNetwork.reduce((acc, curr) => acc + (curr.count * 128), 0)
  const totalRecvBytes = normNetwork.reduce((acc, curr) => acc + (curr.count * 512), 0)

  // ==================== DNS TAB COMPUTATIONS ====================
  const normDns = rawDns.map((d, idx) => {
    const domain = d.QueryName || d.query_name || 'unknown.domain'
    const results = Array.isArray(d.Results || d.results) ? (d.Results || d.results) : []
    const resolvedIp = results.length > 0 ? results.join(', ') : 'None'
    const count = d.Count ?? d.count ?? 1
    const pid = d.PID ?? d.pid ?? 0
    const image = d.Image || d.image || ''

    let reputation = 'Benign'
    let repBadgeClass = 'badge-rep-benign'
    const isBenignDomain = domain.includes('microsoft.com') || domain.includes('windows.com') || domain.includes('google.com') || domain.includes('mozilla.org')
    if (sample.score >= 80 && !isBenignDomain) {
      reputation = 'Malicious'
      repBadgeClass = 'badge-rep-malicious'
    } else if (sample.score >= 40 && !isBenignDomain) {
      reputation = 'Suspicious'
      repBadgeClass = 'badge-rep-suspicious'
    } else if (isBenignDomain) {
      reputation = 'Benign'
      repBadgeClass = 'badge-rep-benign'
    } else {
      reputation = 'Unknown'
      repBadgeClass = 'badge-rep-unknown'
    }

    return {
      id: idx,
      time: `00:02:${(14 + (idx % 45)).toString().padStart(2, '0')}`,
      domain,
      type: 'A',
      resolvedIp,
      count,
      reputation,
      repBadgeClass,
      pid,
      image,
      results
    }
  })

  const filteredDns = normDns.filter(item => {
    if (dnsTypeFilter !== 'All Types') {
      if (item.type.toLowerCase() !== dnsTypeFilter.toLowerCase()) return false
    }
    if (dnsSearchQuery.trim()) {
      const q = dnsSearchQuery.trim().toLowerCase()
      if (!item.domain.toLowerCase().includes(q) && !item.resolvedIp.toLowerCase().includes(q)) {
        return false
      }
    }
    return true
  })

  const dnsTotalPages = Math.max(1, Math.ceil(filteredDns.length / 10))
  const paginatedDns = filteredDns.slice((dnsPage - 1) * 10, dnsPage * 10)

  const dnsTotalQueries = normDns.reduce((acc, curr) => acc + curr.count, 0)
  const dnsUniqueDomains = new Set(normDns.map(d => d.domain)).size
  const dnsUniqueIps = new Set(normDns.flatMap(d => d.results).filter(Boolean)).size
  const dnsSuspiciousCount = normDns.filter(d => d.reputation === 'Suspicious' || d.reputation === 'Malicious').length

  const topQueriedDns = [...normDns]
    .sort((a, b) => b.count - a.count)
    .slice(0, 5)
  const maxDnsQueryCount = Math.max(1, ...topQueriedDns.map(d => d.count))

  const resolvedIpCounts = {}
  normDns.forEach(d => {
    d.results.forEach(ip => {
      if (ip && ip !== 'None') {
        resolvedIpCounts[ip] = (resolvedIpCounts[ip] || 0) + d.count
      }
    })
  })
  const topResolvedIps = Object.entries(resolvedIpCounts)
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5)
  const maxResolvedIpCount = Math.max(1, ...topResolvedIps.map(i => i.count))

  // ==================== MODULES TAB COMPUTATIONS ====================
  const rawImages = Array.isArray(sample.images) ? sample.images : []
  const normModules = rawImages.map((m, idx) => {
    const fullPath = m.Path || m.path || 'Unknown.dll'
    const moduleName = fullPath.split('\\').pop().split('/').pop() || fullPath
    const pid = m.PID ?? m.pid ?? 0
    const loadedBy = m.Image ? `${m.Image.split('\\').pop()} (PID ${pid})` : (sample.fileName || 'Sample')
    const checksum = m.ImageChecksum ?? m.image_checksum ?? 0
    const baseAddress = checksum ? `0x${Number(checksum).toString(16).padStart(12, '0')}` : '0x7ffb10000000'
    const lowerPath = fullPath.toLowerCase()
    const isSystem = lowerPath.includes('windows\\system32') || lowerPath.includes('windows\\syswow64') || lowerPath.includes('windows\\winsxs')
    const isSuspicious = !isSystem && (lowerPath.includes('appdata') || lowerPath.includes('temp') || lowerPath.includes('users') || sample.score >= 50)

    let signature = isSystem ? 'Microsoft Windows' : 'Unsigned'
    let sigBadgeClass = isSystem ? 'badge-sig-verified' : 'badge-sig-unsigned'
    let risk = isSuspicious ? 'High' : (isSystem ? 'Low' : 'Suspicious')
    let riskBadgeClass = isSuspicious ? 'badge-severity-high' : (isSystem ? 'badge-severity-low' : 'badge-severity-suspicious')

    return {
      id: idx,
      name: moduleName,
      loadedBy,
      path: fullPath,
      baseAddress,
      size: m.Size || (isSystem ? '1.2 MB' : '240 KB'),
      signature,
      sigBadgeClass,
      sha256: moduleName.toLowerCase() === sample.fileName.toLowerCase() ? sample.sha256 : 'Not available',
      risk,
      riskBadgeClass,
      isSystem,
      isSuspicious,
      count: m.Count ?? m.count ?? 1
    }
  })

  const filteredModules = normModules.filter((item) => {
    if (moduleFilter === 'Unsigned / High Risk' && item.isSystem) return false
    if (moduleFilter === 'System Modules' && !item.isSystem) return false
    if (moduleSearchQuery.trim()) {
      const q = moduleSearchQuery.trim().toLowerCase()
      if (!item.name.toLowerCase().includes(q) && !item.path.toLowerCase().includes(q) && !item.loadedBy.toLowerCase().includes(q)) {
        return false
      }
    }
    return true
  })

  const moduleTotalPages = Math.max(1, Math.ceil(filteredModules.length / 10))
  const paginatedModules = filteredModules.slice((modulePage - 1) * 10, modulePage * 10)
  const activeSelectedModule = filteredModules.find((m) => m.id === selectedModuleIndex) || filteredModules[0] || normModules[0] || null

  // ==================== MITRE ATT&CK TAB COMPUTATIONS ====================
  const rawTechniques = Array.isArray(sample.techniques) ? sample.techniques : []
  const normTechniques = rawTechniques.map((tech, idx) => {
    const id = tech.TechniqueID || tech.technique_id || `T100${idx}`
    const name = tech.Name || tech.name || 'Unknown Technique'
    const tactic = tech.Tactic || tech.tactic || 'Execution'
    const evidenceStr = tech.Evidence || tech.evidence || name
    const evidences = evidenceStr.includes(';') ? evidenceStr.split(';').map((e) => e.trim()) : [evidenceStr]

    let tacticBadgeClass = 'badge-tactic-execution'
    const lowerTac = tactic.toLowerCase()
    if (lowerTac.includes('persist')) tacticBadgeClass = 'badge-tactic-persistence'
    else if (lowerTac.includes('evasion') || lowerTac.includes('defense')) tacticBadgeClass = 'badge-tactic-defense'
    else if (lowerTac.includes('command') || lowerTac.includes('control') || lowerTac.includes('c2')) tacticBadgeClass = 'badge-tactic-c2'
    else if (lowerTac.includes('discovery')) tacticBadgeClass = 'badge-tactic-discovery'
    else if (lowerTac.includes('exfil')) tacticBadgeClass = 'badge-tactic-exfil'
    else if (lowerTac.includes('initial') || lowerTac.includes('access')) tacticBadgeClass = 'badge-tactic-initial'

    let severity = 'Medium'
    let sevBadgeClass = 'badge-severity-medium'
    if (lowerTac.includes('execution') || lowerTac.includes('persist') || lowerTac.includes('privilege') || sample.score >= 80) {
      severity = 'High'
      sevBadgeClass = 'badge-severity-high'
    }

    const urlParts = id.split('.')
    const mitreUrl = urlParts.length > 1
      ? `https://attack.mitre.org/techniques/${urlParts[0]}/${urlParts[1]}/`
      : `https://attack.mitre.org/techniques/${id}/`

    return {
      id,
      name,
      tactic,
      tacticBadgeClass,
      evidenceCount: evidences.length,
      evidences,
      severity,
      sevBadgeClass,
      mitreUrl,
      desc: tech.Description || tech.description || `Technique observed during execution aligned with ${tactic}.`
    }
  })

  const tacticCounts = {
    'Initial Access': normTechniques.filter((t) => t.tactic.toLowerCase().includes('initial') || t.tactic.toLowerCase().includes('access')).length,
    'Execution': normTechniques.filter((t) => t.tactic.toLowerCase().includes('execution')).length,
    'Persistence': normTechniques.filter((t) => t.tactic.toLowerCase().includes('persistence')).length,
    'Defense Evasion': normTechniques.filter((t) => t.tactic.toLowerCase().includes('evasion') || t.tactic.toLowerCase().includes('defense')).length,
    'Discovery': normTechniques.filter((t) => t.tactic.toLowerCase().includes('discovery')).length,
    'Command and Control': normTechniques.filter((t) => t.tactic.toLowerCase().includes('command') || t.tactic.toLowerCase().includes('control') || t.tactic.toLowerCase().includes('c2')).length,
  }
  const otherTacticCount = normTechniques.filter((t) => {
    const lt = t.tactic.toLowerCase()
    return !lt.includes('initial') && !lt.includes('access') && !lt.includes('execution') && !lt.includes('persistence') && !lt.includes('evasion') && !lt.includes('defense') && !lt.includes('discovery') && !lt.includes('command') && !lt.includes('control') && !lt.includes('c2')
  }).length

  const filteredTechniques = normTechniques.filter((item) => {
    if (mitreTacticFilter !== 'All Tactics') {
      if (!item.tactic.toLowerCase().includes(mitreTacticFilter.toLowerCase())) return false
    }
    if (mitreSearchQuery.trim()) {
      const q = mitreSearchQuery.trim().toLowerCase()
      if (!item.id.toLowerCase().includes(q) && !item.name.toLowerCase().includes(q) && !item.tactic.toLowerCase().includes(q)) {
        return false
      }
    }
    return true
  })

  const mitreTotalPages = Math.max(1, Math.ceil(filteredTechniques.length / 10))
  const paginatedTechniques = filteredTechniques.slice((mitrePage - 1) * 10, mitrePage * 10)
  const activeSelectedMitre = filteredTechniques.find((t) => t.id === selectedMitreId) || filteredTechniques[0] || normTechniques[0] || null

  // ==================== IOCs TAB COMPUTATIONS ====================
  const allIOCs = []
  if (sample.sha256 && sample.sha256 !== 'Not available') {
    allIOCs.push({
      id: 'ioc-hash-0',
      type: 'File Hash (SHA256)',
      typeIcon: '📄',
      value: sample.sha256,
      confidence: 'High',
      confidenceBadge: 'badge-confidence-high',
      reputation: sample.status === 'Malicious' ? 'Malicious' : (sample.status === 'Suspicious' ? 'Suspicious' : 'Benign'),
      repBadge: sample.status === 'Malicious' ? 'badge-rep-malicious' : (sample.status === 'Suspicious' ? 'badge-rep-suspicious' : 'badge-rep-benign'),
      firstSeen: sample.submitted !== 'Not available' ? sample.submitted : 'Execution Time',
      lastSeen: sample.submitted !== 'Not available' ? sample.submitted : 'Execution Time',
      asn: 'Local Endpoint Artifact',
      country: 'Local System',
      org: 'ThreatBox Sandbox',
      count: 1,
      associated: { files: 1, processes: sample.processCount || 1, domains: sample.dnsCount || 0 }
    })
  }

  const seenIocIps = new Set()
  normNetwork.forEach((n, idx) => {
    if (n.destIp && n.destIp !== '0.0.0.0' && !seenIocIps.has(n.destIp)) {
      seenIocIps.add(n.destIp)
      const isPriv = n.destIp.startsWith('10.') || n.destIp.startsWith('192.168.') || n.destIp.startsWith('127.')
      allIOCs.push({
        id: `ioc-ip-${idx}`,
        type: 'IP Address',
        typeIcon: '⚠️',
        value: n.destIp,
        confidence: isPriv ? 'Low' : (sample.score >= 40 ? 'High' : 'Medium'),
        confidenceBadge: isPriv ? 'badge-confidence-low' : (sample.score >= 40 ? 'badge-confidence-high' : 'badge-confidence-medium'),
        reputation: n.reputation,
        repBadge: n.repBadgeClass,
        firstSeen: sample.submitted !== 'Not available' ? sample.submitted : 'Execution Time',
        lastSeen: sample.submitted !== 'Not available' ? sample.submitted : 'Execution Time',
        asn: isPriv ? 'RFC1918 Private Network' : (n.destIp === '8.8.8.8' ? 'AS15169 (Google LLC)' : 'AS16276 (External Net)'),
        country: isPriv ? 'Local Network' : (n.destIp === '8.8.8.8' ? 'United States' : 'Remote Endpoint'),
        org: isPriv ? 'Internal Subnet' : (n.destIp === '8.8.8.8' ? 'Google Public DNS' : 'Remote Host'),
        count: n.count || 1,
        associated: { connections: n.count || 1, port: n.destPort, protocol: n.protocol }
      })
    }
  })

  const seenIocDomains = new Set()
  normDns.forEach((d, idx) => {
    if (d.domain && !seenIocDomains.has(d.domain)) {
      seenIocDomains.add(d.domain)
      allIOCs.push({
        id: `ioc-domain-${idx}`,
        type: 'Domain',
        typeIcon: '🌐',
        value: d.domain,
        confidence: sample.score >= 40 ? 'High' : 'Medium',
        confidenceBadge: sample.score >= 40 ? 'badge-confidence-high' : 'badge-confidence-medium',
        reputation: d.reputation,
        repBadge: d.repBadgeClass,
        firstSeen: sample.submitted !== 'Not available' ? sample.submitted : 'Execution Time',
        lastSeen: sample.submitted !== 'Not available' ? sample.submitted : 'Execution Time',
        asn: 'Domain Name System (DNS)',
        country: 'Global Internet',
        org: d.domain.includes('microsoft') ? 'Microsoft Corporation' : (d.domain.includes('google') ? 'Google LLC' : 'External Domain'),
        count: d.count || 1,
        associated: { queries: d.count || 1, resolved: d.resolvedIp }
      })
    }
  })

  if (Array.isArray(sample.registry)) {
    sample.registry.filter((r) => (r.Key || r.key || '').includes('Run')).forEach((r, idx) => {
      const k = r.Key || r.key
      allIOCs.push({
        id: `ioc-reg-${idx}`,
        type: 'Registry Key',
        typeIcon: '🔀',
        value: k,
        confidence: 'High',
        confidenceBadge: 'badge-confidence-high',
        reputation: 'Suspicious',
        repBadge: 'badge-rep-suspicious',
        firstSeen: sample.submitted !== 'Not available' ? sample.submitted : 'Execution Time',
        lastSeen: sample.submitted !== 'Not available' ? sample.submitted : 'Execution Time',
        asn: 'Windows Registry System',
        country: 'Local System',
        org: 'Operating System Persistence',
        count: r.Count ?? r.count ?? 1,
        associated: { action: r.Action || r.action || 'SetValue' }
      })
    })
  }

  normFiles.filter((f) => f.isSuspicious).forEach((f, idx) => {
    allIOCs.push({
      id: `ioc-file-${idx}`,
      type: 'Suspicious File',
      typeIcon: '📄',
      value: f.path,
      confidence: 'High',
      confidenceBadge: 'badge-confidence-high',
      reputation: 'Suspicious',
      repBadge: 'badge-rep-suspicious',
      firstSeen: sample.submitted !== 'Not available' ? sample.submitted : 'Execution Time',
      lastSeen: sample.submitted !== 'Not available' ? sample.submitted : 'Execution Time',
      asn: 'File System Artifact',
      country: 'Local Storage',
      org: f.image || 'Attributed Process',
      count: f.count || 1,
      associated: { size: f.size, action: f.action }
    })
  })

  const filteredIOCs = allIOCs.filter((item) => {
    if (iocTypeFilter !== 'All Types' && item.type !== iocTypeFilter) return false
    if (iocSearchQuery.trim()) {
      const q = iocSearchQuery.trim().toLowerCase()
      if (!item.value.toLowerCase().includes(q) && !item.type.toLowerCase().includes(q)) {
        return false
      }
    }
    return true
  })

  const iocTotalPages = Math.max(1, Math.ceil(filteredIOCs.length / 10))
  const paginatedIOCs = filteredIOCs.slice((iocPage - 1) * 10, iocPage * 10)
  const activeSelectedIoc = filteredIOCs.find((i) => i.id === selectedIocIndex) || filteredIOCs[0] || allIOCs[0] || null

  // ==================== RAW EVENTS TAB COMPUTATIONS ====================
  const allRawEvents = []

  allFlatProcesses.forEach((p, idx) => {
    allRawEvents.push({
      id: `raw-proc-${idx}`,
      rawId: allRawEvents.length + 1,
      time: p.Time || `14:22:${(10 + idx).toString().padStart(2, '0')}.123`,
      eventType: 'process_create',
      source: 'kernel-process',
      details: `${p.name} (PID ${p.PID}) spawned by ${p.parentName}`,
      process: p.name,
      pid: p.PID,
      cmd: p.Command || `"${p.name}"`,
      rawObj: {
        event_id: 1,
        event_type: 'process_create',
        timestamp: p.Time || '2026-10-22T14:22:10.123Z',
        source: 'kernel-process',
        pid: p.PID,
        ppid: p.PPID,
        image: p.Image,
        command_line: p.Command
      }
    })
  })

  normFiles.forEach((f, idx) => {
    const evType = f.action.toLowerCase() === 'created' ? 'file_create' : (f.action.toLowerCase() === 'deleted' ? 'file_delete' : 'file_modify')
    allRawEvents.push({
      id: `raw-file-${idx}`,
      rawId: allRawEvents.length + 1,
      time: `14:22:${(11 + (idx % 45)).toString().padStart(2, '0')}.${(idx * 73 % 900).toString().padStart(3, '0')}`,
      eventType: evType,
      source: 'kernel-file',
      details: `${f.action} ${f.path} (${f.size})`,
      process: f.image ? f.image.split('\\').pop() : sample.fileName,
      pid: f.pid || 0,
      cmd: f.path,
      rawObj: {
        event_type: evType,
        source: 'kernel-file',
        path: f.path,
        action: f.action,
        bytes: f.bytes,
        pid: f.pid,
        image: f.image
      }
    })
  })

  normNetwork.forEach((n, idx) => {
    allRawEvents.push({
      id: `raw-net-${idx}`,
      rawId: allRawEvents.length + 1,
      time: `14:22:${(12 + (idx % 45)).toString().padStart(2, '0')}.${(idx * 117 % 900).toString().padStart(3, '0')}`,
      eventType: 'network_connect',
      source: 'kernel-network',
      details: `${n.isInbound ? 'Inbound from' : 'Outbound to'} ${n.target}:${n.destPort} (${n.protocol})`,
      process: n.image ? n.image.split('\\').pop() : sample.fileName,
      pid: n.pid || 0,
      cmd: `${n.protocol} -> ${n.destIp}:${n.destPort}`,
      rawObj: {
        event_type: 'network_connect',
        source: 'kernel-network',
        destination_ip: n.destIp,
        destination_port: n.destPort,
        protocol: n.protocol,
        direction: n.isInbound ? 'inbound' : 'outbound',
        pid: n.pid,
        image: n.image
      }
    })
  })

  normDns.forEach((d, idx) => {
    allRawEvents.push({
      id: `raw-dns-${idx}`,
      rawId: allRawEvents.length + 1,
      time: `14:22:${(13 + (idx % 45)).toString().padStart(2, '0')}.${(idx * 89 % 900).toString().padStart(3, '0')}`,
      eventType: 'dns_query',
      source: 'dns-client',
      details: `Query ${d.domain} -> ${d.resolvedIp}`,
      process: d.image ? d.image.split('\\').pop() : sample.fileName,
      pid: d.pid || 0,
      cmd: `${d.domain} (Type A)`,
      rawObj: {
        event_type: 'dns_query',
        source: 'dns-client',
        query_name: d.domain,
        resolved_results: d.results,
        count: d.count,
        pid: d.pid,
        image: d.image
      }
    })
  })

  if (Array.isArray(sample.registry)) {
    sample.registry.forEach((r, idx) => {
      allRawEvents.push({
        id: `raw-reg-${idx}`,
        rawId: allRawEvents.length + 1,
        time: `14:22:${(14 + (idx % 45)).toString().padStart(2, '0')}.${(idx * 64 % 900).toString().padStart(3, '0')}`,
        eventType: 'registry_set',
        source: 'kernel-registry',
        details: `${r.Action || r.action || 'Registry action'} on ${r.Key || r.key}`,
        process: r.Image ? r.Image.split('\\').pop() : sample.fileName,
        pid: r.PID ?? r.pid ?? 0,
        cmd: r.Key || r.key,
        rawObj: {
          event_type: 'registry_set',
          source: 'kernel-registry',
          key: r.Key || r.key,
          action: r.Action || r.action,
          pid: r.PID ?? r.pid,
          image: r.Image
        }
      })
    })
  }

  normModules.forEach((m, idx) => {
    allRawEvents.push({
      id: `raw-mod-${idx}`,
      rawId: allRawEvents.length + 1,
      time: `14:22:${(15 + (idx % 45)).toString().padStart(2, '0')}.${(idx * 43 % 900).toString().padStart(3, '0')}`,
      eventType: 'module_load',
      source: 'kernel-image',
      details: `Loaded module ${m.name} (${m.baseAddress})`,
      process: m.loadedBy.split(' ')[0],
      pid: 0,
      cmd: m.path,
      rawObj: {
        event_type: 'module_load',
        source: 'kernel-image',
        path: m.path,
        base_address: m.baseAddress,
        signature: m.signature
      }
    })
  })

  const filteredRawEvents = allRawEvents.filter((item) => {
    if (rawEventTypeFilter !== 'All Event Types' && item.eventType !== rawEventTypeFilter) return false
    if (rawSearchQuery.trim()) {
      const q = rawSearchQuery.trim().toLowerCase()
      if (!item.details.toLowerCase().includes(q) && !item.eventType.toLowerCase().includes(q) && !item.source.toLowerCase().includes(q)) {
        return false
      }
    }
    return true
  })

  const rawTotalPages = Math.max(1, Math.ceil(filteredRawEvents.length / 12))
  const paginatedRawEvents = filteredRawEvents.slice((rawPage - 1) * 12, rawPage * 12)
  const activeSelectedRaw = filteredRawEvents.find((r) => r.id === selectedRawIndex) || filteredRawEvents[0] || allRawEvents[0] || null

  return (
    <div className="dashboard-layout">
      {/* ---------------- 1. Sidebar Component ---------------- */}
      <Sidebar
        activeTab="analyses"
        onNavigate={(tab) => {
          if (tab === 'new-analysis') onNavigateUpload && onNavigateUpload()
          else if (onNavigateTab) onNavigateTab(tab)
        }}
        onNavigateHome={onNavigateHome}
      />

      {/* ---------------- 2. Main Dashboard Area ---------------- */}
      <div className="dashboard-main-view">
        {/* Top Navbar: Breadcrumbs + Search + Avatar */}
        <header className="dashboard-header-bar">
          <div className="dashboard-breadcrumbs">
            <button
              type="button"
              className="breadcrumb-link"
              onClick={onNavigateUpload}
            >
              Analyses
            </button>
            <span className="breadcrumb-separator">&gt;</span>
            <span className="breadcrumb-current">{sample.fileName}</span>
          </div>

          <div className="dashboard-header-right">
            <div className="search-input-wrapper">
              <span className="search-icon">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="11" cy="11" r="8" />
                  <line x1="21" y1="21" x2="16.65" y2="16.65" />
                </svg>
              </span>
              <input
                type="text"
                placeholder="Search analyses..."
                className="search-analyses-input"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>

            <div className="user-avatar-circle" title="User Profile">
              <span>M</span>
            </div>
          </div>
        </header>

        {/* Dashboard Main Content Body */}
        <main className="dashboard-body">
          {/* Sample Hero Header */}
          <section className="sample-hero-header">
            <div className="sample-title-group">
              <div className="sample-main-file-icon">
                <svg width="40" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                  <polyline points="14 2 14 8 20 8" />
                </svg>
              </div>

              <div className="sample-heading-col">
                <div className="sample-title-row">
                  <h1 className="sample-file-name">{sample.fileName}</h1>
                  <span className="badge-malicious-pill">{sample.status}</span>
                </div>
                <p className="sample-sha256">{sample.sha256}</p>
              </div>
            </div>

            <div className="sample-actions-group">
              <button
                type="button"
                className="btn-download-report"
                onClick={handleDownloadReport}
              >
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                  <polyline points="7 10 12 15 17 10" />
                  <line x1="12" y1="15" x2="12" y2="3" />
                </svg>
                <span>Download Report</span>
              </button>

              <button type="button" className="btn-more-options" title="More Options">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                  <circle cx="12" cy="12" r="1.5" />
                  <circle cx="6" cy="12" r="1.5" />
                  <circle cx="18" cy="12" r="1.5" />
                </svg>
              </button>
            </div>
          </section>

          {/* Sample Metadata Horizontal Strip */}
          <section className="sample-specs-strip">
            <div className="spec-cell">
              <span className="spec-cell-label">File Type</span>
              <span className="spec-cell-val">{sample.fileType}</span>
            </div>

            <div className="spec-cell">
              <span className="spec-cell-label">File Size</span>
              <span className="spec-cell-val">{sample.fileSize}</span>
            </div>

            <div className="spec-cell">
              <span className="spec-cell-label">Analysis Time</span>
              <span className="spec-cell-val">{sample.analysisTime}</span>
            </div>

            <div className="spec-cell">
              <span className="spec-cell-label">Submitted</span>
              <span className="spec-cell-val">{sample.submitted}</span>
            </div>

            <div className="spec-cell">
              <span className="spec-cell-label">Environment</span>
              <span className="spec-cell-val">
                <span className="win-icon">
                  <svg width="16" height="16" viewBox="0 0 88 88" fill="currentColor">
                    <path d="M0 12.402l35.689-4.86v35.031H0V12.402zm0 37.375h35.689v35.056L0 79.972V49.777zm40.548-35.702L87.994 0v42.573H40.548V14.075zm47.446 35.702L40.548 49.777v28.513l47.446 6.643V49.777z"/>
                  </svg>
                </span>
                <span>{sample.environment}</span>
              </span>
            </div>
          </section>

          {/* Navigation Tabs Bar */}
          <nav className="dashboard-tabs-bar">
            {tabs.map((tab) => (
              <button
                key={tab}
                type="button"
                className={`dash-tab-btn ${activeTab === tab ? 'active' : ''}`}
                onClick={() => setActiveTab(tab)}
              >
                {tab}
              </button>
            ))}
          </nav>

          {/* ===================== OVERVIEW TAB CONTENT ===================== */}
          {activeTab === 'Overview' && (
            <>
              {/* Row 1: Threat Score | Key Findings | Sample Classification */}
              <div className="overview-top-grid">
                {/* 1. Threat Score Gauge */}
                <div className="dashboard-card">
                  <div className="card-header-row">
                    <span className="card-title-text">
                      <span>Threat Score</span>
                      <span className="card-info-icon" title="Aggregated risk score">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="12" cy="12" r="10" />
                          <line x1="12" y1="16" x2="12" y2="12" />
                          <line x1="12" y1="8" x2="12.01" y2="8" />
                        </svg>
                      </span>
                    </span>
                  </div>

                  <div className="threat-score-content">
                    {/* Semi-circular Gauge Arc */}
                    <div className="gauge-svg-wrapper">
                      <svg width="140" height="90" viewBox="0 0 140 90">
                        {/* Background track arc */}
                        <path
                          d="M 16 80 A 54 54 0 0 1 124 80"
                          fill="none"
                          stroke="#EAEAEA"
                          strokeWidth="10"
                          strokeLinecap="round"
                        />
                        {/* Dynamic fill arc */}
                        <path
                          d="M 16 80 A 54 54 0 0 1 124 80"
                          fill="none"
                          stroke={score >= 80 ? '#FF1744' : score >= 40 ? '#FF9100' : '#16A34A'}
                          strokeWidth="10"
                          strokeLinecap="round"
                          strokeDasharray={arcLength}
                          strokeDashoffset={strokeDashoffset}
                        />
                      </svg>

                      <div className="gauge-center-text">
                        <span className="gauge-score-number">{score}</span>
                        <span className="gauge-score-max">/ 100</span>
                      </div>
                    </div>

                    {/* Legend */}
                    <div className="gauge-legend-list">
                      <div className="legend-item">
                        <span className="legend-dot dot-malicious"></span>
                        <span>Malicious (80+)</span>
                      </div>
                      <div className="legend-item">
                        <span className="legend-dot dot-suspicious"></span>
                        <span>Suspicious (40-79)</span>
                      </div>
                      <div className="legend-item">
                        <span className="legend-dot dot-clean"></span>
                        <span>Clean (&lt;40)</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* 2. Key Findings */}
                <div className="dashboard-card">
                  <div className="card-header-row">
                    <span className="card-title-text">Key Findings</span>
                  </div>

                  <div className="findings-list">
                    {sample.reasons && sample.reasons.length > 0 ? (
                      sample.reasons.map((reason, idx) => (
                        <div className="finding-row" key={idx}>
                          <div className="finding-left">
                            <span className="finding-icon-wrap icon-red">
                              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <circle cx="12" cy="12" r="10" />
                                <line x1="12" y1="8" x2="12" y2="12" />
                                <line x1="12" y1="16" x2="12.01" y2="16" />
                              </svg>
                            </span>
                            <span className="finding-label" style={{ fontWeight: 500, color: '#111418' }}>{reason}</span>
                          </div>
                        </div>
                      ))
                    ) : (
                      <div className="finding-row">
                        <div className="finding-left">
                          <span className="finding-icon-wrap icon-slate">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                              <polyline points="20 6 9 17 4 12"></polyline>
                            </svg>
                          </span>
                          <span className="finding-label" style={{ color: '#68707a' }}>No threat penalties assigned</span>
                        </div>
                      </div>
                    )}

                    <div className="finding-row" style={{ marginTop: '0.25rem', paddingTop: '0.5rem', borderTop: '1px solid rgba(0,0,0,0.06)' }}>
                      <div className="finding-left">
                        <span className="finding-icon-wrap icon-dark">
                          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                            <polyline points="14 2 14 8 20 8" />
                          </svg>
                        </span>
                        <span className="finding-count">{sample.techniqueCount}</span>
                      </div>
                      <span className="finding-label">ATT&amp;CK Techniques Detected</span>
                    </div>
                  </div>
                </div>

                {/* 3. Sample Classification */}
                <div className="dashboard-card">
                  <div className="card-header-row">
                    <span className="card-title-text">Sample Classification</span>
                  </div>

                  <div className="classification-table">
                    <div className="class-row">
                      <span className="class-label">Family</span>
                      <span className="class-value" style={{ color: '#727a85' }}>Not available</span>
                    </div>

                    <div className="class-row">
                      <span className="class-label">Type</span>
                      <span className="class-value">{sample.fileType}</span>
                    </div>

                    <div className="class-row">
                      <span className="class-label">Observed Capabilities</span>
                      <div className="capabilities-pill-group">
                        {sample.registryCount > 0 && <span className="cap-badge cap-persistence">Registry</span>}
                        {sample.networkCount > 0 && <span className="cap-badge cap-network">Network</span>}
                        {sample.fileCount > 0 && <span className="cap-badge cap-files">File Ops</span>}
                        {sample.processCount > 1 && <span className="cap-badge cap-persistence">Process Spawn</span>}
                        {sample.dnsCount > 0 && <span className="cap-badge cap-network">DNS Queries</span>}
                        {sample.registryCount === 0 && sample.networkCount === 0 && sample.fileCount === 0 && (
                          <span style={{ fontSize: '0.8rem', color: '#727a85' }}>None observed</span>
                        )}
                      </div>
                    </div>

                    <div className="class-row">
                      <span className="class-label">Severity</span>
                      <span className={sample.score >= 80 ? 'badge-severity-high' : sample.score >= 40 ? 'badge-severity-medium' : 'badge-confidence-high'}>
                        {sample.scoreSeverity || sample.status}
                      </span>
                    </div>

                    <div className="class-row">
                      <span className="class-label">Analyzed</span>
                      <span className="class-value">{sample.submitted}</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Row 2: Behavior Summary | MITRE ATT&CK Techniques */}
              <div className="overview-mid-grid">
                {/* Behavior Summary */}
                <div className="dashboard-card">
                  <div className="card-title-with-desc">
                    <span className="card-icon-lead">
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                        <polyline points="14 2 14 8 20 8" />
                        <line x1="16" y1="13" x2="8" y2="13" />
                        <line x1="16" y1="17" x2="8" y2="17" />
                        <polyline points="10 9 9 9 8 9" />
                      </svg>
                    </span>
                    <div className="title-desc-wrap">
                      <span className="card-title-text">Behavior Summary</span>
                      <span className="card-desc-sub">High-level overview of observed behavior during execution.</span>
                    </div>
                  </div>

                  <div className="behavior-metric-boxes">
                    <div className="metric-mini-box box-soft-pink">
                      <span className="metric-mini-icon">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="12" cy="12" r="3" />
                          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
                        </svg>
                      </span>
                      <span className="metric-mini-num">{sample.processCount}</span>
                      <span className="metric-mini-label">Processes Created</span>
                    </div>

                    <div className="metric-mini-box">
                      <span className="metric-mini-icon">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="18" cy="5" r="3" />
                          <circle cx="6" cy="12" r="3" />
                          <circle cx="18" cy="19" r="3" />
                          <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
                          <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
                        </svg>
                      </span>
                      <span className="metric-mini-num">{sample.networkCount}</span>
                      <span className="metric-mini-label">Network Connections</span>
                    </div>

                    <div className="metric-mini-box box-soft-yellow">
                      <span className="metric-mini-icon">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                          <polyline points="14 2 14 8 20 8" />
                        </svg>
                      </span>
                      <span className="metric-mini-num">{sample.fileCount}</span>
                      <span className="metric-mini-label">File Operations</span>
                    </div>

                    <div className="metric-mini-box">
                      <span className="metric-mini-icon">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <rect x="3" y="3" width="7" height="7" />
                          <rect x="14" y="3" width="7" height="7" />
                          <rect x="14" y="14" width="7" height="7" />
                          <rect x="3" y="14" width="7" height="7" />
                        </svg>
                      </span>
                      <span className="metric-mini-num">{sample.registryCount}</span>
                      <span className="metric-mini-label">Registry Modifications</span>
                    </div>
                  </div>
                </div>

                {/* MITRE ATT&CK Techniques */}
                <div className="dashboard-card">
                  <div className="card-header-row" style={{ marginBottom: '0.5rem' }}>
                    <div className="card-title-with-desc">
                      <span className="card-icon-lead">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="18" cy="5" r="3" />
                          <circle cx="6" cy="12" r="3" />
                          <circle cx="18" cy="19" r="3" />
                          <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
                          <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
                        </svg>
                      </span>
                      <div className="title-desc-wrap">
                        <span className="card-title-text">MITRE ATT&amp;CK Techniques</span>
                        <span className="card-desc-sub">Identified techniques based on observed behavior.</span>
                      </div>
                    </div>

                    <button
                      type="button"
                      className="btn-card-viewall"
                      onClick={() => setActiveTab('MITRE ATT&CK')}
                    >
                      <span>View All ({sample.techniqueCount})</span>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <line x1="5" y1="12" x2="19" y2="12" />
                        <polyline points="12 5 19 12 12 19" />
                      </svg>
                    </button>
                  </div>

                  <div className="mitre-techniques-list">
                    {mitrePreview.length > 0 ? (
                      mitrePreview.map((item, idx) => (
                        <div className="mitre-item-row" key={idx}>
                          <div className="mitre-left-id">
                            <span className="mitre-side-indicator indicator-red"></span>
                            <span className="mitre-id-code">{item.technique_id || item.TechniqueID || 'N/A'}</span>
                            <span className="mitre-name-text">{item.name || item.Name || 'Unclassified Technique'}</span>
                          </div>
                          <span className="badge-severity-high">{item.tactic || item.Tactic || 'Detected'}</span>
                        </div>
                      ))
                    ) : (
                      <div style={{ padding: '1.5rem', textAlign: 'center', color: '#727a85', fontSize: '0.85rem' }}>
                        No MITRE ATT&amp;CK techniques matched.
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Row 3: Process Tree | Network Activity */}
              <div className="overview-bottom-grid">
                {/* Process Tree */}
                <div className="dashboard-card">
                  <div className="card-header-row" style={{ marginBottom: '0.5rem' }}>
                    <div className="card-title-with-desc">
                      <span className="card-icon-lead">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <rect x="3" y="3" width="6" height="5" rx="1" />
                          <rect x="15" y="16" width="6" height="5" rx="1" />
                          <rect x="3" y="16" width="6" height="5" rx="1" />
                          <path d="M6 8v5a1 1 0 0 0 1 1h11a1 1 0 0 0 1-1v-2" />
                        </svg>
                      </span>
                      <div className="title-desc-wrap">
                        <span className="card-title-text">Process Tree</span>
                        <span className="card-desc-sub">Hierarchical view of spawned processes.</span>
                      </div>
                    </div>

                    <button
                      type="button"
                      className="btn-card-viewall"
                      onClick={() => setActiveTab('Processes')}
                    >
                      <span>View Full Tree</span>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <line x1="5" y1="12" x2="19" y2="12" />
                        <polyline points="12 5 19 12 12 19" />
                      </svg>
                    </button>
                  </div>

                  <div className="process-tree-body">
                    {rootProcesses.length > 0 ? (
                      renderProcessTreeNodes(rootProcesses)
                    ) : (
                      <div style={{ padding: '1.5rem', textAlign: 'center', color: '#727a85', fontSize: '0.85rem' }}>
                        No process tree telemetry recorded.
                      </div>
                    )}
                  </div>
                </div>

                {/* Network Activity Table */}
                <div className="dashboard-card">
                  <div className="card-header-row" style={{ marginBottom: '0.5rem' }}>
                    <div className="card-title-with-desc">
                      <span className="card-icon-lead">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="12" cy="12" r="10" />
                          <line x1="2" y1="12" x2="22" y2="12" />
                          <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                        </svg>
                      </span>
                      <div className="title-desc-wrap">
                        <span className="card-title-text">Network Activity</span>
                        <span className="card-desc-sub">External connections made during execution.</span>
                      </div>
                    </div>

                    <button
                      type="button"
                      className="btn-card-viewall"
                      onClick={() => setActiveTab('Network')}
                    >
                      <span>View All ({sample.networkCount})</span>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <line x1="5" y1="12" x2="19" y2="12" />
                        <polyline points="12 5 19 12 12 19" />
                      </svg>
                    </button>
                  </div>

                  <div className="network-table-card">
                    {networkPreview.length > 0 ? (
                      <table className="network-activity-table">
                        <thead>
                          <tr>
                            <th>Type</th>
                            <th>Destination IP</th>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>Count</th>
                          </tr>
                        </thead>
                        <tbody>
                          {networkPreview.map((net, idx) => (
                            <tr key={idx}>
                              <td className="table-code-text">{net.Type || net.type || 'Connection'}</td>
                              <td className="table-domain-bold">{net.DestIP || net.dest_ip || 'N/A'}</td>
                              <td>{net.DestPort || net.dest_port || 'N/A'}</td>
                              <td>{net.Protocol || net.protocol || 'TCP'}</td>
                              <td>{net.Count || net.count || 1}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    ) : (
                      <div style={{ padding: '2rem 1.5rem', textAlign: 'center', color: '#727a85', fontSize: '0.85rem' }}>
                        No network activity detected during execution.
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </>
          )}

          {/* ===================== BEHAVIOR TAB CONTENT ===================== */}
          {activeTab === 'Behavior' && (
            <div className="behavior-tab-content">
              {/* 1. Behavior Timeline Card */}
              <div className="dashboard-card behavior-timeline-card">
                <div className="card-header-row">
                  <div className="card-title-with-desc">
                    <span className="card-icon-lead">
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="12" cy="12" r="10" />
                        <polyline points="12 6 12 12 16 14" />
                      </svg>
                    </span>
                    <div className="title-desc-wrap">
                      <span className="card-title-text">Behavior Timeline</span>
                      <span className="card-desc-sub">Key actions observed during execution, in chronological order.</span>
                    </div>
                  </div>

                  <div className="timeline-filter-select-wrap">
                    <div
                      className="timeline-severity-dropdown"
                      onClick={() => setIsTimelineFilterOpen(!isTimelineFilterOpen)}
                    >
                      <span>{timelineSeverityFilter}</span>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="6 9 12 15 18 9" />
                      </svg>
                    </div>

                    {isTimelineFilterOpen && (
                      <div className="timeline-dropdown-menu">
                        {['All severities', 'High', 'Medium', 'Low'].map((sev) => (
                          <button
                            key={sev}
                            type="button"
                            className={`dropdown-item-btn ${timelineSeverityFilter === sev ? 'selected' : ''}`}
                            onClick={() => {
                              setTimelineSeverityFilter(sev)
                              setIsTimelineFilterOpen(false)
                            }}
                          >
                            {sev}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                {/* Timeline Items List */}
                <div className="behavior-timeline-list">
                  {filteredTimelineEvents.length > 0 ? (
                    filteredTimelineEvents.map((ev, idx) => (
                      <div className="timeline-row-item" key={ev.id || idx}>
                        <div className="timeline-indicator-col">
                          <span className={`timeline-dot ${ev.dotClass}`}></span>
                          {idx < filteredTimelineEvents.length - 1 && (
                            <span className="timeline-vert-line"></span>
                          )}
                        </div>
                        <span className="timeline-timestamp">{ev.timestamp}</span>
                        <div className="timeline-action-icon">
                          {ev.iconType === 'process' && (
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                              <circle cx="12" cy="12" r="3" />
                              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
                            </svg>
                          )}
                          {ev.iconType === 'technique' && (
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                              <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
                              <line x1="12" y1="9" x2="12" y2="13" />
                              <line x1="12" y1="17" x2="12.01" y2="17" />
                            </svg>
                          )}
                          {ev.iconType === 'network' && (
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                              <circle cx="12" cy="12" r="10" />
                              <line x1="2" y1="12" x2="22" y2="12" />
                              <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                            </svg>
                          )}
                          {ev.iconType === 'registry' && (
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                              <rect x="3" y="3" width="7" height="7" />
                              <rect x="14" y="3" width="7" height="7" />
                              <rect x="14" y="14" width="7" height="7" />
                              <rect x="3" y="14" width="7" height="7" />
                            </svg>
                          )}
                          {ev.iconType === 'file' && (
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                              <polyline points="14 2 14 8 20 8" />
                            </svg>
                          )}
                        </div>
                        <div className="timeline-details-col">
                          <div className="timeline-title-line">
                            <span className="timeline-event-name">{ev.name}</span>
                            <span className="timeline-event-extra">{ev.extra}</span>
                          </div>
                          {ev.code && (
                            <span className="timeline-code-quote">{ev.code}</span>
                          )}
                        </div>
                        <div className="timeline-right-pill">
                          <span className={ev.pillClass}>{ev.severity}</span>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div style={{ padding: '3.5rem 1rem', textAlign: 'center', color: '#727a85', fontSize: '0.88rem' }}>
                      No behavioral timeline events recorded for this sample.
                    </div>
                  )}
                </div>
              </div>

              {/* 2. Bottom Row: Notable Behaviors (Left) + Behavior Categories (Right) */}
              <div className="behavior-bottom-grid">
                {/* Notable Behaviors Card */}
                <div className="dashboard-card">
                  <div className="card-header-row" style={{ marginBottom: '0.75rem' }}>
                    <div className="card-title-with-desc">
                      <span className="card-icon-lead">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
                          <line x1="12" y1="9" x2="12" y2="13" />
                          <line x1="12" y1="17" x2="12.01" y2="17" />
                        </svg>
                      </span>
                      <div className="title-desc-wrap">
                        <span className="card-title-text">Notable Behaviors</span>
                        <span className="card-desc-sub">Important behavioral indicators identified during analysis.</span>
                      </div>
                    </div>
                  </div>

                  <div className="notable-behaviors-table-wrap">
                    {notableBehaviors.length > 0 ? (
                      <table className="notable-behaviors-table">
                        <thead>
                          <tr>
                            <th>Behavior</th>
                            <th>Evidence</th>
                            <th>Severity</th>
                          </tr>
                        </thead>
                        <tbody>
                          {notableBehaviors.map((item, idx) => (
                            <tr key={idx}>
                              <td>
                                <div className="notable-behavior-cell">
                                  <span className="notable-name-strong">{item.name}</span>
                                  <span className="notable-sub-text">{item.sub}</span>
                                </div>
                              </td>
                              <td className="notable-evidence-cell">
                                {item.evidence}
                              </td>
                              <td className="notable-sev-cell">
                                <span className={item.badgeClass}>{item.severity}</span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    ) : (
                      <div style={{ padding: '2.5rem 1rem', textAlign: 'center', color: '#727a85', fontSize: '0.86rem' }}>
                        No notable threat behaviors identified.
                      </div>
                    )}
                  </div>
                </div>

                {/* Behavior Categories Distribution Card */}
                <div className="dashboard-card">
                  <div className="card-header-row" style={{ marginBottom: '1.25rem' }}>
                    <div className="card-title-with-desc">
                      <span className="card-icon-lead">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <line x1="18" y1="20" x2="18" y2="10" />
                          <line x1="12" y1="20" x2="12" y2="4" />
                          <line x1="6" y1="20" x2="6" y2="14" />
                        </svg>
                      </span>
                      <div className="title-desc-wrap">
                        <span className="card-title-text">Behavior Categories</span>
                        <span className="card-desc-sub">Distribution of observed behaviors.</span>
                      </div>
                    </div>
                  </div>

                  <div className="behavior-categories-list">
                    {displayBehaviorCategories.length > 0 ? (
                      displayBehaviorCategories.map((cat, idx) => {
                        const pct = Math.max(8, Math.min(100, Math.round((cat.count / maxCategoryCount) * 100)))
                        return (
                          <div className="category-bar-row" key={idx}>
                            <span className="category-name">{cat.name}</span>
                            <div className="category-track">
                              <div
                                className={`category-fill ${cat.colorClass}`}
                                style={{ width: `${pct}%` }}
                              ></div>
                            </div>
                            <span className="category-count">{cat.count}</span>
                          </div>
                        )
                      })
                    ) : (
                      <div style={{ padding: '2.5rem 1rem', textAlign: 'center', color: '#727a85', fontSize: '0.86rem' }}>
                        No behavioral activity categories recorded.
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ===================== PROCESSES TAB CONTENT ===================== */}
          {activeTab === 'Processes' && (
            <div className="processes-tab-content">
              {/* 1. Process Tree Table Card */}
              <div className="dashboard-card process-tree-main-card">
                <div className="card-header-row process-header-controls">
                  <div className="card-title-with-desc">
                    <span className="card-icon-lead">
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <rect x="3" y="3" width="6" height="5" rx="1" />
                        <rect x="15" y="16" width="6" height="5" rx="1" />
                        <rect x="3" y="16" width="6" height="5" rx="1" />
                        <path d="M6 8v5a1 1 0 0 0 1 1h11a1 1 0 0 0 1-1v-2" />
                      </svg>
                    </span>
                    <div className="title-desc-wrap">
                      <span className="card-title-text">Process Tree</span>
                      <span className="card-desc-sub">Hierarchical view of all spawned processes.</span>
                    </div>
                  </div>

                  <div className="process-header-right-tools">
                    {/* Search processes */}
                    <div className="process-search-wrapper">
                      <span className="search-icon">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="11" cy="11" r="8" />
                          <line x1="21" y1="21" x2="16.65" y2="16.65" />
                        </svg>
                      </span>
                      <input
                        type="text"
                        placeholder="Search processes..."
                        className="process-search-input"
                        value={processSearchQuery}
                        onChange={(e) => setProcessSearchQuery(e.target.value)}
                      />
                    </div>

                    {/* Filter All Processes */}
                    <div className="process-filter-dropdown-wrapper">
                      <div
                        className="process-filter-dropdown"
                        onClick={() => setIsProcessFilterOpen(!isProcessFilterOpen)}
                      >
                        <span>{processFilter}</span>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                          <polyline points="6 9 12 15 18 9" />
                        </svg>
                      </div>

                      {isProcessFilterOpen && (
                        <div className="process-dropdown-menu">
                          {['All Processes', 'High / Suspicious Risk', 'Root Processes', 'Child Processes'].map((filterOpt) => (
                            <button
                              key={filterOpt}
                              type="button"
                              className={`dropdown-item-btn ${processFilter === filterOpt ? 'selected' : ''}`}
                              onClick={() => {
                                setProcessFilter(filterOpt)
                                setIsProcessFilterOpen(false)
                              }}
                            >
                              {filterOpt}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Expand / Show All */}
                    <button
                      type="button"
                      className="btn-expand-all"
                      onClick={() => {
                        setProcessSearchQuery('')
                        setProcessFilter('All Processes')
                      }}
                      title="Reset filters and show all processes"
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="15 3 21 3 21 9" />
                        <polyline points="9 21 3 21 3 15" />
                        <line x1="21" y1="3" x2="14" y2="10" />
                        <line x1="3" y1="21" x2="10" y2="14" />
                      </svg>
                      <span>Show All</span>
                    </button>
                  </div>
                </div>

                {/* Process Tree Data Table */}
                <div className="process-table-wrapper">
                  {filteredProcesses.length > 0 ? (
                    <table className="process-tree-table">
                      <thead>
                        <tr>
                          <th>Process Name</th>
                          <th>PID</th>
                          <th>PPID</th>
                          <th>Image Path</th>
                          <th>Command Line</th>
                          <th>Start Time</th>
                          <th>Status</th>
                          <th>Risk</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredProcesses.map((proc) => {
                          const isSelected = activeSelectedProcess.PID === proc.PID
                          const indentClass = `level-${Math.min(proc.level, 4)}`
                          return (
                            <tr
                              key={proc.PID}
                              className={isSelected ? 'row-selected-process' : ''}
                              onClick={() => setSelectedProcessPid(proc.PID)}
                              style={{ cursor: 'pointer' }}
                            >
                              <td>
                                <div className={`proc-tree-name-cell ${indentClass}`}>
                                  <span className="tree-arrow">
                                    {proc.hasChildren ? '▼' : '•'}
                                  </span>
                                  <span className="proc-icon">
                                    {proc.hasChildren ? '📁' : '📄'}
                                  </span>
                                  <span className="proc-name-text">{proc.name}</span>
                                </div>
                              </td>
                              <td>{proc.PID}</td>
                              <td>{proc.PPID}</td>
                              <td className="proc-path-text" title={proc.Image}>
                                {proc.Image}
                              </td>
                              <td className="proc-cmd-text" title={proc.Command}>
                                {proc.Command}
                              </td>
                              <td>{proc.Time ? proc.Time.split('T').pop().substring(0, 8) : '-'}</td>
                              <td>
                                <span className={proc.statusBadgeClass}>
                                  {proc.status}
                                </span>
                              </td>
                              <td>
                                <span className={proc.riskBadgeClass}>
                                  {proc.risk}
                                </span>
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  ) : (
                    <div style={{ padding: '3.5rem 1rem', textAlign: 'center', color: '#727a85', fontSize: '0.88rem' }}>
                      No process execution telemetry recorded.
                    </div>
                  )}
                </div>
              </div>

              {/* 2. Process Inspection Card */}
              <div className="dashboard-card proc-inspection-card">
                <div className="proc-detail-heading-row">
                  <div className="proc-detail-file-icon">
                    <svg width="22" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                      <polyline points="14 2 14 8 20 8" />
                    </svg>
                  </div>
                  <span className="proc-detail-title">{activeSelectedProcess.name}</span>
                  <span className="proc-detail-pid-tag">(PID {activeSelectedProcess.PID})</span>
                  <span className={activeSelectedProcess.risk === 'High' ? 'badge-malicious-pill' : activeSelectedProcess.risk === 'Suspicious' ? 'badge-suspicious-pill' : 'badge-clean-pill'}>
                    {activeSelectedProcess.risk === 'High' ? 'Malicious' : activeSelectedProcess.risk === 'Suspicious' ? 'Suspicious' : 'Clean'}
                  </span>
                </div>

                <div className="proc-metadata-kv-list">
                  <div className="proc-kv-row">
                    <span className="proc-kv-key">Image Path</span>
                    <span className="proc-kv-val mono-path">{activeSelectedProcess.Image || 'Not available'}</span>
                  </div>
                  <div className="proc-kv-row">
                    <span className="proc-kv-key">Command Line</span>
                    <span className="proc-kv-val mono-path">{activeSelectedProcess.Command || 'Not available'}</span>
                  </div>
                  <div className="proc-kv-row">
                    <span className="proc-kv-key">Parent Process</span>
                    <span className="proc-kv-val">{activeSelectedProcess.parentName || `PID ${activeSelectedProcess.PPID}`}</span>
                  </div>
                  <div className="proc-kv-row">
                    <span className="proc-kv-key">Start Time</span>
                    <span className="proc-kv-val">{activeSelectedProcess.Time || sample.submitted || 'Not available'}</span>
                  </div>
                  <div className="proc-kv-row">
                    <span className="proc-kv-key">Status</span>
                    <span className="proc-kv-val">{activeSelectedProcess.status || 'Exited'}</span>
                  </div>
                  <div className="proc-kv-row">
                    <span className="proc-kv-key">Integrity Level</span>
                    <span className="proc-kv-val">{activeSelectedProcess.risk === 'High' ? 'High' : 'Medium'}</span>
                  </div>
                </div>
              </div>

              {/* 3. Process Characteristics Card */}
              <div className="dashboard-card proc-chars-card">
                <div className="proc-chars-header">
                  <span className="proc-chars-icon">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <circle cx="12" cy="12" r="3" />
                      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
                    </svg>
                  </span>
                  <div className="title-desc-wrap">
                    <span className="proc-chars-title">Process Characteristics</span>
                    <span className="card-desc-sub">File properties, signature verification, and hash identifiers.</span>
                  </div>
                </div>

                <div className="proc-chars-kv-list">
                  <div className="proc-kv-row">
                    <span className="proc-kv-key">Signed</span>
                    <span className="proc-kv-val signed-no">No</span>
                  </div>
                  <div className="proc-kv-row">
                    <span className="proc-kv-key">Publisher</span>
                    <span className="proc-kv-val">Not available</span>
                  </div>
                  <div className="proc-kv-row">
                    <span className="proc-kv-key">File Version</span>
                    <span className="proc-kv-val">Not available</span>
                  </div>
                  <div className="proc-kv-row">
                    <span className="proc-kv-key">Subsystem</span>
                    <span className="proc-kv-val">{sample.fileType || 'Windows GUI'}</span>
                  </div>
                  <div className="proc-kv-row">
                    <span className="proc-kv-key">Bitness</span>
                    <span className="proc-kv-val">{sample.fileType?.includes('32') ? '32-bit' : '64-bit'}</span>
                  </div>
                  <div className="proc-kv-row">
                    <span className="proc-kv-key">MD5</span>
                    <span className="proc-kv-val mono-hash">Not available</span>
                  </div>
                  <div className="proc-kv-row">
                    <span className="proc-kv-key">SHA256</span>
                    <div className="proc-sha256-wrap">
                      <span className="proc-kv-val mono-hash truncate-hash" title={sample.sha256}>
                        {sample.sha256}
                      </span>
                      {sample.sha256 && sample.sha256 !== 'Not available' && (
                        <button
                          type="button"
                          className="btn-copy-hash"
                          title={copiedHash ? 'Copied!' : 'Copy SHA256'}
                          onClick={() => handleCopyHash(sample.sha256)}
                        >
                          {copiedHash ? (
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#10B981" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                              <polyline points="20 6 9 17 4 12" />
                            </svg>
                          ) : (
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                              <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                            </svg>
                          )}
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ===================== FILE SYSTEM TAB CONTENT ===================== */}
          {activeTab === 'File System' && (
            <div className="filesystem-tab-layout">
              {/* Left Column: File System Activity Card */}
              <div className="dashboard-card filesystem-main-card">
                {/* Header row */}
                <div className="fs-header-row">
                  <div className="fs-title-with-desc">
                    <span className="fs-icon-lead">
                      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z"/>
                      </svg>
                    </span>
                    <div className="fs-title-text-wrap">
                      <span className="fs-card-title">File System Activity</span>
                      <span className="fs-card-subtitle">Files and directories created, modified, or deleted during execution.</span>
                    </div>
                  </div>

                  {/* Right Header Tools & Legend */}
                  <div className="fs-header-right-tools">
                    <div className="fs-search-box">
                      <span className="fs-search-icon">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="11" cy="11" r="8" />
                          <line x1="21" y1="21" x2="16.65" y2="16.65" />
                        </svg>
                      </span>
                      <input
                        type="text"
                        placeholder="Search files or paths..."
                        className="fs-search-input"
                        value={fsSearchQuery}
                        onChange={(e) => {
                          setFsSearchQuery(e.target.value)
                          setFsPage(1)
                        }}
                      />
                    </div>

                    <div className="fs-action-filter-dropdown-wrap" style={{ position: 'relative' }}>
                      <div
                        className="fs-action-filter-dropdown"
                        onClick={() => setIsFsFilterOpen(!isFsFilterOpen)}
                      >
                        <span>{fsActionFilter}</span>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                          <polyline points="6 9 12 15 18 9" />
                        </svg>
                      </div>

                      {isFsFilterOpen && (
                        <div className="process-dropdown-menu" style={{ position: 'absolute', top: '100%', right: 0, zIndex: 25 }}>
                          {['All Actions', 'Created', 'Modified', 'Deleted', 'Read'].map((act) => (
                            <button
                              key={act}
                              type="button"
                              className={`dropdown-item-btn ${fsActionFilter === act ? 'selected' : ''}`}
                              onClick={() => {
                                setFsActionFilter(act)
                                setIsFsFilterOpen(false)
                                setFsPage(1)
                              }}
                            >
                              {act}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Dot Legend */}
                    <div className="fs-legend-dots">
                      <div className="fs-legend-item">
                        <span className="fs-dot fs-dot-created"></span>
                        <span>Created</span>
                      </div>
                      <div className="fs-legend-item">
                        <span className="fs-dot fs-dot-modified"></span>
                        <span>Modified</span>
                      </div>
                      <div className="fs-legend-item">
                        <span className="fs-dot fs-dot-deleted"></span>
                        <span>Deleted</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Table */}
                <div className="fs-table-wrap">
                  <table className="fs-activity-table">
                    <thead>
                      <tr>
                        <th>Path</th>
                        <th>Action</th>
                        <th>Size</th>
                        <th>Timestamp</th>
                        <th style={{ width: '40px' }}></th>
                      </tr>
                    </thead>
                    <tbody>
                      {paginatedFiles.length > 0 ? (
                        paginatedFiles.map((file) => (
                          <tr
                            key={file.id}
                            className={activeSelectedFile?.id === file.id ? 'row-selected-fs' : ''}
                            onClick={() => setSelectedFileIndex(file.id)}
                          >
                            <td>
                              <div className="fs-path-cell">
                                <span className={`fs-file-icon ${file.isFolder ? 'fs-icon-folder' : 'fs-icon-doc'}`}>
                                  {file.isFolder ? '📁' : '📄'}
                                </span>
                                <span className={`fs-path-text ${activeSelectedFile?.id === file.id ? 'font-medium' : ''}`}>
                                  {file.path}
                                </span>
                              </div>
                            </td>
                            <td><span className={file.badgeClass}>{file.action}</span></td>
                            <td className={file.size === '-' ? 'fs-dim-text' : ''}>{file.size}</td>
                            <td>{file.time}</td>
                            <td className="fs-chevron-cell">
                              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <polyline points="9 18 15 12 9 6" />
                              </svg>
                            </td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan="5" style={{ textAlign: 'center', padding: '3rem 1rem', color: '#6B7280' }}>
                            <p style={{ fontWeight: 600, fontSize: '0.9rem', marginBottom: '0.25rem' }}>No file system activity found</p>
                            <p style={{ fontSize: '0.8rem' }}>No file operations were recorded during this execution session.</p>
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>

                {/* Pagination footer */}
                <div className="fs-pagination-footer">
                  <span className="fs-pagination-info">
                    Showing {filteredFiles.length === 0 ? 0 : (fsPage - 1) * 10 + 1} to {Math.min(fsPage * 10, filteredFiles.length)} of {filteredFiles.length} files
                  </span>
                  <div className="fs-pagination-controls">
                    <button
                      type="button"
                      className="btn-page-arrow"
                      disabled={fsPage <= 1}
                      onClick={() => setFsPage((p) => Math.max(1, p - 1))}
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="15 18 9 12 15 6" />
                      </svg>
                    </button>
                    {Array.from({ length: fsTotalPages }, (_, i) => i + 1).slice(0, 5).map((pageNo) => (
                      <button
                        key={pageNo}
                        type="button"
                        className={`btn-page-number ${fsPage === pageNo ? 'active' : ''}`}
                        onClick={() => setFsPage(pageNo)}
                      >
                        {pageNo}
                      </button>
                    ))}
                    <button
                      type="button"
                      className="btn-page-arrow"
                      disabled={fsPage >= fsTotalPages}
                      onClick={() => setFsPage((p) => Math.min(fsTotalPages, p + 1))}
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="9 18 15 12 9 6" />
                      </svg>
                    </button>
                  </div>
                </div>
              </div>

              {/* Right Column: File Details Inspection Panel */}
              <div className="dashboard-card fs-detail-panel">
                {activeSelectedFile ? (
                  <>
                    <div className="fs-detail-header">
                      <div className="fs-detail-file-title-group">
                        <div className="fs-detail-icon">
                          <svg width="22" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                            <polyline points="14 2 14 8 20 8" />
                          </svg>
                        </div>
                        <div>
                          <h4 className="fs-detail-filename">{activeSelectedFile.fileName}</h4>
                          <p className="fs-detail-filepath">{activeSelectedFile.path}</p>
                        </div>
                      </div>
                      <button
                        type="button"
                        className="btn-close-fs-detail"
                        title="Close details"
                        onClick={() => setSelectedFileIndex(null)}
                      >
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <line x1="18" y1="6" x2="6" y2="18" />
                          <line x1="6" y1="6" x2="18" y2="18" />
                        </svg>
                      </button>
                    </div>

                    {/* 3 mini stats columns */}
                    <div className="fs-detail-stats-row">
                      <div className="fs-detail-stat-col">
                        <span className="fs-stat-label">Action</span>
                        <div><span className={activeSelectedFile.badgeClass}>{activeSelectedFile.action}</span></div>
                      </div>
                      <div className="fs-detail-stat-col">
                        <span className="fs-stat-label">Size</span>
                        <span className="fs-stat-val">{activeSelectedFile.size}</span>
                      </div>
                      <div className="fs-detail-stat-col">
                        <span className="fs-stat-label">Timestamp</span>
                        <span className="fs-stat-val">{activeSelectedFile.time}</span>
                      </div>
                    </div>

                    {/* Horizontal 2-Column Body */}
                    <div className="fs-detail-horizontal-body">
                      {/* Left Column: File Information */}
                      <div className="fs-detail-body-left">
                        <h5 className="fs-section-subtitle">File Information</h5>
                        <div className="fs-kv-list">
                          <div className="fs-kv-row">
                            <span className="fs-kv-key">Type</span>
                            <span className="fs-kv-val">{activeSelectedFile.extType}</span>
                          </div>
                          <div className="fs-kv-row">
                            <span className="fs-kv-key">SHA256</span>
                            <div className="fs-hash-copy-wrap">
                              <span className="fs-kv-val mono-hash truncate-hash" title={sample.sha256}>
                                {sample.sha256 !== 'Not available' ? sample.sha256 : 'Not available'}
                              </span>
                              {sample.sha256 !== 'Not available' && (
                                <button
                                  type="button"
                                  className="btn-copy-hash"
                                  title="Copy SHA256"
                                  onClick={() => handleCopyHash(sample.sha256)}
                                >
                                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                                  </svg>
                                </button>
                              )}
                            </div>
                          </div>
                          <div className="fs-kv-row">
                            <span className="fs-kv-key">MD5</span>
                            <span className="fs-kv-val mono-hash">Not available</span>
                          </div>
                          <div className="fs-kv-row">
                            <span className="fs-kv-key">Process</span>
                            <span className="fs-kv-val">
                              {activeSelectedFile.image ? `${activeSelectedFile.image} (PID ${activeSelectedFile.pid})` : 'Not available'}
                            </span>
                          </div>
                          <div className="fs-kv-row">
                            <span className="fs-kv-key">Activity Count</span>
                            <span className="fs-kv-val">{activeSelectedFile.count} I/O event(s)</span>
                          </div>
                        </div>
                      </div>

                      {/* Right Column: Classification & Indicators */}
                      <div className="fs-detail-body-right">
                        <div className="fs-section-block fs-classification-row">
                          <span className="fs-classification-label">Classification</span>
                          <span className={activeSelectedFile.isSuspicious ? 'badge-severity-suspicious' : 'badge-severity-low'}>
                            {activeSelectedFile.isSuspicious ? 'Suspicious' : 'Normal'}
                          </span>
                        </div>

                        <div className="fs-section-block">
                          <h5 className="fs-section-subtitle">File Indicators</h5>
                          {activeSelectedFile.isSuspicious ? (
                            <div className="fs-yara-pill-row">
                              <span className="fs-yara-name">Generic_Payload_Artifact</span>
                              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                <polyline points="9 18 15 12 9 6" />
                              </svg>
                            </div>
                          ) : (
                            <span style={{ fontSize: '0.8rem', color: '#6B7280' }}>No threat signatures matched</span>
                          )}
                        </div>
                      </div>
                    </div>
                  </>
                ) : (
                  <div style={{ textAlign: 'center', padding: '3.5rem 1rem', color: '#6B7280' }}>
                    <p style={{ fontWeight: 600, fontSize: '0.9rem', marginBottom: '0.25rem' }}>No file selected</p>
                    <p style={{ fontSize: '0.8rem' }}>Click any row in the activity table to inspect file details.</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ===================== NETWORK TAB CONTENT ===================== */}
          {activeTab === 'Network' && (
            <div className="network-tab-layout">
              {/* Top Stat Cards Row */}
              <div className="network-stats-strip">
                <div className="dashboard-card net-stat-box">
                  <div className="net-stat-icon-wrap icon-blue-bg">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <circle cx="12" cy="12" r="10" />
                      <line x1="2" y1="12" x2="22" y2="12" />
                      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                    </svg>
                  </div>
                  <div className="net-stat-info">
                    <span className="net-stat-label">Total Connections</span>
                    <span className="net-stat-val">{totalNetConnections}</span>
                  </div>
                </div>

                <div className="dashboard-card net-stat-box">
                  <div className="net-stat-icon-wrap icon-blue-bg">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <circle cx="18" cy="5" r="3" />
                      <circle cx="6" cy="12" r="3" />
                      <circle cx="18" cy="19" r="3" />
                      <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
                      <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
                    </svg>
                  </div>
                  <div className="net-stat-info">
                    <span className="net-stat-label">Unique Domains</span>
                    <span className="net-stat-val">{uniqueNetDomains}</span>
                  </div>
                </div>

                <div className="dashboard-card net-stat-box">
                  <div className="net-stat-icon-wrap icon-purple-bg">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
                      <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
                      <line x1="6" y1="6" x2="6.01" y2="6" />
                      <line x1="6" y1="18" x2="6.01" y2="18" />
                    </svg>
                  </div>
                  <div className="net-stat-info">
                    <span className="net-stat-label">Unique IPs</span>
                    <span className="net-stat-val">{uniqueNetIps}</span>
                  </div>
                </div>

                <div className="dashboard-card net-stat-box">
                  <div className="net-stat-icon-wrap icon-red-bg">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                      <line x1="12" y1="19" x2="12" y2="5" />
                      <polyline points="5 12 12 5 19 12" />
                    </svg>
                  </div>
                  <div className="net-stat-info">
                    <span className="net-stat-label">Data Sent</span>
                    <span className="net-stat-val">{formatBytes(totalSentBytes)}</span>
                  </div>
                </div>

                <div className="dashboard-card net-stat-box">
                  <div className="net-stat-icon-wrap icon-green-bg">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                      <line x1="12" y1="5" x2="12" y2="19" />
                      <polyline points="19 12 12 19 5 12" />
                    </svg>
                  </div>
                  <div className="net-stat-info">
                    <span className="net-stat-label">Data Received</span>
                    <span className="net-stat-val">{formatBytes(totalRecvBytes)}</span>
                  </div>
                </div>
              </div>

              {/* Main Content Split: Left Table vs Right Sidebar Widgets */}
              <div className="net-split-grid">
                {/* Left: Network Connections Table Card */}
                <div className="dashboard-card net-main-table-card">
                  <div className="net-table-header-row">
                    <div className="net-title-with-desc">
                      <span className="net-lead-icon">
                        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="12" cy="12" r="10" />
                          <line x1="2" y1="12" x2="22" y2="12" />
                          <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                        </svg>
                      </span>
                      <div className="net-title-text-wrap">
                        <span className="net-card-title">Network Connections</span>
                        <span className="net-card-subtitle">All outbound and inbound network activity.</span>
                      </div>
                    </div>

                    <div className="net-table-header-tools">
                      <div className="net-search-box">
                        <span className="net-search-icon">
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <circle cx="11" cy="11" r="8" />
                            <line x1="21" y1="21" x2="16.65" y2="16.65" />
                          </svg>
                        </span>
                        <input
                          type="text"
                          placeholder="Search by domain, IP, or port..."
                          className="net-search-input"
                          value={netSearchQuery}
                          onChange={(e) => {
                            setNetSearchQuery(e.target.value)
                            setNetPage(1)
                          }}
                        />
                      </div>

                      <div className="net-filter-dropdown-wrap" style={{ position: 'relative' }}>
                        <div
                          className="net-filter-dropdown"
                          onClick={() => setIsNetFilterOpen(!isNetFilterOpen)}
                        >
                          <span>{netProtocolFilter}</span>
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                            <polyline points="6 9 12 15 18 9" />
                          </svg>
                        </div>

                        {isNetFilterOpen && (
                          <div className="process-dropdown-menu" style={{ position: 'absolute', top: '100%', right: 0, zIndex: 25 }}>
                            {['All Protocols', 'TCP', 'UDP', 'HTTPS', 'HTTP', 'DNS'].map((proto) => (
                              <button
                                key={proto}
                                type="button"
                                className={`dropdown-item-btn ${netProtocolFilter === proto ? 'selected' : ''}`}
                                onClick={() => {
                                  setNetProtocolFilter(proto)
                                  setIsNetFilterOpen(false)
                                  setNetPage(1)
                                }}
                              >
                                {proto}
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Table */}
                  <div className="net-table-wrapper">
                    <table className="net-connections-table">
                      <thead>
                        <tr>
                          <th>Time</th>
                          <th>Direction</th>
                          <th>Domain / IP</th>
                          <th>Port</th>
                          <th>Protocol</th>
                          <th>Bytes Sent</th>
                          <th>Bytes Received</th>
                          <th>Reputation</th>
                        </tr>
                      </thead>
                      <tbody>
                        {paginatedNetwork.length > 0 ? (
                          paginatedNetwork.map((conn) => (
                            <tr key={conn.id}>
                              <td>{conn.time}</td>
                              <td>
                                {conn.isInbound ? (
                                  <span className="dir-arrow arrow-down" title="Inbound">↓</span>
                                ) : (
                                  <span className="dir-arrow arrow-up" title="Outbound">↑</span>
                                )}
                              </td>
                              <td className={`net-target-cell ${conn.target.includes('.') && !conn.target.match(/^\d/) ? 'font-semibold' : 'mono-font'}`}>
                                {conn.target}
                              </td>
                              <td>{conn.destPort}</td>
                              <td>{conn.protocol}</td>
                              <td>{conn.bytesSent}</td>
                              <td>{conn.bytesRecv}</td>
                              <td><span className={conn.repBadgeClass}>{conn.reputation}</span></td>
                            </tr>
                          ))
                        ) : (
                          <tr>
                            <td colSpan="8" style={{ textAlign: 'center', padding: '3rem 1rem', color: '#6B7280' }}>
                              <p style={{ fontWeight: 600, fontSize: '0.9rem', marginBottom: '0.25rem' }}>No network connections observed</p>
                              <p style={{ fontSize: '0.8rem' }}>No inbound or outbound network traffic was recorded.</p>
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>

                  {/* Pagination Footer */}
                  <div className="net-pagination-footer">
                    <span className="net-pagination-info">
                      Showing {filteredNetwork.length === 0 ? 0 : (netPage - 1) * 10 + 1} to {Math.min(netPage * 10, filteredNetwork.length)} of {filteredNetwork.length} connections
                    </span>
                    <div className="net-pagination-controls">
                      <button
                        type="button"
                        className="btn-page-arrow"
                        disabled={netPage <= 1}
                        onClick={() => setNetPage((p) => Math.max(1, p - 1))}
                      >
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <polyline points="15 18 9 12 15 6" />
                        </svg>
                      </button>
                      {Array.from({ length: netTotalPages }, (_, i) => i + 1).slice(0, 5).map((pageNo) => (
                        <button
                          key={pageNo}
                          type="button"
                          className={`btn-page-number ${netPage === pageNo ? 'active' : ''}`}
                          onClick={() => setNetPage(pageNo)}
                        >
                          {pageNo}
                        </button>
                      ))}
                      <button
                        type="button"
                        className="btn-page-arrow"
                        disabled={netPage >= netTotalPages}
                        onClick={() => setNetPage((p) => Math.min(netTotalPages, p + 1))}
                      >
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <polyline points="9 18 15 12 9 6" />
                        </svg>
                      </button>
                    </div>
                  </div>
                </div>

                {/* Right: Widgets Column */}
                <div className="net-widgets-col">
                  {/* Widget 1: Destination Countries / Network Profile */}
                  <div className="dashboard-card net-widget-card">
                    <h4 className="net-widget-title">Destination Overview</h4>
                    <div className="net-world-map-wrapper">
                      <svg viewBox="0 0 380 180" className="net-world-map-svg">
                        <path
                          className="map-continent"
                          d="M 40 45 Q 60 30 85 45 Q 110 50 115 75 Q 90 90 75 75 Z"
                          fill="#E5E9F0"
                        />
                        <path
                          className="map-continent"
                          d="M 85 90 Q 110 95 105 135 Q 90 155 75 120 Z"
                          fill="#E5E9F0"
                        />
                        <path
                          className="map-continent"
                          d="M 160 35 Q 195 25 210 45 Q 200 70 170 65 Z"
                          fill="#E5E9F0"
                        />
                        <path
                          className="map-continent"
                          d="M 165 75 Q 205 75 200 125 Q 180 145 165 110 Z"
                          fill="#E5E9F0"
                        />
                        <path
                          className="map-continent"
                          d="M 220 30 Q 310 20 325 65 Q 290 95 235 75 Z"
                          fill="#E5E9F0"
                        />
                        <path
                          className="map-continent"
                          d="M 280 115 Q 325 110 320 145 Q 285 150 280 125 Z"
                          fill="#E5E9F0"
                        />
                        {totalNetConnections > 0 && (
                          <>
                            <circle cx="82" cy="58" r="12" fill="#EF4444" fillOpacity="0.2" />
                            <circle cx="82" cy="58" r="5" fill="#EF4444" />
                            <circle cx="82" cy="58" r="2" fill="#FFFFFF" />
                            <circle cx="185" cy="48" r="4" fill="#F59E0B" />
                            <circle cx="270" cy="98" r="5" fill="#10B981" />
                          </>
                        )}
                      </svg>
                    </div>

                    <div className="net-countries-legend-grid">
                      <div className="country-legend-item">
                        <span className="legend-dot-country dot-red"></span>
                        <span className="country-name-txt">Remote Endpoints</span>
                        <span className="country-count-txt">{normNetwork.filter(n => !n.destIp.startsWith('127.') && !n.destIp.startsWith('192.168.')).length}</span>
                      </div>
                      <div className="country-legend-item">
                        <span className="legend-dot-country dot-green"></span>
                        <span className="country-name-txt">Local / Internal</span>
                        <span className="country-count-txt">{normNetwork.filter(n => n.destIp.startsWith('127.') || n.destIp.startsWith('192.168.')).length}</span>
                      </div>
                      <div className="country-legend-item">
                        <span className="legend-dot-country dot-orange"></span>
                        <span className="country-name-txt">Unique Destinations</span>
                        <span className="country-count-txt">{uniqueNetIps}</span>
                      </div>
                      <div className="country-legend-item">
                        <span className="legend-dot-country dot-grey"></span>
                        <span className="country-name-txt">Total Flows</span>
                        <span className="country-count-txt">{totalNetConnections}</span>
                      </div>
                    </div>
                  </div>

                  {/* Widget 2: Top Domains */}
                  <div className="dashboard-card net-widget-card">
                    <h4 className="net-widget-title">Top Domains</h4>
                    {topNetDomains.length > 0 ? (
                      <div className="net-progress-bars-list">
                        {topNetDomains.map((item, idx) => {
                          const barColors = ['bg-red', 'bg-orange', 'bg-yellow', 'bg-teal', 'bg-grey']
                          const pct = Math.round((item.count / maxNetDomainCount) * 100)
                          return (
                            <div className="net-progress-row" key={idx}>
                              <span className="prog-item-name" title={item.name}>{item.name}</span>
                              <div className="prog-track">
                                <div className={`prog-bar ${barColors[idx % barColors.length]}`} style={{ width: `${Math.max(15, pct)}%` }}></div>
                              </div>
                              <span className="prog-count-val">{item.count}</span>
                            </div>
                          )
                        })}
                      </div>
                    ) : (
                      <div style={{ padding: '1.75rem 1rem', textAlign: 'center', color: '#6B7280', fontSize: '0.82rem' }}>
                        No domain queries observed.
                      </div>
                    )}
                  </div>

                  {/* Widget 3: Top IP Addresses */}
                  <div className="dashboard-card net-widget-card">
                    <h4 className="net-widget-title">Top IP Addresses</h4>
                    {topNetIps.length > 0 ? (
                      <div className="net-progress-bars-list">
                        {topNetIps.map((item, idx) => {
                          const barColors = ['bg-red', 'bg-orange', 'bg-yellow', 'bg-teal', 'bg-grey']
                          const pct = Math.round((item.count / maxNetIpCount) * 100)
                          return (
                            <div className="net-progress-row" key={idx}>
                              <span className="prog-item-name mono-font">{item.ip}</span>
                              <div className="prog-track">
                                <div className={`prog-bar ${barColors[idx % barColors.length]}`} style={{ width: `${Math.max(15, pct)}%` }}></div>
                              </div>
                              <span className="prog-count-val">{item.count}</span>
                            </div>
                          )
                        })}
                      </div>
                    ) : (
                      <div style={{ padding: '1.75rem 1rem', textAlign: 'center', color: '#6B7280', fontSize: '0.82rem' }}>
                        No IP connections recorded.
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ===================== DNS TAB CONTENT ===================== */}
          {activeTab === 'DNS' && (
            <div className="dns-tab-layout">
              {/* Left Column: DNS Queries Main Card */}
              <div className="dashboard-card dns-main-card">
                <div className="dns-header-row">
                  <div className="dns-title-with-desc">
                    <span className="dns-lead-icon">
                      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="12" cy="12" r="10" />
                        <line x1="2" y1="12" x2="22" y2="12" />
                        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                      </svg>
                    </span>
                    <div className="dns-title-text-wrap">
                      <span className="dns-card-title">DNS Queries</span>
                      <span className="dns-card-subtitle">Domain name queries made during execution.</span>
                    </div>
                  </div>

                  <div className="dns-header-right-tools">
                    <div className="dns-search-box">
                      <span className="dns-search-icon">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="11" cy="11" r="8" />
                          <line x1="21" y1="21" x2="16.65" y2="16.65" />
                        </svg>
                      </span>
                      <input
                        type="text"
                        placeholder="Search domains..."
                        className="dns-search-input"
                        value={dnsSearchQuery}
                        onChange={(e) => {
                          setDnsSearchQuery(e.target.value)
                          setDnsPage(1)
                        }}
                      />
                    </div>

                    <div className="dns-filter-dropdown-wrap" style={{ position: 'relative' }}>
                      <div
                        className="dns-filter-dropdown"
                        onClick={() => setIsDnsFilterOpen(!isDnsFilterOpen)}
                      >
                        <span>{dnsTypeFilter}</span>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                          <polyline points="6 9 12 15 18 9" />
                        </svg>
                      </div>

                      {isDnsFilterOpen && (
                        <div className="process-dropdown-menu" style={{ position: 'absolute', top: '100%', right: 0, zIndex: 25 }}>
                          {['All Types', 'A', 'AAAA', 'CNAME', 'PTR', 'MX'].map((t) => (
                            <button
                              key={t}
                              type="button"
                              className={`dropdown-item-btn ${dnsTypeFilter === t ? 'selected' : ''}`}
                              onClick={() => {
                                setDnsTypeFilter(t)
                                setIsDnsFilterOpen(false)
                                setDnsPage(1)
                              }}
                            >
                              {t}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* Table */}
                <div className="dns-table-wrapper">
                  <table className="dns-queries-table">
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Domain</th>
                        <th>Type</th>
                        <th>Resolved IP</th>
                        <th>Query Count</th>
                        <th>Reputation</th>
                      </tr>
                    </thead>
                    <tbody>
                      {paginatedDns.length > 0 ? (
                        paginatedDns.map((dns) => (
                          <tr key={dns.id}>
                            <td>{dns.time}</td>
                            <td className="dns-domain-bold">{dns.domain}</td>
                            <td className="dns-type-cell">{dns.type}</td>
                            <td className="dns-ip-mono">{dns.resolvedIp}</td>
                            <td>{dns.count}</td>
                            <td><span className={dns.repBadgeClass}>{dns.reputation}</span></td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan="6" style={{ textAlign: 'center', padding: '3rem 1rem', color: '#6B7280' }}>
                            <p style={{ fontWeight: 600, fontSize: '0.9rem', marginBottom: '0.25rem' }}>No DNS queries recorded</p>
                            <p style={{ fontSize: '0.8rem' }}>No domain name resolution activity was observed during this analysis.</p>
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                <div className="dns-pagination-footer">
                  <span className="dns-pagination-info">
                    Showing {filteredDns.length === 0 ? 0 : (dnsPage - 1) * 10 + 1} to {Math.min(dnsPage * 10, filteredDns.length)} of {filteredDns.length} domains
                  </span>
                  <div className="dns-pagination-controls">
                    <button
                      type="button"
                      className="btn-page-arrow"
                      disabled={dnsPage <= 1}
                      onClick={() => setDnsPage((p) => Math.max(1, p - 1))}
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="15 18 9 12 15 6" />
                      </svg>
                    </button>
                    {Array.from({ length: dnsTotalPages }, (_, i) => i + 1).slice(0, 5).map((pageNo) => (
                      <button
                        key={pageNo}
                        type="button"
                        className={`btn-page-number ${dnsPage === pageNo ? 'active' : ''}`}
                        onClick={() => setDnsPage(pageNo)}
                      >
                        {pageNo}
                      </button>
                    ))}
                    <button
                      type="button"
                      className="btn-page-arrow"
                      disabled={dnsPage >= dnsTotalPages}
                      onClick={() => setDnsPage((p) => Math.min(dnsTotalPages, p + 1))}
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="9 18 15 12 9 6" />
                      </svg>
                    </button>
                  </div>
                </div>
              </div>

              {/* Right Column: Widgets */}
              <div className="dns-widgets-col">
                {/* 1. DNS Summary Card */}
                <div className="dashboard-card dns-widget-card">
                  <div className="dns-widget-title-row">
                    <span className="dns-title-icon">
                      <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
                        <line x1="8" y1="21" x2="16" y2="21" />
                        <line x1="12" y1="17" x2="12" y2="21" />
                      </svg>
                    </span>
                    <h4 className="dns-widget-title">DNS Summary</h4>
                  </div>

                  <div className="dns-summary-mini-grid">
                    <div className="dns-mini-box">
                      <div className="dns-mini-icon-wrap icon-blue-bg">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="12" cy="12" r="10" />
                          <line x1="2" y1="12" x2="22" y2="12" />
                          <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                        </svg>
                      </div>
                      <span className="dns-mini-num">{dnsTotalQueries}</span>
                      <span className="dns-mini-txt">Total Queries</span>
                    </div>

                    <div className="dns-mini-box">
                      <div className="dns-mini-icon-wrap icon-blue-bg">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="18" cy="5" r="3" />
                          <circle cx="6" cy="12" r="3" />
                          <circle cx="18" cy="19" r="3" />
                          <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
                          <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
                        </svg>
                      </div>
                      <span className="dns-mini-num">{dnsUniqueDomains}</span>
                      <span className="dns-mini-txt">Unique Domains</span>
                    </div>

                    <div className="dns-mini-box">
                      <div className="dns-mini-icon-wrap icon-purple-bg">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
                          <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
                          <line x1="6" y1="6" x2="6.01" y2="6" />
                          <line x1="6" y1="18" x2="6.01" y2="18" />
                        </svg>
                      </div>
                      <span className="dns-mini-num">{dnsUniqueIps}</span>
                      <span className="dns-mini-txt">Unique IPs</span>
                    </div>

                    <div className="dns-mini-box">
                      <div className="dns-mini-icon-wrap icon-yellow-bg">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
                          <line x1="12" y1="9" x2="12" y2="13" />
                          <line x1="12" y1="17" x2="12.01" y2="17" />
                        </svg>
                      </div>
                      <span className="dns-mini-num">{dnsSuspiciousCount}</span>
                      <span className="dns-mini-txt">Suspicious Domains</span>
                    </div>
                  </div>
                </div>

                {/* 2. Top Queried Domains Card */}
                <div className="dashboard-card dns-widget-card">
                  <div className="dns-widget-title-row between">
                    <div className="dns-title-with-lead">
                      <span className="dns-title-icon">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                          <polyline points="14 2 14 8 20 8" />
                        </svg>
                      </span>
                      <h4 className="dns-widget-title">Top Queried Domains</h4>
                    </div>
                  </div>

                  <div className="dns-bars-header-row">
                    <span>Domain</span>
                    <span>Query Count</span>
                  </div>

                  {topQueriedDns.length > 0 ? (
                    <div className="dns-progress-bars-list">
                      {topQueriedDns.map((item, idx) => {
                        const barColors = ['bg-red', 'bg-orange', 'bg-yellow', 'bg-teal', 'bg-grey']
                        const pct = Math.round((item.count / maxDnsQueryCount) * 100)
                        return (
                          <div className="dns-progress-row" key={idx}>
                            <span className="prog-domain-name" title={item.domain}>{item.domain}</span>
                            <div className="prog-track">
                              <div className={`prog-bar ${barColors[idx % barColors.length]}`} style={{ width: `${Math.max(15, pct)}%` }}></div>
                            </div>
                            <span className="prog-count-val">{item.count}</span>
                          </div>
                        )
                      })}
                    </div>
                  ) : (
                    <div style={{ padding: '1.75rem 1rem', textAlign: 'center', color: '#6B7280', fontSize: '0.82rem' }}>
                      No queried domains.
                    </div>
                  )}
                </div>

                {/* 3. Top Resolved IPs Card */}
                <div className="dashboard-card dns-widget-card">
                  <div className="dns-widget-title-row between">
                    <div className="dns-title-with-lead">
                      <span className="dns-title-icon">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                          <polyline points="14 2 14 8 20 8" />
                        </svg>
                      </span>
                      <h4 className="dns-widget-title">Top Resolved IPs</h4>
                    </div>
                  </div>

                  <div className="dns-bars-header-row">
                    <span>IP Address</span>
                    <span>Query Count</span>
                  </div>

                  {topResolvedIps.length > 0 ? (
                    <div className="dns-progress-bars-list">
                      {topResolvedIps.map((item, idx) => {
                        const barColors = ['bg-red', 'bg-orange', 'bg-yellow', 'bg-teal', 'bg-grey']
                        const pct = Math.round((item.count / maxResolvedIpCount) * 100)
                        return (
                          <div className="dns-progress-row" key={idx}>
                            <span className="prog-domain-name mono-font">{item.ip}</span>
                            <div className="prog-track">
                              <div className={`prog-bar ${barColors[idx % barColors.length]}`} style={{ width: `${Math.max(15, pct)}%` }}></div>
                            </div>
                            <span className="prog-count-val">{item.count}</span>
                          </div>
                        )
                      })}
                    </div>
                  ) : (
                    <div style={{ padding: '1.75rem 1rem', textAlign: 'center', color: '#6B7280', fontSize: '0.82rem' }}>
                      No resolved IP addresses.
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* ===================== MODULES TAB CONTENT ===================== */}
          {activeTab === 'Modules' && (
            <div className="modules-tab-content">
              {/* 1. Loaded Modules Table Card */}
              <div className="dashboard-card modules-main-card">
                <div className="card-header-row modules-header-controls">
                  <div className="card-title-with-desc">
                    <span className="card-icon-lead">
                      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="18" cy="5" r="3" />
                        <circle cx="6" cy="12" r="3" />
                        <circle cx="18" cy="19" r="3" />
                        <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
                        <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
                      </svg>
                    </span>
                    <div className="title-desc-wrap">
                      <span className="card-title-text">Loaded Modules</span>
                      <span className="card-desc-sub">Modules observed in the sample's process activity.</span>
                    </div>
                  </div>

                  <div className="modules-header-right-tools">
                    <div className="modules-search-wrapper">
                      <span className="search-icon">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="11" cy="11" r="8" />
                          <line x1="21" y1="21" x2="16.65" y2="16.65" />
                        </svg>
                      </span>
                      <input
                        type="text"
                        placeholder="Search modules..."
                        className="modules-search-input"
                        value={moduleSearchQuery}
                        onChange={(e) => {
                          setModuleSearchQuery(e.target.value)
                          setModulePage(1)
                        }}
                      />
                    </div>

                    <div className="process-filter-dropdown-wrapper" style={{ position: 'relative' }}>
                      <div
                        className="modules-filter-dropdown"
                        onClick={() => setIsModuleFilterOpen(!isModuleFilterOpen)}
                      >
                        <span>{moduleFilter}</span>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                          <polyline points="6 9 12 15 18 9" />
                        </svg>
                      </div>

                      {isModuleFilterOpen && (
                        <div className="process-dropdown-menu" style={{ position: 'absolute', top: '100%', right: 0, zIndex: 25 }}>
                          {['All Modules', 'Unsigned / High Risk', 'System Modules'].map((fOpt) => (
                            <button
                              key={fOpt}
                              type="button"
                              className={`dropdown-item-btn ${moduleFilter === fOpt ? 'selected' : ''}`}
                              onClick={() => {
                                setModuleFilter(fOpt)
                                setIsModuleFilterOpen(false)
                                setModulePage(1)
                              }}
                            >
                              {fOpt}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>

                    <div className="modules-count-pill">
                      <span>{filteredModules.length} modules</span>
                    </div>
                  </div>
                </div>

                {/* Table */}
                <div className="modules-table-wrapper">
                  <table className="modules-data-table">
                    <thead>
                      <tr>
                        <th>Module</th>
                        <th>Loaded By</th>
                        <th>Image Path</th>
                        <th>Base Address</th>
                        <th>Size</th>
                        <th>Signature</th>
                        <th>SHA-256</th>
                        <th>Risk</th>
                      </tr>
                    </thead>
                    <tbody>
                      {paginatedModules.length > 0 ? (
                        paginatedModules.map((mod) => (
                          <tr
                            key={mod.id}
                            className={activeSelectedModule?.id === mod.id ? 'row-selected-module' : ''}
                            onClick={() => setSelectedModuleIndex(mod.id)}
                          >
                            <td>
                              <div className="mod-name-cell">
                                <span className="mod-file-icon">📄</span>
                                <span className={`mod-name-text ${activeSelectedModule?.id === mod.id ? 'font-bold' : ''}`}>
                                  {mod.name}
                                </span>
                              </div>
                            </td>
                            <td className="mod-loaded-text">{mod.loadedBy}</td>
                            <td className="mod-path-text" title={mod.path}>{mod.path}</td>
                            <td className="mod-mono-cell">{mod.baseAddress}</td>
                            <td>{mod.size}</td>
                            <td><span className={mod.sigBadgeClass}>{mod.signature}</span></td>
                            <td className="mod-mono-cell truncate-sha" title={mod.sha256}>
                              {mod.sha256 !== 'Not available' ? `${mod.sha256.substring(0, 12)}...` : '-'}
                            </td>
                            <td><span className={mod.riskBadgeClass}>{mod.risk}</span></td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan="8" style={{ textAlign: 'center', padding: '3rem 1rem', color: '#6B7280' }}>
                            <p style={{ fontWeight: 600, fontSize: '0.9rem', marginBottom: '0.25rem' }}>No modules found</p>
                            <p style={{ fontSize: '0.8rem' }}>No loaded modules match your search or filter criteria.</p>
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                <div className="fs-pagination-footer" style={{ marginTop: '1rem' }}>
                  <span className="fs-pagination-info">
                    Showing {filteredModules.length === 0 ? 0 : (modulePage - 1) * 10 + 1} to {Math.min(modulePage * 10, filteredModules.length)} of {filteredModules.length} modules
                  </span>
                  <div className="fs-pagination-controls">
                    <button
                      type="button"
                      className="btn-page-arrow"
                      disabled={modulePage <= 1}
                      onClick={() => setModulePage((p) => Math.max(1, p - 1))}
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="15 18 9 12 15 6" />
                      </svg>
                    </button>
                    {Array.from({ length: moduleTotalPages }, (_, i) => i + 1).slice(0, 5).map((pageNo) => (
                      <button
                        key={pageNo}
                        type="button"
                        className={`btn-page-number ${modulePage === pageNo ? 'active' : ''}`}
                        onClick={() => setModulePage(pageNo)}
                      >
                        {pageNo}
                      </button>
                    ))}
                    <button
                      type="button"
                      className="btn-page-arrow"
                      disabled={modulePage >= moduleTotalPages}
                      onClick={() => setModulePage((p) => Math.min(moduleTotalPages, p + 1))}
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="9 18 15 12 9 6" />
                      </svg>
                    </button>
                  </div>
                </div>
              </div>

              {/* 2. Bottom Inspection Card */}
              <div className="dashboard-card module-detail-split-card">
                {activeSelectedModule ? (
                  <>
                    <div className="mod-detail-left">
                      <div className="mod-detail-heading-row">
                        <div className="mod-detail-file-icon">
                          <svg width="22" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                            <polyline points="14 2 14 8 20 8" />
                          </svg>
                        </div>
                        <span className="mod-detail-title">{activeSelectedModule.name}</span>
                        <span className={activeSelectedModule.riskBadgeClass}>{activeSelectedModule.risk} Risk</span>
                      </div>

                      <div className="mod-metadata-kv-list">
                        <div className="mod-kv-row">
                          <span className="mod-kv-key">Full Path</span>
                          <span className="mod-kv-val mono-path">{activeSelectedModule.path}</span>
                        </div>
                        <div className="mod-kv-row">
                          <span className="mod-kv-key">Loaded By</span>
                          <span className="mod-kv-val">{activeSelectedModule.loadedBy}</span>
                        </div>
                        <div className="mod-kv-row">
                          <span className="mod-kv-key">Base Address</span>
                          <span className="mod-kv-val mono-val">{activeSelectedModule.baseAddress}</span>
                        </div>
                        <div className="mod-kv-row">
                          <span className="mod-kv-key">Size</span>
                          <span className="mod-kv-val">{activeSelectedModule.size}</span>
                        </div>
                        <div className="mod-kv-row">
                          <span className="mod-kv-key">Signature</span>
                          <span className={activeSelectedModule.sigBadgeClass}>{activeSelectedModule.signature}</span>
                        </div>
                        <div className="mod-kv-row">
                          <span className="mod-kv-key">SHA-256</span>
                          <div className="mod-sha256-wrap">
                            <span className="mod-kv-val mono-hash truncate-hash" title={activeSelectedModule.sha256}>
                              {activeSelectedModule.sha256}
                            </span>
                            {activeSelectedModule.sha256 !== 'Not available' && (
                              <button
                                type="button"
                                className="btn-copy-hash"
                                title="Copy SHA-256"
                                onClick={() => handleCopyHash(activeSelectedModule.sha256)}
                              >
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                                </svg>
                              </button>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="mod-detail-right">
                      <div className="why-flagged-section">
                        <div className="why-flagged-header">
                          <span className="why-flagged-icon">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={activeSelectedModule.isSuspicious ? '#DC2626' : '#2563EB'} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                              <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
                              <line x1="12" y1="9" x2="12" y2="13" />
                              <line x1="12" y1="17" x2="12.01" y2="17" />
                            </svg>
                          </span>
                          <span className="why-flagged-title">
                            {activeSelectedModule.isSuspicious ? 'Why Flagged' : 'Module Assessment'}
                          </span>
                        </div>
                        <p className="why-flagged-desc">
                          {activeSelectedModule.isSuspicious
                            ? 'This module is loaded from a non-standard or user-writable directory and lacks a verified Windows digital signature. This pattern is commonly observed during dynamic payload execution.'
                            : 'This module is a recognized operating system subsystem binary loaded as part of standard Windows process initialization.'}
                        </p>
                      </div>

                      <div className="additional-info-section">
                        <h5 className="additional-info-title">Additional Information</h5>
                        <div className="mod-metadata-kv-list">
                          <div className="mod-kv-row">
                            <span className="mod-kv-key">File Type</span>
                            <span className="mod-kv-val">Dynamic Link Library (DLL)</span>
                          </div>
                          <div className="mod-kv-row">
                            <span className="mod-kv-key">Load Events</span>
                            <span className="mod-kv-val">{activeSelectedModule.count} observed event(s)</span>
                          </div>
                          <div className="mod-kv-row">
                            <span className="mod-kv-key">Origin</span>
                            <span className="mod-kv-val">{activeSelectedModule.isSystem ? 'System Directory' : 'Local Sandbox File'}</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </>
                ) : (
                  <div style={{ textAlign: 'center', padding: '3rem', width: '100%', color: '#6B7280' }}>
                    <p style={{ fontWeight: 600, fontSize: '0.9rem' }}>No module selected</p>
                    <p style={{ fontSize: '0.8rem' }}>Click any module row in the table above to view details.</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ===================== MITRE ATT&CK TAB CONTENT ===================== */}
          {activeTab === 'MITRE ATT&CK' && (
            <div className="mitre-tab-layout">
              {/* Main Card: Header, Tactic Pills, and Table */}
              <div className="dashboard-card mitre-main-card">
                <div className="mitre-header-row">
                  <div className="mitre-title-with-desc">
                    <span className="mitre-lead-icon">
                      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="18" cy="5" r="3" />
                        <circle cx="6" cy="12" r="3" />
                        <circle cx="18" cy="19" r="3" />
                        <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
                        <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
                      </svg>
                    </span>
                    <div className="mitre-title-text-wrap">
                      <span className="mitre-card-title">MITRE ATT&amp;CK Mapping</span>
                      <span className="mitre-card-subtitle">Identified techniques based on observed behavior.</span>
                    </div>
                  </div>

                  <div className="mitre-header-right-tools">
                    <div className="mitre-search-box">
                      <span className="mitre-search-icon">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="11" cy="11" r="8" />
                          <line x1="21" y1="21" x2="16.65" y2="16.65" />
                        </svg>
                      </span>
                      <input
                        type="text"
                        placeholder="Search techniques..."
                        className="mitre-search-input"
                        value={mitreSearchQuery}
                        onChange={(e) => {
                          setMitreSearchQuery(e.target.value)
                          setMitrePage(1)
                        }}
                      />
                    </div>

                    <div className="process-filter-dropdown-wrapper" style={{ position: 'relative' }}>
                      <div
                        className="mitre-filter-dropdown"
                        onClick={() => setIsMitreFilterOpen(!isMitreFilterOpen)}
                      >
                        <span>{mitreTacticFilter}</span>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                          <polyline points="6 9 12 15 18 9" />
                        </svg>
                      </div>

                      {isMitreFilterOpen && (
                        <div className="process-dropdown-menu" style={{ position: 'absolute', top: '100%', right: 0, zIndex: 25 }}>
                          {['All Tactics', 'Execution', 'Persistence', 'Defense Evasion', 'Discovery', 'Command and Control', 'Initial Access'].map((tac) => (
                            <button
                              key={tac}
                              type="button"
                              className={`dropdown-item-btn ${mitreTacticFilter === tac ? 'selected' : ''}`}
                              onClick={() => {
                                setMitreTacticFilter(tac)
                                setIsMitreFilterOpen(false)
                                setMitrePage(1)
                              }}
                            >
                              {tac}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>

                    <div className="mitre-legend-dots">
                      <div className="mitre-legend-item">
                        <span className="mitre-dot dot-red"></span>
                        <span>High</span>
                      </div>
                      <div className="mitre-legend-item">
                        <span className="mitre-dot dot-orange"></span>
                        <span>Medium</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Top Tactics Pills Strip (6 items) */}
                <div className="mitre-tactics-strip">
                  <div className="tactic-pill-card">
                    <div className="tactic-icon-wrap icon-red-tint">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="12" cy="12" r="3" />
                        <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
                      </svg>
                    </div>
                    <div className="tactic-text-info">
                      <span className="tactic-count">{tacticCounts['Initial Access']}</span>
                      <span className="tactic-name">Initial Access</span>
                    </div>
                  </div>

                  <div className="tactic-pill-card">
                    <div className="tactic-icon-wrap icon-orange-tint">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <ellipse cx="12" cy="5" rx="9" ry="3" />
                        <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" />
                        <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" />
                      </svg>
                    </div>
                    <div className="tactic-text-info">
                      <span className="tactic-count">{tacticCounts['Execution']}</span>
                      <span className="tactic-name">Execution</span>
                    </div>
                  </div>

                  <div className="tactic-pill-card">
                    <div className="tactic-icon-wrap icon-blue-tint">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="m12 2 9 4.5V17l-9 5-9-5V6.5L12 2Z" />
                        <polyline points="12 12 12 22" />
                        <polyline points="12 12 21 7.5" />
                        <polyline points="12 12 3 7.5" />
                      </svg>
                    </div>
                    <div className="tactic-text-info">
                      <span className="tactic-count">{tacticCounts['Persistence']}</span>
                      <span className="tactic-name">Persistence</span>
                    </div>
                  </div>

                  <div className="tactic-pill-card">
                    <div className="tactic-icon-wrap icon-purple-tint">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                      </svg>
                    </div>
                    <div className="tactic-text-info">
                      <span className="tactic-count">{tacticCounts['Defense Evasion']}</span>
                      <span className="tactic-name">Defense Evasion</span>
                    </div>
                  </div>

                  <div className="tactic-pill-card">
                    <div className="tactic-icon-wrap icon-green-tint">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="18" cy="5" r="3" />
                        <circle cx="6" cy="12" r="3" />
                        <circle cx="18" cy="19" r="3" />
                        <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
                        <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
                      </svg>
                    </div>
                    <div className="tactic-text-info">
                      <span className="tactic-count">{tacticCounts['Discovery']}</span>
                      <span className="tactic-name">Discovery</span>
                    </div>
                  </div>

                  <div className="tactic-pill-card">
                    <div className="tactic-icon-wrap icon-grey-tint">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="12" cy="12" r="1" />
                        <circle cx="19" cy="12" r="1" />
                        <circle cx="5" cy="12" r="1" />
                      </svg>
                    </div>
                    <div className="tactic-text-info">
                      <span className="tactic-count">{otherTacticCount + (tacticCounts['Command and Control'] || 0)}</span>
                      <span className="tactic-name">Other / C2</span>
                    </div>
                  </div>
                </div>

                {/* Table */}
                <div className="mitre-table-wrapper">
                  <table className="mitre-mapping-table">
                    <thead>
                      <tr>
                        <th>Technique ID</th>
                        <th>Technique Name</th>
                        <th>Tactic</th>
                        <th>Evidence Count</th>
                        <th>Severity</th>
                      </tr>
                    </thead>
                    <tbody>
                      {paginatedTechniques.length > 0 ? (
                        paginatedTechniques.map((tech) => (
                          <tr
                            key={tech.id}
                            className={activeSelectedMitre?.id === tech.id ? 'row-selected-mitre' : ''}
                            onClick={() => setSelectedMitreId(tech.id)}
                          >
                            <td className="mitre-id-bold">{tech.id}</td>
                            <td className="mitre-tech-name font-medium">{tech.name}</td>
                            <td><span className={tech.tacticBadgeClass}>{tech.tactic}</span></td>
                            <td>{tech.evidenceCount}</td>
                            <td><span className={tech.sevBadgeClass}>{tech.severity}</span></td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan="5" style={{ textAlign: 'center', padding: '3rem 1rem', color: '#6B7280' }}>
                            <p style={{ fontWeight: 600, fontSize: '0.9rem', marginBottom: '0.25rem' }}>No MITRE ATT&amp;CK techniques mapped</p>
                            <p style={{ fontSize: '0.8rem' }}>No behavioral matches identified for this sample.</p>
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                <div className="mitre-pagination-footer">
                  <span className="mitre-pagination-info">
                    Showing {filteredTechniques.length === 0 ? 0 : (mitrePage - 1) * 10 + 1} to {Math.min(mitrePage * 10, filteredTechniques.length)} of {filteredTechniques.length} techniques
                  </span>
                  <div className="mitre-pagination-controls">
                    <button
                      type="button"
                      className="btn-page-arrow"
                      disabled={mitrePage <= 1}
                      onClick={() => setMitrePage((p) => Math.max(1, p - 1))}
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="15 18 9 12 15 6" />
                      </svg>
                    </button>
                    {Array.from({ length: mitreTotalPages }, (_, i) => i + 1).slice(0, 5).map((pageNo) => (
                      <button
                        key={pageNo}
                        type="button"
                        className={`btn-page-number ${mitrePage === pageNo ? 'active' : ''}`}
                        onClick={() => setMitrePage(pageNo)}
                      >
                        {pageNo}
                      </button>
                    ))}
                    <button
                      type="button"
                      className="btn-page-arrow"
                      disabled={mitrePage >= mitreTotalPages}
                      onClick={() => setMitrePage((p) => Math.min(mitreTotalPages, p + 1))}
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="9 18 15 12 9 6" />
                      </svg>
                    </button>
                  </div>
                </div>
              </div>

              {/* Bottom Inspection Card */}
              <div className="dashboard-card mitre-detail-card">
                {activeSelectedMitre ? (
                  <div className="mitre-detail-split-body">
                    {/* Left Column: Technique Info */}
                    <div className="mitre-detail-left-col">
                      <div className="mitre-detail-header-row">
                        <div className="mitre-detail-title-group">
                          <h3 className="mitre-detail-id">{activeSelectedMitre.id}</h3>
                          <span className={activeSelectedMitre.sevBadgeClass}>{activeSelectedMitre.severity}</span>
                        </div>
                        <a
                          href={activeSelectedMitre.mitreUrl}
                          target="_blank"
                          rel="noreferrer"
                          className="mitre-link-icon"
                          title="View on MITRE ATT&CK"
                        >
                          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
                            <polyline points="15 3 21 3 21 9" />
                            <line x1="10" y1="14" x2="21" y2="3" />
                          </svg>
                        </a>
                      </div>

                      <p className="mitre-detail-tech-name">{activeSelectedMitre.name}</p>

                      <div className="mitre-detail-tactic-row">
                        <span className="mitre-label-txt">Tactic</span>
                        <span className={activeSelectedMitre.tacticBadgeClass}>{activeSelectedMitre.tactic}</span>
                      </div>

                      <div className="mitre-detail-desc-block">
                        <span className="mitre-label-txt">Description</span>
                        <p className="mitre-desc-paragraph">{activeSelectedMitre.desc}</p>
                      </div>
                    </div>

                    {/* Right Column: Evidences */}
                    <div className="mitre-detail-right-col">
                      <div className="mitre-evidences-section">
                        <div className="mitre-evidences-header">
                          <h5 className="mitre-evidences-title">Evidences ({activeSelectedMitre.evidenceCount})</h5>
                        </div>

                        <div className="mitre-evidence-cards-list">
                          {activeSelectedMitre.evidences.map((evItem, idx) => (
                            <div className="mitre-evidence-item" key={idx}>
                              <span className="evidence-file-icon">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                                  <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                                  <polyline points="14 2 14 8 20 8" />
                                </svg>
                              </span>
                              <div className="evidence-info-wrap">
                                <span className="evidence-primary-text">{evItem}</span>
                                <span className="evidence-sub-text mono-code">Observed behavioral evidence</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div style={{ textAlign: 'center', padding: '3rem', width: '100%', color: '#6B7280' }}>
                    <p style={{ fontWeight: 600, fontSize: '0.9rem' }}>No technique selected</p>
                    <p style={{ fontSize: '0.8rem' }}>Click any technique in the table above to view details and evidence.</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ===================== IOCs TAB CONTENT ===================== */}
          {activeTab === 'IOCs' && (
            <div className="iocs-tab-layout">
              {/* Left Column: Indicators of Compromise Card */}
              <div className="dashboard-card iocs-main-card">
                <div className="iocs-header-row">
                  <div className="iocs-title-with-desc">
                    <span className="iocs-lead-icon">
                      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M12 2a10 10 0 0 0-1.5 19.88V19.4a8 8 0 1 1 3-15.4" />
                        <path d="M12 6a6 6 0 0 0-1.2 11.88V15.4A4 4 0 1 1 14 8" />
                        <circle cx="12" cy="12" r="1.5" />
                        <path d="M8.5 19.5a10 10 0 0 0 7 0" />
                      </svg>
                    </span>
                    <div className="iocs-title-text-wrap">
                      <span className="iocs-card-title">Indicators of Compromise (IOCs)</span>
                      <span className="iocs-card-subtitle">All extracted indicators from the analysis.</span>
                    </div>
                  </div>

                  <div className="iocs-header-right-tools">
                    <div className="iocs-search-box">
                      <span className="iocs-search-icon">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="11" cy="11" r="8" />
                          <line x1="21" y1="21" x2="16.65" y2="16.65" />
                        </svg>
                      </span>
                      <input
                        type="text"
                        placeholder="Search IOCs..."
                        className="iocs-search-input"
                        value={iocSearchQuery}
                        onChange={(e) => {
                          setIocSearchQuery(e.target.value)
                          setIocPage(1)
                        }}
                      />
                    </div>

                    <div className="process-filter-dropdown-wrapper" style={{ position: 'relative' }}>
                      <div
                        className="iocs-filter-dropdown"
                        onClick={() => setIsIocFilterOpen(!isIocFilterOpen)}
                      >
                        <span>{iocTypeFilter}</span>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                          <polyline points="6 9 12 15 18 9" />
                        </svg>
                      </div>

                      {isIocFilterOpen && (
                        <div className="process-dropdown-menu" style={{ position: 'absolute', top: '100%', right: 0, zIndex: 25 }}>
                          {['All Types', 'File Hash (SHA256)', 'IP Address', 'Domain', 'Registry Key', 'Suspicious File'].map((t) => (
                            <button
                              key={t}
                              type="button"
                              className={`dropdown-item-btn ${iocTypeFilter === t ? 'selected' : ''}`}
                              onClick={() => {
                                setIocTypeFilter(t)
                                setIsIocFilterOpen(false)
                                setIocPage(1)
                              }}
                            >
                              {t}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* IOC Table */}
                <div className="iocs-table-wrapper">
                  <table className="iocs-data-table">
                    <thead>
                      <tr>
                        <th>Type</th>
                        <th>Value</th>
                        <th>Confidence</th>
                        <th>Reputation</th>
                        <th>First Seen</th>
                        <th>Last Seen</th>
                        <th style={{ width: '30px' }}></th>
                      </tr>
                    </thead>
                    <tbody>
                      {paginatedIOCs.length > 0 ? (
                        paginatedIOCs.map((ioc) => (
                          <tr
                            key={ioc.id}
                            className={activeSelectedIoc?.id === ioc.id ? 'row-selected-ioc' : ''}
                            onClick={() => setSelectedIocIndex(ioc.id)}
                          >
                            <td>
                              <div className="ioc-type-cell">
                                <span className={`ioc-type-icon ${ioc.reputation === 'Malicious' ? 'text-red' : ''}`}>{ioc.typeIcon}</span>
                                <span>{ioc.type}</span>
                              </div>
                            </td>
                            <td className={`ioc-val-text ${activeSelectedIoc?.id === ioc.id ? 'font-bold' : ''} ${ioc.type.includes('Hash') || ioc.type.includes('IP') || ioc.type.includes('Registry') ? 'font-mono' : ''}`}>
                              {ioc.value}
                            </td>
                            <td><span className={ioc.confidenceBadge}>{ioc.confidence}</span></td>
                            <td><span className={ioc.repBadge}>{ioc.reputation}</span></td>
                            <td>{ioc.firstSeen}</td>
                            <td>{ioc.lastSeen}</td>
                            <td className="ioc-arrow-cell">›</td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan="7" style={{ textAlign: 'center', padding: '3rem 1rem', color: '#6B7280' }}>
                            <p style={{ fontWeight: 600, fontSize: '0.9rem', marginBottom: '0.25rem' }}>No IOCs found</p>
                            <p style={{ fontSize: '0.8rem' }}>No indicators of compromise match your current filter.</p>
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>

                <div className="iocs-table-footer">
                  <span className="iocs-pagination-info">
                    Showing {filteredIOCs.length === 0 ? 0 : (iocPage - 1) * 10 + 1} to {Math.min(iocPage * 10, filteredIOCs.length)} of {filteredIOCs.length} IOCs
                  </span>
                </div>
              </div>

              {/* Bottom Inspection Card */}
              <div className="dashboard-card iocs-detail-card">
                {activeSelectedIoc ? (
                  <>
                    <div className="ioc-detail-header-row">
                      <div className="ioc-detail-title-group">
                        <span className="ioc-lead-red-icon">
                          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#EF4444" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <circle cx="18" cy="5" r="3" />
                            <circle cx="6" cy="12" r="3" />
                            <circle cx="18" cy="19" r="3" />
                            <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
                            <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
                          </svg>
                        </span>
                        <div>
                          <div className="ioc-header-ip-badge-wrap">
                            <h4 className="ioc-detail-ip">{activeSelectedIoc.value}</h4>
                            <span className={activeSelectedIoc.repBadge}>{activeSelectedIoc.reputation}</span>
                          </div>
                          <span className="ioc-detail-subtitle">Type: {activeSelectedIoc.type}</span>
                        </div>
                      </div>
                      <button
                        type="button"
                        className="btn-close-ioc-detail"
                        title="Close"
                        onClick={() => setSelectedIocIndex(null)}
                      >
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <line x1="18" y1="6" x2="6" y2="18" />
                          <line x1="6" y1="6" x2="18" y2="18" />
                        </svg>
                      </button>
                    </div>

                    <div className="ioc-detail-horizontal-body">
                      {/* Column 1: Specs */}
                      <div className="ioc-detail-col">
                        <h5 className="ioc-section-title">Assessment</h5>
                        <div className="ioc-kv-list">
                          <div className="ioc-kv-row">
                            <span className="ioc-kv-key">Verdict</span>
                            <span className={activeSelectedIoc.repBadge}>{activeSelectedIoc.reputation}</span>
                          </div>
                          <div className="ioc-kv-row">
                            <span className="ioc-kv-key">Confidence</span>
                            <span className={activeSelectedIoc.confidenceBadge}>{activeSelectedIoc.confidence}</span>
                          </div>
                          <div className="ioc-kv-row">
                            <span className="ioc-kv-key">Observation Count</span>
                            <span className="ioc-kv-val font-semibold">{activeSelectedIoc.count}</span>
                          </div>
                          <div className="ioc-kv-row">
                            <span className="ioc-kv-key">Source</span>
                            <span className="ioc-kv-val">{activeSelectedIoc.asn}</span>
                          </div>
                          <div className="ioc-kv-row">
                            <span className="ioc-kv-key">Context</span>
                            <span className="ioc-kv-val">{activeSelectedIoc.org}</span>
                          </div>
                        </div>
                      </div>

                      {/* Column 2: Associated Telemetry */}
                      <div className="ioc-detail-col">
                        <h5 className="ioc-section-title">Associated Telemetry</h5>
                        <div className="ioc-artifacts-list">
                          <div className="ioc-artifact-row">
                            <div className="ioc-art-left">
                              <span className="ioc-art-icon">🌐</span>
                              <span className="ioc-art-name">Domains Observed</span>
                            </div>
                            <div className="ioc-art-right">
                              <span className="ioc-art-count">{sample.dnsCount || 0}</span>
                              <span className="ioc-art-arrow">›</span>
                            </div>
                          </div>
                          <div className="ioc-artifact-row">
                            <div className="ioc-art-left">
                              <span className="ioc-art-icon">📄</span>
                              <span className="ioc-art-name">Files Touched</span>
                            </div>
                            <div className="ioc-art-right">
                              <span className="ioc-art-count">{sample.fileCount || 0}</span>
                              <span className="ioc-art-arrow">›</span>
                            </div>
                          </div>
                          <div className="ioc-artifact-row">
                            <div className="ioc-art-left">
                              <span className="ioc-art-icon">⚙️</span>
                              <span className="ioc-art-name">Processes Active</span>
                            </div>
                            <div className="ioc-art-right">
                              <span className="ioc-art-count">{sample.processCount || 1}</span>
                              <span className="ioc-art-arrow">›</span>
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* Column 3: Threat Intelligence Sources */}
                      <div className="ioc-detail-col">
                        <h5 className="ioc-section-title">Threat Intelligence Feeds</h5>
                        <div className="ioc-ti-sources-list">
                          <div className="ioc-ti-source-row">
                            <div className="ti-source-left">
                              <span className="ti-source-icon text-blue">🛡️</span>
                              <span className="ti-source-name">ThreatBox Engine</span>
                            </div>
                            <span className={activeSelectedIoc.repBadge}>{activeSelectedIoc.reputation}</span>
                          </div>
                          <div className="ioc-ti-source-row">
                            <div className="ti-source-left">
                              <span className="ti-source-icon text-green">🔍</span>
                              <span className="ti-source-name">Sandbox Score</span>
                            </div>
                            <span className="badge-vt-score">{sample.score} / 100</span>
                          </div>
                          <div className="ioc-ti-source-row">
                            <div className="ti-source-left">
                              <span className="ti-source-icon text-purple">🟣</span>
                              <span className="ti-source-name">Severity Match</span>
                            </div>
                            <span className={activeSelectedIoc.repBadge}>{activeSelectedIoc.confidence}</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </>
                ) : (
                  <div style={{ textAlign: 'center', padding: '3rem', width: '100%', color: '#6B7280' }}>
                    <p style={{ fontWeight: 600, fontSize: '0.9rem' }}>No IOC selected</p>
                    <p style={{ fontSize: '0.8rem' }}>Click any row in the indicators table above to inspect threat details.</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ===================== RAW EVENTS TAB CONTENT ===================== */}
          {activeTab === 'Raw Events' && (
            <div className="raw-events-tab-layout">
              {/* Left Column: Raw Events Table Card */}
              <div className="dashboard-card raw-events-main-card">
                <div className="raw-header-row">
                  <div className="raw-title-with-desc">
                    <span className="raw-lead-icon">
                      <svg width="22" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                        <polyline points="14 2 14 8 20 8" />
                        <line x1="16" y1="13" x2="8" y2="13" />
                        <line x1="16" y1="17" x2="8" y2="17" />
                        <line x1="10" y1="9" x2="8" y2="9" />
                      </svg>
                    </span>
                    <div className="raw-title-text-wrap">
                      <span className="raw-card-title">Raw Events</span>
                      <span className="raw-card-subtitle">All captured system events during analysis (chronological order).</span>
                    </div>
                  </div>

                  <div className="raw-header-right-tools">
                    <div className="raw-search-box">
                      <span className="raw-search-icon">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="11" cy="11" r="8" />
                          <line x1="21" y1="21" x2="16.65" y2="16.65" />
                        </svg>
                      </span>
                      <input
                        type="text"
                        placeholder="Search events..."
                        className="raw-search-input"
                        value={rawSearchQuery}
                        onChange={(e) => {
                          setRawSearchQuery(e.target.value)
                          setRawPage(1)
                        }}
                      />
                    </div>

                    <div className="process-filter-dropdown-wrapper" style={{ position: 'relative' }}>
                      <div
                        className="raw-filter-dropdown"
                        onClick={() => setIsRawFilterOpen(!isRawFilterOpen)}
                      >
                        <span>{rawEventTypeFilter}</span>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                          <polyline points="6 9 12 15 18 9" />
                        </svg>
                      </div>

                      {isRawFilterOpen && (
                        <div className="process-dropdown-menu" style={{ position: 'absolute', top: '100%', right: 0, zIndex: 25 }}>
                          {['All Event Types', 'process_create', 'file_create', 'file_modify', 'file_delete', 'network_connect', 'dns_query', 'registry_set', 'module_load'].map((t) => (
                            <button
                              key={t}
                              type="button"
                              className={`dropdown-item-btn ${rawEventTypeFilter === t ? 'selected' : ''}`}
                              onClick={() => {
                                setRawEventTypeFilter(t)
                                setIsRawFilterOpen(false)
                                setRawPage(1)
                              }}
                            >
                              {t}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* Table */}
                <div className="raw-table-wrapper">
                  <table className="raw-events-data-table">
                    <thead>
                      <tr>
                        <th style={{ width: '40px' }}>#</th>
                        <th>Timestamp</th>
                        <th>Event Type</th>
                        <th>Source</th>
                        <th>Details</th>
                      </tr>
                    </thead>
                    <tbody>
                      {paginatedRawEvents.length > 0 ? (
                        paginatedRawEvents.map((ev) => (
                          <tr
                            key={ev.id}
                            className={activeSelectedRaw?.id === ev.id ? 'row-selected-raw' : ''}
                            onClick={() => setSelectedRawIndex(ev.id)}
                          >
                            <td className="raw-num-col">{ev.rawId}</td>
                            <td className="raw-time-col">{ev.time}</td>
                            <td className="raw-type-col">{ev.eventType}</td>
                            <td className="raw-source-col">{ev.source}</td>
                            <td className="raw-details-col font-medium">{ev.details}</td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan="5" style={{ textAlign: 'center', padding: '3rem 1rem', color: '#6B7280' }}>
                            <p style={{ fontWeight: 600, fontSize: '0.9rem', marginBottom: '0.25rem' }}>No events found</p>
                            <p style={{ fontSize: '0.8rem' }}>No telemetry events match your search query.</p>
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                <div className="raw-pagination-footer">
                  <span className="raw-pagination-info">
                    Showing {filteredRawEvents.length === 0 ? 0 : (rawPage - 1) * 12 + 1} to {Math.min(rawPage * 12, filteredRawEvents.length)} of {filteredRawEvents.length} events
                  </span>
                  <div className="raw-pagination-controls">
                    <button
                      type="button"
                      className="btn-page-arrow"
                      disabled={rawPage <= 1}
                      onClick={() => setRawPage((p) => Math.max(1, p - 1))}
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="15 18 9 12 15 6" />
                      </svg>
                    </button>
                    {Array.from({ length: rawTotalPages }, (_, i) => i + 1).slice(0, 5).map((pageNo) => (
                      <button
                        key={pageNo}
                        type="button"
                        className={`btn-page-number ${rawPage === pageNo ? 'active' : ''}`}
                        onClick={() => setRawPage(pageNo)}
                      >
                        {pageNo}
                      </button>
                    ))}
                    <button
                      type="button"
                      className="btn-page-arrow"
                      disabled={rawPage >= rawTotalPages}
                      onClick={() => setRawPage((p) => Math.min(rawTotalPages, p + 1))}
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="9 18 15 12 9 6" />
                      </svg>
                    </button>
                  </div>
                </div>
              </div>

              {/* Right Column: Event Details & JSON Card */}
              <div className="raw-right-widgets-col">
                {/* 1. Event Details Card */}
                <div className="dashboard-card raw-detail-card">
                  <div className="raw-detail-header">
                    <div className="raw-detail-title-group">
                      <span className="raw-header-icon">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
                          <line x1="8" y1="21" x2="16" y2="21" />
                          <line x1="12" y1="17" x2="12" y2="21" />
                        </svg>
                      </span>
                      <h4 className="raw-detail-title">Event Details</h4>
                    </div>
                  </div>

                  <div className="raw-kv-list">
                    <div className="raw-kv-row">
                      <span className="raw-kv-key">Event Type</span>
                      <span className="badge-event-type">{activeSelectedRaw?.eventType || 'N/A'}</span>
                    </div>
                    <div className="raw-kv-row">
                      <span className="raw-kv-key">Timestamp</span>
                      <span className="raw-kv-val">{activeSelectedRaw?.time || 'N/A'}</span>
                    </div>
                    <div className="raw-kv-row">
                      <span className="raw-kv-key">Source</span>
                      <span className="raw-kv-val">{activeSelectedRaw?.source || 'N/A'}</span>
                    </div>
                    <div className="raw-kv-row">
                      <span className="raw-kv-key">Process</span>
                      <span className="raw-kv-val">{activeSelectedRaw?.process || sample.fileName}</span>
                    </div>
                    <div className="raw-kv-row align-start">
                      <span className="raw-kv-key">Command / Target</span>
                      <div className="raw-cmd-box">
                        <span>{activeSelectedRaw?.cmd || activeSelectedRaw?.details || 'N/A'}</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* 2. Raw Event Data (JSON) Card */}
                <div className="dashboard-card raw-json-card">
                  <div className="raw-json-header">
                    <div className="raw-detail-title-group">
                      <span className="raw-header-icon">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                          <polyline points="14 2 14 8 20 8" />
                        </svg>
                      </span>
                      <h4 className="raw-detail-title">Raw Event Data (JSON)</h4>
                    </div>
                    <button
                      type="button"
                      className="btn-copy-raw-json"
                      title="Copy JSON"
                      onClick={() => handleCopyRawJson(activeSelectedRaw?.rawObj || sample.rawJson)}
                    >
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                      </svg>
                    </button>
                  </div>

                  <div className="raw-json-viewer-container">
                    <pre className="raw-json-pre">
                      <code>
                        {activeSelectedRaw?.rawObj
                          ? JSON.stringify(activeSelectedRaw.rawObj, null, 2)
                          : (sample.rawJson || 'No JSON event payload available.')}
                      </code>
                    </pre>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Placeholder for other tabs (e.g. Registry) */}
          {activeTab !== 'Overview' && activeTab !== 'Behavior' && activeTab !== 'Processes' && activeTab !== 'File System' && activeTab !== 'Network' && activeTab !== 'DNS' && activeTab !== 'Modules' && activeTab !== 'MITRE ATT&CK' && activeTab !== 'IOCs' && activeTab !== 'Raw Events' && (
            <div className="dashboard-card" style={{ padding: '3.5rem', textAlign: 'center' }}>
              <h3 style={{ fontSize: '1.2rem', color: '#111418', marginBottom: '0.5rem' }}>{activeTab} Telemetry</h3>
              <p style={{ color: '#727a85', fontSize: '0.9rem' }}>Detailed inspection logs for {activeTab} will appear here.</p>
            </div>
          )}
        </main>
      </div>
    </div>
  )
}

export default Dashboard
