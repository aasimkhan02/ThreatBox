# ThreatBox Accuracy Test Fixtures

Three benign Windows test executables. They do not use networking, persistence, injection, credential access, destructive actions, or evasion.

## Tests
1. **file-ops**: creates/writes 3 files, reads 2, renames 1, deletes 1 in a unique `%TEMP%\ThreatBoxAccuracy` directory. Prints a `GROUND_TRUTH` JSON ledger.
2. **process-tree**: starts a child instance of itself; the child writes one marker file. Parent and child print PID/PPID and paths.
3. **mitre-shells**: positive mode launches harmless `cmd.exe /d /c ver` and PowerShell `Write-Output`. `--negative` launches neither, as a false-positive control.

The ledger records successful logical operations, not exact ETW event counts. One logical operation can generate multiple ETW events.

## Build (from ThreatBox repo root)
Extract this ZIP so the folder is `tools\threatbox-accuracy-tests`, then run:

```powershell
go build -trimpath -o .\file-ops-test.exe .\tools\threatbox-accuracy-tests\file-ops
go build -trimpath -o .\process-tree-test.exe .\tools\threatbox-accuracy-tests\process-tree
go build -trimpath -o .\mitre-shells-test.exe .\tools\threatbox-accuracy-tests\mitre-shells
```

Uses only the Go standard library. Build on your Windows host for Windows Sandbox.

## Run
Run one executable per ThreatBox job through your normal upload/detonation flow. Do not run on the host for telemetry collection.
1. Upload `file-ops-test.exe`.
2. Upload `process-tree-test.exe`.
3. Upload `mitre-shells-test.exe` with no arguments (positive).
4. Run `mitre-shells-test.exe --negative` as a separate control if your pipeline supports arguments. Otherwise change the source default `flag.Bool("negative", false, ...)` to `true`, then build a separate negative-control executable.

If the wrapper renames uploaded files to `sample.exe`, use `sample.exe` as the analyzer expected name; otherwise use the actual process image name.

## Reanalyse
Replace `<JOB-FOLDER>` and expected image name:

```powershell
.\process-analyzer.p1.exe "C:\ThreatBox\runtime\jobs\<JOB-FOLDER>\output\events.jsonl" file-ops-test.exe
```

Preserve `GROUND_TRUTH` console output if available, `events.jsonl`, status JSON, and analyzer output. For each fixture action mark correct, missed, misclassified, or false positive.
- Recall = correctly detected ground-truth actions / ground-truth actions the sensor is expected to observe.
- Precision = correctly supported reported actions / all reported actions evaluated.
- Attribution accuracy = correctly attributed in-scope events / evaluated in-scope events.

Compare logical actions to raw ETW evidence; do not use raw ETW event count as the logical-operation denominator. Track OS/background noise separately. For MITRE, positive mode should support T1059.003 and T1059.001; the negative control should not report those based on fixture actions. Other sandbox activity may still appear, so inspect supporting evidence, not only technique names.
