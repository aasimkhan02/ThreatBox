# Vendors a pristine goetw v0.9.11 into third_party\goetw, applies the one-hunk
# MOF-first patch, and adds a local `replace` to go.mod. Run from the repo root.
# It refuses to continue if the module-cache copy still contains stale
# threatBoxDiag* edits, and it never touches the module cache.
$ErrorActionPreference = 'Stop'
$patch = Join-Path $PSScriptRoot 'goetw-mof-first.patch'
if (-not (Test-Path .\go.mod))      { throw 'Run this from the repository root (go.mod not found).' }
if (-not (Test-Path $patch))        { throw "Patch not found: $patch" }
if (Test-Path .\third_party\goetw)  { throw 'third_party\goetw already exists; remove it first or inspect it.' }

$dir = (go list -m -f '{{.Dir}}' github.com/tekert/goetw).Trim()
if (-not $dir -or -not (Test-Path $dir)) { throw 'goetw v0.9.11 is not in the module cache; run: go mod download github.com/tekert/goetw' }

$stale = Select-String -Path "$dir\etw\*.go" -Pattern 'threatBoxDiag' -SimpleMatch -ErrorAction SilentlyContinue
if ($stale) {
  $stale | Select-Object Path, LineNumber | Format-Table -AutoSize
  throw "Module cache copy is NOT pristine. Re-extract it first:`n  attrib -r `"$dir\*`" /s /d`n  Remove-Item -Recurse -Force `"$dir`"`n  go mod download github.com/tekert/goetw`n  go mod verify"
}

New-Item -ItemType Directory -Force .\third_party | Out-Null
Copy-Item -Recurse $dir .\third_party\goetw
attrib -r .\third_party\goetw\* /s /d | Out-Null

git apply --check --directory=third_party/goetw $patch
if ($LASTEXITCODE -ne 0) {
  Write-Host 'Strict apply failed; retrying ignoring whitespace (CRLF?)'
  git apply --check --ignore-whitespace --directory=third_party/goetw $patch
  if ($LASTEXITCODE -ne 0) { Remove-Item -Recurse -Force .\third_party\goetw; throw 'Patch does not apply to this goetw copy.' }
  git apply --ignore-whitespace --directory=third_party/goetw $patch
} else {
  git apply --directory=third_party/goetw $patch
}
if ($LASTEXITCODE -ne 0) { throw 'git apply failed' }

go mod edit -replace 'github.com/tekert/goetw=./third_party/goetw'
Select-String -Path .\third_party\goetw\etw\etw_helpers.go -Pattern 'THREATBOX PATCH' | Select-Object -First 1
Write-Host 'Done. Now build and vet:  go vet ./cmd/etw-collector ; go build ./...'
