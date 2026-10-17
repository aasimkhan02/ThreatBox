$ErrorActionPreference = 'Stop'

$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$buildDir = Join-Path $projectRoot 'bin\sandbox-tools'

$deployDir = $env:THREATBOX_SANDBOX_TOOLS
if ([string]::IsNullOrWhiteSpace($deployDir)) {
    $deployDir = 'C:\ThreatBoxSandbox'
}

New-Item -ItemType Directory -Force -Path $buildDir, $deployDir |
    Out-Null

Push-Location $projectRoot

try {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

    $artifacts = @(
        @{
            Name = 'etw-collector.exe'
            Package = '.\cmd\etw-collector'
        },
        @{
            Name = 'sandbox-agent.exe'
            Package = '.\cmd\sandbox-agent'
        }
    )

    # Build both before replacing either deployed executable.
    foreach ($artifact in $artifacts) {
        $staged = Join-Path $buildDir (
            $artifact.Name + '.staging.exe'
        )

        if (Test-Path $staged) {
            Remove-Item $staged -Force
        }

        Write-Host "Building $($artifact.Name)..."
        go build -o $staged $artifact.Package

        if ($LASTEXITCODE -ne 0 -or !(Test-Path $staged)) {
            throw "Build failed: $($artifact.Name). Nothing deployed."
        }
    }

    foreach ($artifact in $artifacts) {
        $name = $artifact.Name
        $staged = Join-Path $buildDir ($name + '.staging.exe')
        $built = Join-Path $buildDir $name
        $deployed = Join-Path $deployDir $name

        Move-Item $staged $built -Force

        if (Test-Path $deployed) {
            Copy-Item $deployed "$deployed.bak-$stamp"
        }

        Copy-Item $built $deployed -Force

        $builtHash = (Get-FileHash $built -Algorithm SHA256).Hash
        $deployedHash = (Get-FileHash $deployed -Algorithm SHA256).Hash

        if ($builtHash -ne $deployedHash) {
            throw "Hash mismatch after deployment: $name"
        }

        Write-Host "Verified $name"
        Write-Host "SHA256: $deployedHash"
    }

    Write-Host ''
    Write-Host 'Sandbox tools built and deployed successfully.'
    Write-Host "Source build: $buildDir"
    Write-Host "Sandbox tools: $deployDir"
}
finally {
    Pop-Location
}