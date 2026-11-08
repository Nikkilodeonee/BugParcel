$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$jarPath = Join-Path $projectRoot 'target\bugparcel-1.3.0.jar'
if (-not (Test-Path -LiteralPath $jarPath)) { throw 'Run mvn verify before packaging.' }
$artifactRoot = Join-Path $projectRoot 'artifacts'
$releaseRoot = Join-Path $artifactRoot 'BugParcel-1.3.0'
New-Item -ItemType Directory -Path $releaseRoot -Force | Out-Null
Copy-Item -LiteralPath $jarPath -Destination (Join-Path $releaseRoot 'bugparcel.jar')
Copy-Item -LiteralPath (Join-Path $projectRoot 'LICENSE') -Destination $releaseRoot
Copy-Item -LiteralPath (Join-Path $projectRoot 'src\main\resources\samples\bugparcel.example.yml') -Destination $releaseRoot
$launcher = @'
@echo off
cd /d "%~dp0"
echo BugParcel is starting at http://127.0.0.1:8087
echo Open that address in your browser. Press Ctrl+C to stop.
java "-Djdk.net.unixdomain.tmpdir=%~dp0unused-nio-sockets" -jar bugparcel.jar
if errorlevel 1 pause
'@
Set-Content -LiteralPath (Join-Path $releaseRoot 'Start BugParcel.cmd') -Value $launcher -Encoding Ascii
$cliCmd = @'
@echo off
rem BugParcel command line. Run "bugparcel help" for usage; with no command it starts the web interface.
java "-Djdk.net.unixdomain.tmpdir=%~dp0unused-nio-sockets" -jar "%~dp0bugparcel.jar" %*
exit /b %errorlevel%
'@
Set-Content -LiteralPath (Join-Path $releaseRoot 'bugparcel.cmd') -Value $cliCmd -Encoding Ascii
$cliSh = @'
#!/bin/sh
# BugParcel command line. Run "bugparcel help" for usage.
exec java -jar "$(dirname "$0")/bugparcel.jar" "$@"
'@
# LF line endings and no BOM so the script runs on macOS/Linux.
[IO.File]::WriteAllText((Join-Path $releaseRoot 'bugparcel'), ($cliSh -replace "`r`n", "`n") + "`n", (New-Object Text.UTF8Encoding $false))
$instructions = @'
BugParcel 1.3.0

Requires Java 17 or newer.

Windows: double-click Start BugParcel.cmd.
macOS/Linux: run java -jar bugparcel.jar from this folder.
Open http://127.0.0.1:8087 and click Try a sample incident.

Command line (no server, nothing leaves your machine):
  bugparcel sample
  bugparcel report bugparcel-sample\checkout.har --logs bugparcel-sample\checkout.ndjson -o report.html
  bugparcel review checkout.har --logs app.log
  bugparcel diff before.har after.har --before-logs before.log --logs after.log -o comparison.html
  bugparcel replay checkout.har --request req-5 --tool curl -o replay.sh
  bugparcel help
Use bugparcel.cmd on Windows or ./bugparcel on macOS/Linux.
Choose Security sample in the interface to try synthetic token/identifier redaction.
Use --paranoid for checksum identifiers and entropy suspects.
Copy bugparcel.example.yml to bugparcel.yml in your working directory for CLI policy auto-loading.
Use --policy <file> for an explicit policy, --no-policy to disable discovery, or --no-decode to disable decoded inspection.
Exports include a scoped self-check; kept/allowlisted values may remain visible.
Timeline and Compare tabs show request completion order, timings and sanitized differences.
Try the before/after demo from Compare. Export themes: Paper, Night and High contrast.
Open an HTML report in your browser and Print / Save as PDF for the print layout.
Replay exports are POSIX shell templates only; BugParcel never executes them.
Set required BP_* variables yourself. URL variables need percent-encoded values;
masked, omitted or truncated bodies require a complete BP_REQUEST_BODY.
Press Ctrl+C in the terminal to stop the application.

Evidence stays in memory. Download a report before closing or reloading the app.
Review redactions before sharing. Automatic detection may miss sensitive values.

Source and full documentation are in the BugParcel project folder.
Author: Roman Sushkin (https://github.com/Nikkilodeonee)
MIT License.
'@
Set-Content -LiteralPath (Join-Path $releaseRoot 'READ ME.txt') -Value $instructions -Encoding Ascii
Compress-Archive -LiteralPath $releaseRoot -DestinationPath (Join-Path $artifactRoot 'BugParcel-1.3.0.zip') -Force
Get-FileHash -LiteralPath (Join-Path $artifactRoot 'BugParcel-1.3.0.zip') -Algorithm SHA256 | ForEach-Object { $_.Hash.ToLowerInvariant() + '  BugParcel-1.3.0.zip' } | Set-Content -LiteralPath (Join-Path $artifactRoot 'SHA256SUMS.txt') -Encoding Ascii
Write-Host (Join-Path $artifactRoot 'BugParcel-1.3.0.zip')
