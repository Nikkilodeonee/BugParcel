$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$version = ([xml](Get-Content -LiteralPath (Join-Path $projectRoot 'pom.xml') -Raw)).project.version
if ($version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') { throw 'Packaging requires a stable Maven version.' }
$jarPath = Join-Path $projectRoot "target\bugparcel-$version.jar"
if (-not (Test-Path -LiteralPath $jarPath)) { throw 'Run mvn verify before packaging.' }
$artifactRoot = Join-Path $projectRoot 'artifacts'
$releaseRoot = Join-Path $artifactRoot "BugParcel-$version"
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
BugParcel {{VERSION}}

Requires Java 17 or newer.

Windows: double-click Start BugParcel.cmd.
macOS/Linux: run java -jar bugparcel.jar from this folder.
Open http://127.0.0.1:8087 and click Try a sample incident.

Command line (no server; local inputs unless explicit pull flags are used):
  bugparcel sample
  bugparcel report bugparcel-sample\checkout.har --logs bugparcel-sample\checkout.ndjson -o report.html
  bugparcel review checkout.har --logs app.log
  bugparcel diff before.har after.har --before-logs before.log --logs after.log -o comparison.html
  bugparcel replay checkout.har --request req-5 --tool curl -o replay.sh
  bugparcel help
  bugparcel sample --inputs
  bugparcel report bugparcel-sample\playwright-checkout.zip --logs bugparcel-sample\checkout-logs.zip -o report.html
  bugparcel report trace.zip --logs "logs/**/*.log.gz" -o report.html
  bugparcel help inputs
Use bugparcel.cmd on Windows; run chmod +x bugparcel then ./bugparcel on macOS/Linux.
Choose Security sample in the interface to try synthetic token/identifier redaction.
Use --paranoid for checksum identifiers and entropy suspects.
Copy bugparcel.example.yml to bugparcel.yml in your working directory for CLI policy auto-loading.
Use --policy <file> for an explicit policy, --no-policy to disable discovery, or --no-decode to disable decoded inspection.
Exports include a scoped self-check; kept/allowlisted values may remain visible.
Timeline and Compare tabs show request completion order, timings and sanitized differences.
Try the before/after demo from Compare. Export themes: Paper, Night and High contrast.
Open an HTML report in your browser and Print / Save as PDF for the print layout.
Replay exports are POSIX shell templates only; BugParcel never executes them.
Supported captures include Charles XML, mitmproxy flow format 21/HAR, Postman/Newman runs,
and Playwright trace ZIPs. Log directories, globs, gzip and ZIP inputs are bounded.
Input formats and pipeline recipes are available in the interface and help inputs.
Optional CLI --logs-url, --loki and --elasticsearch flags retrieve from a source you name.
Authorization is read from an explicitly named environment variable (--auth-env).
No browser/API pulls, automatic URL fetches, redirects, or credential restoration occur.
Set required BP_* variables yourself. URL variables need percent-encoded values;
masked, omitted or truncated bodies require a complete BP_REQUEST_BODY.
Press Ctrl+C in the terminal to stop the application.

Evidence stays in memory. Download a report before closing or reloading the app.
Review redactions before sharing. Automatic detection may miss sensitive values.

Source and full documentation are in the BugParcel project folder.
Author: Roman Sushkin (https://github.com/Nikkilodeonee)
MIT License.
'@
Set-Content -LiteralPath (Join-Path $releaseRoot 'READ ME.txt') -Value $instructions.Replace('{{VERSION}}',$version) -Encoding Ascii
$zipPath = Join-Path $artifactRoot "BugParcel-$version.zip"
Compress-Archive -LiteralPath $releaseRoot -DestinationPath $zipPath -Force
$checksum = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant() + "  BugParcel-$version.zip`n"
[IO.File]::WriteAllText((Join-Path $artifactRoot 'SHA256SUMS.txt'), $checksum, [Text.UTF8Encoding]::new($false))
Write-Host $zipPath
