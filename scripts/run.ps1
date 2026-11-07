param([switch]$Build, [int]$Port = 8087)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$jarPath = Join-Path $projectRoot 'target\bugparcel-1.0.0.jar'
if ($Build -or -not (Test-Path -LiteralPath $jarPath)) {
    $mavenCommand = Get-Command mvn.cmd -ErrorAction SilentlyContinue
    if ($mavenCommand) { $mavenPath = $mavenCommand.Source }
    else {
        $wrapperRoot = Join-Path $env:USERPROFILE '.m2\wrapper\dists'
        $mavenPath = if (Test-Path -LiteralPath $wrapperRoot) { Get-ChildItem -LiteralPath $wrapperRoot -Filter mvn.cmd -Recurse -File | Select-Object -First 1 -ExpandProperty FullName }
    }
    if (-not $mavenPath) { throw 'Maven 3.9+ is required to build from source. Install Maven, then run mvn verify. A prebuilt JAR only requires Java 17+.' }
    & $mavenPath verify
    if ($LASTEXITCODE -ne 0) { throw 'The build or tests failed. Check the output above.' }
}
Write-Host "BugParcel is starting at http://127.0.0.1:$Port" -ForegroundColor Green
Write-Host 'Open that address in your browser. Press Ctrl+C to stop.'
# Some Windows JDKs fail their internal Unix-domain selector pipe with non-ASCII
# or sandbox TEMP paths. A deliberately absent socket directory makes the JDK
# fall back to its TCP pipe. This option changes this JVM only, not OS settings.
$socketFallback = Join-Path $projectRoot '.cache\unused-nio-sockets'
& java "-Djdk.net.unixdomain.tmpdir=$socketFallback" -jar $jarPath "--server.port=$Port"
exit $LASTEXITCODE
