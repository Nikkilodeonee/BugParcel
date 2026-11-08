$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $projectRoot
try {
    $version = ([xml](Get-Content -LiteralPath pom.xml -Raw)).project.version
    if ($version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') { throw 'A stable Maven version is required.' }
    if ($env:GITHUB_REF_NAME -and $env:GITHUB_REF_NAME -ne "v$version") { throw 'Tag and Maven version do not match.' }
    $jar = "target/bugparcel-$version.jar"
    & java -jar $jar report src/main/resources/samples/checkout.har --logs src/main/resources/samples/checkout.ndjson --include-bodies --strict --title 'Synthetic checkout: database timeout' --theme paper -o docs/sample-report.html
    if ($LASTEXITCODE -ne 0) { throw 'Sample report generation failed.' }
    & node scripts/verify-public-demo.mjs
    if ($LASTEXITCODE -ne 0) { throw 'Public demo verification failed.' }
    & ./scripts/package.ps1
    $publishRoot = Join-Path $projectRoot 'artifacts/publish'
    $assetRoot = Join-Path $publishRoot 'assets'
    New-Item -ItemType Directory -Path $assetRoot -Force | Out-Null
    Copy-Item -LiteralPath "artifacts/BugParcel-$version.zip" -Destination $assetRoot
    Copy-Item -LiteralPath $jar -Destination $assetRoot
    Copy-Item -LiteralPath docs/sample-report.html, docs/demo.gif -Destination $assetRoot
    Copy-Item -LiteralPath "docs/releases/$version.md" -Destination (Join-Path $publishRoot 'RELEASE_NOTES.md')
    $names = @("BugParcel-$version.zip", "bugparcel-$version.jar", 'sample-report.html', 'demo.gif')
    $checksums = foreach ($name in $names) {
        (Get-FileHash -LiteralPath (Join-Path $assetRoot $name) -Algorithm SHA256).Hash.ToLowerInvariant() + "  $name"
    }
    [IO.File]::WriteAllText((Join-Path $assetRoot 'SHA256SUMS.txt'), ($checksums -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
    Write-Host "Prepared release $version with ZIP, JAR, sample HTML, GIF and SHA-256 checksums."
} finally { Pop-Location }
