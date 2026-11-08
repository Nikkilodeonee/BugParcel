$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $projectRoot
try {
    & node scripts/generate-input-samples.mjs
    if ($LASTEXITCODE -ne 0) { throw 'Synthetic fixture generation failed.' }
    Add-Type -AssemblyName System.IO.Compression
    $fixtureRoot = Join-Path $projectRoot '.cache\tier4-samples'
    $manifest = Get-Content -LiteralPath (Join-Path $fixtureRoot 'manifest.json') -Raw | ConvertFrom-Json
    foreach ($kind in @('trace', 'logs')) {
        $name = if ($kind -eq 'trace') { 'playwright-checkout.zip' } else { 'checkout-logs.zip' }
        $destination = Join-Path $projectRoot ('src\main\resources\samples\' + $name)
        $stream = [IO.File]::Open($destination, [IO.FileMode]::Create)
        $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create)
        try {
            foreach ($part in $manifest.$kind) {
                if ($part.file -notmatch '^[a-z0-9-]+$') { throw 'Invalid synthetic fixture filename.' }
                $entry = $archive.CreateEntry($part.name)
                $outputStream = $entry.Open()
                try { $bytes = [IO.File]::ReadAllBytes((Join-Path $fixtureRoot $part.file)); $outputStream.Write($bytes, 0, $bytes.Length) }
                finally { $outputStream.Dispose() }
            }
        } finally { $archive.Dispose(); $stream.Dispose() }
    }
} finally { Pop-Location }
