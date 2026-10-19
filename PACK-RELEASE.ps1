# SPDX-License-Identifier: MIT
[CmdletBinding()]
param(
    [ValidatePattern('^[0-9A-Za-z][0-9A-Za-z.-]*$')]
    [string]$Version = '10.0.0-preview.2',
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$root = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\')
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $root 'release'
}
$manifestPath = Join-Path $root 'SHA256SUMS.txt'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw 'Release manifest is missing.'
}

foreach ($line in [IO.File]::ReadAllLines($manifestPath, [Text.Encoding]::UTF8)) {
    if ($line -notmatch '^([0-9a-f]{64})  (.+)$') { throw "Malformed release-manifest line: $line" }
    $expected = $matches[1]
    $relative = $matches[2]
    $path = [IO.Path]::GetFullPath((Join-Path $root ($relative.Replace('/', '\'))))
    if (-not $path.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Unsafe or missing manifest path: $relative" }
    $item = Get-Item -LiteralPath $path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Reparse file rejected: $relative" }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $expected) { throw "Release-manifest mismatch: $relative" }
}

$releaseFiles = @(
    'SowCompat.exe',
    'g.exe',
    'sow_compat.ps1',
    'profiles/sow-msstore-x64-1.0.28.2.json',
    'START.cmd',
    'INSTALL.cmd',
    'CHECK-ONLY.cmd',
    'PREPARE-ONLY.cmd',
    'RECOVER.cmd',
    'README.md',
    'SUPPORT.md',
    'LICENSE',
    'NOTICE.md',
    'SECURITY.md',
    'THREAT-MODEL.md'
)

$stageParent = Join-Path ([IO.Path]::GetTempPath()) 'SowCompat-release-staging'
[void][IO.Directory]::CreateDirectory($stageParent)
$stage = Join-Path $stageParent ([Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($stage)

try {
    foreach ($relative in $releaseFiles) {
        $nativeRelative = $relative.Replace('/', '\')
        $source = [IO.Path]::GetFullPath((Join-Path $root $nativeRelative))
        if (-not $source.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Missing package file: $relative" }
        $item = Get-Item -LiteralPath $source -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Reparse file rejected: $relative" }
        $destination = Join-Path $stage $nativeRelative
        [void][IO.Directory]::CreateDirectory((Split-Path -Parent $destination))
        [IO.File]::Copy($source, $destination, $false)
    }

    $packageHashes = New-Object Collections.Generic.List[string]
    foreach ($file in @(Get-ChildItem -LiteralPath $stage -File -Recurse | Sort-Object FullName)) {
        $relative = $file.FullName.Substring($stage.Length + 1).Replace('\', '/')
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $packageHashes.Add("$hash  $relative")
    }
    [IO.File]::WriteAllLines((Join-Path $stage 'SHA256SUMS.txt'), $packageHashes,
        (New-Object Text.UTF8Encoding($false)))

    $output = [IO.Path]::GetFullPath($OutputDirectory)
    if ($output.Equals($root, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Output directory must not be the repository root.'
    }
    [void][IO.Directory]::CreateDirectory($output)
    $zipName = "SowCompat-$Version-win-x64.zip"
    $zipPath = Join-Path $output $zipName
    if (Test-Path -LiteralPath $zipPath) { throw "Release archive already exists: $zipPath" }
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zipPath -CompressionLevel Optimal

    $zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText($zipPath + '.sha256', "$zipHash  $zipName`r`n",
        (New-Object Text.UTF8Encoding($false)))
    Write-Host "RELEASE_PACKAGE_OK: $zipPath" -ForegroundColor Green
    Write-Host "SHA256: $zipHash"
} finally {
    if (Test-Path -LiteralPath $stage -PathType Container) {
        [IO.Directory]::Delete($stage, $true)
    }
}
