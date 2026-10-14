[CmdletBinding()]
param(
    [ValidateSet('Win32', 'x64')][string]$Platform = 'x64',
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$bin = Join-Path $root "artifacts/bin/$Platform/$Configuration"
$tests = Start-Process -FilePath (Join-Path $bin 'Magicmida.Tests.exe') -PassThru -NoNewWindow
if (-not $tests.WaitForExit(120000)) {
    $tests.Kill($true)
    throw 'Native tests timed out (120 seconds).'
}
if ($tests.ExitCode -ne 0) { throw "Native tests failed: $($tests.ExitCode)" }
$exe = Join-Path $bin 'Magicmida.exe'
function Assert-Exit([string]$Arguments, [int]$Expected) {
    $p = Start-Process -FilePath $exe -ArgumentList $Arguments -PassThru -NoNewWindow
    if (-not $p.WaitForExit(30000)) {
        $p.Kill($true)
        throw "CLI timeout: $Arguments"
    }
    if ($p.ExitCode -ne $Expected) { throw "CLI '$Arguments': expected $Expected, got $($p.ExitCode)" }
}
Assert-Exit '/help' 0
Assert-Exit '/unpack' 2
Assert-Exit '/unknown' 2
$missing = Join-Path $bin ([guid]::NewGuid().ToString() + ' missing.exe')
Assert-Exit "/unpack `"$missing`"" 1
$bad = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString() + ' 非 PE.bin')
try {
    [System.IO.File]::WriteAllBytes($bad, [byte[]](0, 1, 2, 3))
    Assert-Exit "/unpack `"$bad`"" 1
} finally { Remove-Item $bad -ErrorAction SilentlyContinue }
Write-Host 'Native tests and CLI smoke tests passed.'
