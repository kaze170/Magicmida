[CmdletBinding()]
param(
    [ValidateSet('Win32', 'x64')][string]$Platform = 'x64',
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$bin = Join-Path $root "artifacts/bin/$Platform/$Configuration"
$stdout = Join-Path $bin 'native-tests.stdout.log'
$stderr = Join-Path $bin 'native-tests.stderr.log'
$tests = Start-Process -FilePath (Join-Path $bin 'Magicmida.Tests.exe') -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
if (-not $tests.WaitForExit(120000)) {
    $tests.Kill($true)
    throw 'Native tests timed out (120 seconds).'
}
Get-Content $stdout
Get-Content $stderr
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
Assert-Exit '/create-data' 2
Assert-Exit '/create-data x --reference' 2
Assert-Exit '/create-data x --invalid y' 2
Assert-Exit '/shrink' 2
$missing = Join-Path $bin ([guid]::NewGuid().ToString() + ' missing.exe')
Assert-Exit "/unpack `"$missing`"" 1
$bad = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString() + ' 非 PE.bin')
try {
    [System.IO.File]::WriteAllBytes($bad, [byte[]](0, 1, 2, 3))
    Assert-Exit "/unpack `"$bad`"" 1
    Assert-Exit "/create-data `"$bad`"" 1
    Assert-Exit "/shrink `"$bad`"" 1
} finally { Remove-Item $bad -ErrorAction SilentlyContinue }
# Exercise the successful CLI paths on a real MSVC executable, then let the
# Windows loader run its tiny child fixture after both transformations.
$edited = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString() + ' section 測試.exe')
$reference = Join-Path $bin 'Magicmida.Tests.exe'
$oldChild = $env:MAGICMIDA_TEST_CHILD
try {
    Copy-Item $reference $edited
    Assert-Exit "/create-data `"$edited`" --reference `"$reference`"" 0
    Assert-Exit "/shrink `"$edited`"" 0
    $env:MAGICMIDA_TEST_CHILD = '1'
    $p = Start-Process -FilePath $edited -PassThru -NoNewWindow
    if (-not $p.WaitForExit(30000)) { $p.Kill($true); throw 'Reconstructed executable timed out.' }
    if ($p.ExitCode -ne 0) { throw "Reconstructed executable failed: $($p.ExitCode)" }
} finally {
    $env:MAGICMIDA_TEST_CHILD = $oldChild
    Remove-Item $edited -ErrorAction SilentlyContinue
}
Write-Host 'Native tests, CLI smoke tests and reconstructed executable loader test passed.'
