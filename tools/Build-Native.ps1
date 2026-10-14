[CmdletBinding()]
param(
    [ValidateSet('Win32', 'x64')][string]$Platform = 'x64',
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [switch]$Rebuild,
    [switch]$Test
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) { throw 'Install Visual Studio 2026 / Build Tools and Desktop development with C++.' }
$msbuild = & $vswhere -latest -products '*' -version '[18.0,19.0)' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find MSBuild\**\Bin\MSBuild.exe
if (-not $msbuild) { throw 'MSVC v145 / Visual Studio 2026 MSBuild not found.' }
$target = if ($Rebuild) { 'Rebuild' } else { 'Build' }
Push-Location $root
try {
    New-Item -ItemType Directory -Force artifacts | Out-Null
    $builder = @($msbuild)[0]
    & $builder Magicmida.slnx /m "/t:$target" "/p:Platform=$Platform" "/p:Configuration=$Configuration" "/bl:artifacts/build-$Platform-$Configuration.binlog"
    if ($LASTEXITCODE -ne 0) { throw "MSBuild failed with code $LASTEXITCODE" }
    if ($Test) { & "$PSScriptRoot/Test-Native.ps1" -Platform $Platform -Configuration $Configuration }
} finally { Pop-Location }
