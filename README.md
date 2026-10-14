# Magicmida

Magicmida is a Themida auto unpacker for 32-bit and 64-bit applications.

## Native Visual Studio 2026 / C++26 port

Open **[`Magicmida.slnx`](Magicmida.slnx)** in Visual Studio 2026. The native
Win32 GUI, command-line entry point and unpacking core are in `native/`;
**Delphi, Lazarus and their prebuilt `.obj` files are not required** by this solution.
The Pascal sources remain unchanged as a reference and legacy build path.

> Validation status: all four configurations have built with real VS2026 / MSVC
> v145 on Windows CI, in addition to local cross-builds and portable tests.
> Sparse IAT reconstruction has passed actual Windows loader checks in all four
> configurations. A debugger fixture startup-timing correction awaits CI.
> Real protected-target parity is not yet established; see the migration notes.

See [繁體中文移植與驗證說明](docs/VC2026-migration.md) for module coverage,
intentional differences, verification steps and remaining runtime checks.
Use this tool only on software you own or are authorized to inspect.

Functions:
* Unpack: Unpacks the binary you select. The unpacked binary will be saved with an `U` suffix.
* Auto create data sections: Restores .rdata/.data sections. Only works on specific targets. This is a must for MSVC applications using Thread Local Storage because they don't work properly otherwise.
* Dump process: Allows you to enter the PID of a running process whose .text section will be dumped (overwritten) into an already unpacked file. This is useful after using Oreans Unvirtualizer in OllyDbg. Only works properly if data sections were created.
* Shrink: Deletes all sections that are no longer needed (if you unvirtualized or if your binary does not use virtualization). Warning: This will break your binary for non-MSVC compilers.

Notes about running unpacked binaries:
* **VM anti-dumps are explicitly not fixed.** If your target has a virtualized entrypoint or any other virtualized code, the resulting dump will be broken and won't run (or it will only run on your system until you reboot, because many anti-dumps use DLL base addresses). Fixing this is possible with special tool assistance, but tedious.
* Unpacked DLLs will miss relocation information, which can make them problematic to use in bigger applications that load a lot of libraries.

Important: Never activate any compatibility mode options for Magicmida or for the target you're unpacking. It would very likely screw up the unpacking process due to shimming.

Windows sometimes decides to auto-apply compatibility patches to an executable if it crashed before. This AppCompat information is stored in the registry and is linked to the exact path of your executable. This can be a problem if you're upgrading to a newer Magicmida version that has fixes for your target. You can try moving your target to a different path or look around in the subkeys of `HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags`.

Old targets from 2007-2009 often don't unpack properly on modern Windows versions
(this can manifest as high CPU for more than 2 minutes). Some require the legacy
Pascal build on Windows XP. **The native v145 build targets Windows 10/11**, not XP.

## Anti-anti-debugging

Newer versions of Themida detect hardware breakpoints. In order to deal with this, injecting [ScyllaHide](https://github.com/x64dbg/ScyllaHide/releases) is supported. A suitable profile is shipped with Magicmida. Place `HookLibraryx86.dll` and `InjectorCLIx86.exe` beside the **Win32**
`Magicmida.exe`. For **x64**, `HookLibraryx64.dll` and `InjectorCLIx64.exe` are
mandatory; the injector must be newer than the legacy buggy build (PE timestamp
at least `0x6484FEF9`). The build copies the supplied profile to each output directory.
ScyllaHide executables are external runtime dependencies and are not downloaded
or bundled by the build. Do not overwrite scylla_hide.ini unless you know what you're doing.

## Command line usage

If you'd like to automate unpacking, it's possible to invoke Magicmida as a command line application.
To do so, pass the parameters `/unpack <filename>` to the matching architecture:

```powershell
$p = Start-Process -FilePath .\artifacts\bin\x64\Release\Magicmida.exe `
    -ArgumentList '/unpack "C:\path with spaces\target.exe"' -Wait -PassThru -NoNewWindow
$p.ExitCode
```

Native CLI options: `/help`, `/unpack <filename> [--no-data]`.
Exit codes: **0** success, **1** failure/cancellation, **2** invalid arguments.
Use `Start-Process -Wait` from PowerShell because this is a Windows GUI-subsystem
executable; `--no-data` disables automatic x86 data-section reconstruction.

## Unpacking applications with uiAccess=true

When unpacking an application that has `uiAccess="true"` in its manifest, you'll likely get process creation error code 740 even when running Magicmida as Administrator.
To get around this, you need to perform the following steps:

1. For the native build, change `uiAccess` to `true` in `native/Magicmida.manifest` and recompile. For the legacy Pascal build use `Magicmida.exe.manifest`.
1. You need to have some version of Windows SDK installed.
1. Run `makecert.exe -r -pe -ss MMTestCert MMTestCert.cer`.
1. Run `certmgr -add MMTestCert.cer -s -r localMachine root`.
1. In my case, I also had to manually copy the cert to the "Trusted Root Certificate" store.
1. Run `signtool.exe sign /s MMTestCert Magicmida.exe`.
1. Copy Magicmida to `C:\Program Files (x86)\Magicmida` and run it from there. This step is important because uiAccess applications need to be in a "trusted location".

## Building

### Visual Studio 2026 (native, recommended for this port)

Install **Desktop development with C++**, **MSVC v145 x86/x64 tools**, and a
Windows 10/11 SDK. No MFC, ATL, CMake, vcpkg, Python or Pascal compiler is needed
for a normal Windows build.

1. Open `Magicmida.slnx` and set **Magicmida** as the startup project.
2. Choose `Debug` or `Release`, and `Win32` or `x64` to match the target binary.
3. Build the solution. Output: `artifacts/bin/<platform>/<configuration>/`.

Or use PowerShell 7:

```powershell
./tools/Build-Native.ps1 -Platform Win32 -Configuration Release -Test
./tools/Build-Native.ps1 -Platform x64 -Configuration Release -Test
```

From a VS 2026 Developer Command Prompt:

```bat
msbuild Magicmida.slnx /m /p:Configuration=Release /p:Platform=x64
artifacts\bin\x64\Release\Magicmida.Tests.exe
```

`Native.Common.props` selects `/std:c++latest` (the compiler's available C++26
preview features), `/permissive-`, `/utf-8`, Unicode Win32 APIs and the matching
DLL CRT. This does not imply that MSVC implements every part of the final C++26
standard. A deployed Release build requires the appropriate Visual C++ runtime.

The solution contains:

| Project | Purpose |
| --- | --- |
| `Magicmida` | Native Win32 GUI and `/unpack` CLI |
| `Magicmida.Core` | Debugger, tracer, PE/import reconstruction and architecture-specific unpackers |
| `BeaEngine` | Vendored disassembler built from C source with the selected toolchain |
| `Magicmida.Tests` | Portable unit checks and Windows PE/debugger/IAT integration tests |

BeaEngine comes from the same [fork](https://github.com/Hendi48/beaengine) used
by the Pascal build, pinned at `6eaf28674c20e73f094ac0f7aee5a770c6a94b3a`.
See `third_party/beaengine/README.magicmida.md` for provenance and licensing.
The old `BeaEngineLib*.obj` files are **not linked into MSVC**.

The CI workflow `.github/workflows/native.yml` builds/tests all four combinations
on a Visual Studio 2026 Windows runner. Adding the workflow does not mean it has
already run for this working tree.

### Legacy Delphi / Free Pascal

The existing `Magicmida.dpr`, `.dproj`, `.lpi` and `.pas` files are retained.
The legacy application can be built with supported Delphi Community Edition
or Lazarus/Free Pascal; the previous warnings about Lazarus icons and older
FPC x64 stack alignment still apply.

## License

Magicmida is licensed under GPLv3.

The [BeaEngine](https://github.com/BeaEngine/beaengine) object and header files are licensed under LGPLv3.
