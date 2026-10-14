# Magicmida — native Visual Studio 2026 / C++26

A native Windows Themida unpacker for Win32 and x64 applications. Open
**[Magicmida.slnx](Magicmida.slnx)** in Visual Studio 2026 with the C++ desktop
workload, MSVC **v145**, and a Windows SDK. The solution uses `/std:c++latest`
(the installed compiler's C++26 preview support, not a claim of complete C++26 implementation).

This branch contains the native implementation, build/test tooling, resources,
and required BeaEngine C sources. Historical Delphi/Lazarus sources, projects,
prebuilt objects/resources and unused language bindings have been removed;
they remain available in Git history. No Delphi compiler or runtime is needed.

Use only on software you own or are authorized to inspect.
See [繁體中文說明與驗證紀錄](docs/VC2026-migration.md).

## Features

- **Unpack**: same-architecture EXE/DLL processing; output gets a `U` suffix.
  Win32 supports the implemented Themida 1/2/3 paths; x64 implements Themida 3.
- **Create data sections**: available in both builds, without filename/game-specific
  signatures. Right-click **Auto create data sections** for automatic splitting
  or **Restore layout from same-build reference**.
  - Automatic PE32 processing can split a merged region at a valid `BaseOfData`.
    It retains executable permissions and does **not** invent a `.rdata` boundary.
  - Reference mode restores section names/boundaries/permissions from an original
    PE of the **same build and RVA layout**, retaining the target's bytes, including
    initialized former BSS and unclassified regions. It handles nonidentity raw offsets.
  - PE32+ has no `BaseOfData`. Without a reference, it reports no safe automatic split
    and leaves the file unchanged. Compiler names, filenames and zero runs cannot
    reliably recover original read-only/writable boundaries.
  - Entry point, TLS callback/index permissions, header capacity, overlaps and
    alignment are checked. Structural checks cannot prove a reference is the same build.
- **Compact (keep all sections)** / `/shrink`: removes raw padding and zero tails
  while retaining virtual extents, all sections (including VM code), overlay bytes,
  and debug data. Updates debug file offsets. Refuses nonzero raw gaps and unsupported
  COFF metadata rather than silently discarding them. This is **not** the old
  section-deleting shrink operation and does not devirtualize code.
- **Dump process**: copies file-backed executable sections from the main module of
  a matching process, using its actual ASLR base, into a separate `.novm` output.
  Choose the matching main-module file, not an arbitrary DLL. Timestamp/architecture
  checks do not prove complete process/file identity; this operation does not repair
  relocations, remove VM protection or distinguish embedded data in executable sections.

Back up files before section editing/compaction: these operations overwrite the
selected file atomically and invalidate existing signatures. Certificate directory
entries are cleared; overlay bytes are retained, not re-signed or interpreted.

## CLI

```text
Magicmida.exe /help
Magicmida.exe /unpack <file> [--no-data]
Magicmida.exe /create-data <file> [--reference <same-build PE>]
Magicmida.exe /shrink <file>
```

For example, using the build matching your target:

```powershell
$p = Start-Process .\artifacts\bin\x64\Release\Magicmida.exe `
    -ArgumentList '/create-data "C:\work\applicationU.exe" --reference "C:\original\application.exe"' `
    -Wait -PassThru -NoNewWindow
$p.ExitCode
```

Use `Start-Process -Wait` because this is a GUI-subsystem executable. Exit codes:
**0** success, **1** failure/cancellation (or no safe split for standalone
`/create-data`), **2** invalid arguments. An unavailable optional automatic split
is logged without invalidating an otherwise successful unpack. `--no-data`
disables this optional postprocessing.

## Build and test

PowerShell 7 with VS2026 build tools available:

```powershell
./tools/Build-Native.ps1 -Platform Win32 -Configuration Debug -Test
./tools/Build-Native.ps1 -Platform Win32 -Configuration Release -Test
./tools/Build-Native.ps1 -Platform x64 -Configuration Debug -Test
./tools/Build-Native.ps1 -Platform x64 -Configuration Release -Test
```

Or from a VS2026 Developer Command Prompt:

```bat
msbuild Magicmida.slnx /m /p:Configuration=Release /p:Platform=x64
artifacts\bin\x64\Release\Magicmida.Tests.exe
```

Outputs: `artifacts/bin/<Platform>/<Configuration>/`. The four projects are the
GUI/CLI application, native core library, BeaEngine, and native tests. Runtime:
Windows 10/11 with the matching Visual C++ runtime (Debug builds need the debug CRT).
Windows XP is not supported.

Validation includes 10,532 portable checks, synthetic PE/TLS/layout tests,
real Windows sparse-import binding, debugger/trace/cancellation integration,
CLI checks, and starting a real MSVC test executable after section restoration
and compaction. Linux cross-compilation is not Windows execution.
The preceding IAT/debugger revision passed all four VS2026 CI configurations;
the expanded section/cleanup revision requires its own CI result.

## External runtime dependency and limits

Place ScyllaHide files beside the matching `Magicmida.exe`:

- x86: `InjectorCLIx86.exe` and `HookLibraryx86.dll` (optional).
- x64: `InjectorCLIx64.exe` and `HookLibraryx64.dll` (required); injector PE timestamp
  must be at least `0x6484FEF9` to exclude a known-bad older version.

The build copies `scylla_hide.ini`; it does not download or bundle the injector.
Keep the supplied profile unless you understand the changes. Source:
[ScyllaHide](https://github.com/x64dbg/ScyllaHide/releases).

- Removing game-specific section heuristics is **not** a guarantee that all Themida
  targets unpack or run. VM anti-dumps and complete devirtualization are not solved.
- Rebuilt DLLs can lack usable relocations. Preserved, unclassified IAT-range data
  may still contain unresolved imports and needs runtime verification.
- Do not enable Windows compatibility mode for this tool or the target. AppCompat
  shims can interfere; previous crashes can cause Windows to retain compatibility
  settings for a specific executable path.
- Targets with `uiAccess=true` require an appropriately signed/trusted tool deployment;
  edit `native/Magicmida.manifest` only if you understand those Windows requirements.

## Licenses and provenance

Magicmida: **GPLv3**, see [LICENSE](LICENSE).
BeaEngine: **LGPLv3 or later**, vendored from the
[Hendi48 fork](https://github.com/Hendi48/beaengine) at
`6eaf28674c20e73f094ac0f7aee5a770c6a94b3a`.
See [vendor provenance and redistribution notes](third_party/beaengine/README.magicmida.md).
Required source and license texts are retained; no prebuilt objects are linked.
