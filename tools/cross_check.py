#!/usr/bin/env python3
"""Optional Linux/Clang cross-build check. Not a substitute for MSVC/Windows tests.

Supply an installed Zig executable (tested with Zig 0.17.0). No downloads are
performed. Windows binaries remain in ignored artifacts/cross/ directories.
"""
import argparse
import concurrent.futures
from pathlib import Path
import subprocess
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', required=True, type=Path)
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    zig = str(args.zig.resolve())
    base = ROOT / 'artifacts/cross'
    base.mkdir(parents=True, exist_ok=True)
    include = Path(zig).parent / 'lib/libc/include/any-windows-any'
    log = []

    def run(command):
        result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return result.returncode, result.stdout

    for source, dest in [('native/Magicmida.rc', 'Magicmida.res'),
                         ('artifacts/cross/manifest.rc', 'manifest.res')]:
        if source.endswith('/manifest.rc'):
            (base / 'manifest.rc').write_text('1 24 "native/Magicmida.manifest"\n')
        code, output = run([zig, 'rc', '/I', 'native', '/I', '.', '/I', str(include), '/fo', str(base / dest), source])
        if code:
            raise RuntimeError(f'Resource compilation failed: {source}\n{output}')
    own = sorted((ROOT / 'native').glob('*.cpp')) + sorted((ROOT / 'tests').glob('*.cpp'))
    bea = ROOT / 'third_party/beaengine/src/BeaEngine.c'
    combinations = [(a, c) for a in ('Win32', 'x64') for c in ('Debug', 'Release')]

    def compile_one(item):
        arch, config, source = item
        target = ('x86_64' if arch == 'x64' else 'x86') + '-windows-gnu'
        folder = base / arch / config
        folder.mkdir(parents=True, exist_ok=True)
        command = [zig, 'cc' if source == bea else 'c++', '-target', target,
                   '-O0' if config == 'Debug' else '-O2', '-g',
                   '-D_DEBUG' if config == 'Debug' else '-DNDEBUG',
                   '-DUNICODE', '-D_UNICODE', '-DBEA_ENGINE_STATIC', '-Inative', '-Itests',
                   '-Ithird_party/beaengine/include']
        if source != bea:
            command += ['-std=c++2c', '-Wall', '-Wextra', '-Werror']
        command += ['-c', str(source), '-o', str(folder / (source.stem + '.obj'))]
        code, output = run(command)
        return f'{arch}/{config} {source.relative_to(ROOT)}', code, output

    jobs = [(a, c, s) for a, c in combinations for s in own + [bea]]
    failed = False
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for label, code, output in pool.map(compile_one, jobs):
            print(f'{"FAIL" if code else "PASS"}: {label}', flush=True)
            log.append(f'{label}: {code}\n{output}')
            if code:
                print(output)
                failed = True
    (base / 'compile.log').write_text('\n'.join(log))
    if failed:
        return 1
    core = [p.stem for p in (ROOT / 'native').glob('*.cpp') if p.stem != 'Main'] + ['BeaEngine']
    for arch, config in combinations:
        folder = base / arch / config
        target = ('x86_64' if arch == 'x64' else 'x86') + '-windows-gnu'
        for app in ('Magicmida', 'Magicmida.Tests'):
            objs = [str(folder / (name + '.obj')) for name in core]
            if app == 'Magicmida':
                objs += [str(folder / 'Main.obj'), str(base / 'Magicmida.res'), str(base / 'manifest.res'), '-municode', '-Wl,--subsystem,windows']
            else:
                objs += [str(folder / 'NativeTests.obj'), str(folder / 'PortableTests.obj')]
            code, output = run([zig, 'c++', '-target', target, *objs, '-lcomctl32', '-lcomdlg32', '-luser32',
                                '-lshell32', '-ladvapi32', '-lgdi32', '-o', str(folder / (app + '.exe'))])
            log.append(f'{arch}/{config}/{app} link: {code}\n{output}')
            print(f'{"FAIL" if code else "PASS"}: link {arch}/{config}/{app}', flush=True)
            if code:
                print(output)
                failed = True
            else:
                data = (folder / (app + '.exe')).read_bytes()
                nt = struct.unpack_from('<I', data, 0x3c)[0]
                machine = struct.unpack_from('<H', data, nt + 4)[0]
                subsystem = struct.unpack_from('<H', data, nt + 24 + 68)[0]
                expected_machine = 0x8664 if arch == 'x64' else 0x14c
                expected_subsystem = 2 if app == 'Magicmida' else 3
                if machine != expected_machine or subsystem != expected_subsystem:
                    print(f'FAIL: PE architecture/subsystem mismatch in {folder / app}')
                    failed = True
    (base / 'build.log').write_text('\n'.join(log))
    return 1 if failed else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, RuntimeError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
