#!/usr/bin/env python3
"""Offline project/data completeness checks; does not claim to compile with MSVC."""
from pathlib import Path
import hashlib
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
NS = {'m': 'http://schemas.microsoft.com/developer/msbuild/2003'}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def path(value):
    return ROOT / value.replace('\\', '/')


def main():
    solution = ET.parse(ROOT / 'Magicmida.slnx').getroot()
    projects = {p.attrib['Path'] for p in solution.iter('Project')}
    require(projects == {'Magicmida.vcxproj', 'Magicmida.Core.vcxproj',
                         'BeaEngine.vcxproj', 'Magicmida.Tests.vcxproj'}, 'solution project inventory')
    require({p.attrib['Name'] for p in solution.findall('Configurations/Platform')} == {'Win32', 'x64'}, 'solution platforms')
    require({p.attrib['Name'] for p in solution.findall('Configurations/BuildType')} == {'Debug', 'Release'}, 'solution configurations')
    for file in solution.iter('File'):
        require(path(file.attrib['Path']).is_file(), f"Missing solution file: {file.attrib['Path']}")
    all_sources = set()
    all_headers = set()
    for project in sorted(projects):
        root = ET.parse(ROOT / project).getroot()
        require(root.findtext('m:PropertyGroup/m:PlatformToolset', namespaces=NS) == 'v145', f'{project}: toolset')
        valid_warnings = {'TurnOffAllWarnings', 'Level1', 'Level2', 'Level3', 'Level4', 'EnableAllWarnings'}
        for setting in ('WarningLevel', 'ExternalWarningLevel'):
            for value in root.findall(f'.//m:{setting}', NS):
                require(value.text in valid_warnings, f'{project}: invalid {setting}: {value.text}')
        configs = {p.attrib['Include'] for p in root.findall('m:ItemGroup/m:ProjectConfiguration', NS)}
        require(configs == {f'{c}|{p}' for c in ('Debug', 'Release') for p in ('Win32', 'x64')}, f'{project}: configuration matrix')
        filters = ET.parse(ROOT / (project + '.filters')).getroot()
        for kind in ('ClCompile', 'ClInclude', 'ResourceCompile', 'Manifest', 'Content'):
            entries = [p.attrib['Include'] for p in root.findall(f'm:ItemGroup/m:{kind}', NS)]
            require(len(entries) == len(set(entries)), f'{project}: duplicate {kind}')
            filtered = {p.attrib['Include'] for p in filters.findall(f'm:ItemGroup/m:{kind}', NS)}
            require(set(entries) == filtered, f'{project}: mismatched {kind} filters')
            for entry in entries:
                require(path(entry).is_file(), f'Missing project item: {entry}')
                require(path(entry).suffix.lower() not in {'.pas', '.obj', '.dpr'}, f'Legacy build dependency: {entry}')
            if kind == 'ClCompile':
                all_sources.update(path(e).resolve() for e in entries)
            if kind == 'ClInclude':
                all_headers.update(path(e).resolve() for e in entries)
        for ref in root.findall('m:ItemGroup/m:ProjectReference', NS):
            require(ref.attrib['Include'] in projects, 'reference missing from solution')
            referenced = ET.parse(path(ref.attrib['Include'])).getroot()
            require(ref.findtext('m:Project', namespaces=NS) == referenced.findtext('m:PropertyGroup/m:ProjectGuid', namespaces=NS), 'reference GUID mismatch')
    own_sources = {p.resolve() for folder in ('native', 'tests') for p in (ROOT / folder).glob('*.cpp')}
    own_headers = {p.resolve() for folder in ('native', 'tests') for p in (ROOT / folder).glob('*.hpp')}
    require(own_sources <= all_sources, f'Unlisted native/test sources: {own_sources - all_sources}')
    require(own_headers <= all_headers, f'Unlisted native/test headers: {own_headers - all_headers}')
    common = ET.parse(ROOT / 'Native.Common.props').getroot()
    require(common.findtext('m:ItemDefinitionGroup/m:ClCompile/m:LanguageStandard', namespaces=NS) == 'stdcpplatest', 'C++26 preview flag')
    baseline = json.loads((ROOT / 'tools/native-baseline.json').read_text())
    cpp = (ROOT / 'native/OneCoreUAP.cpp').read_text()
    pairs = re.findall(r'\{"([^"\\]+)",\s*"([^"\\]+)"\}', cpp)
    digest = hashlib.sha256('\n'.join(api + '\t' + dll for api, dll in pairs).encode('utf-8')).hexdigest()
    require(len(pairs) == baseline['onecore_count'] == 3003, 'OneCore mapping count')
    require(digest == baseline['onecore_sha256'], 'OneCore mapping differs from audited baseline')
    require(len(dict(pairs)) == 3003, 'duplicate OneCore APIs')
    native = '\n'.join(p.read_text() for p in (ROOT / 'native').glob('*.cpp'))
    patterns = baseline['unpacker_signatures']
    for pattern in patterns:
        require(f'"{pattern}"' in native, f'Missing unpacker signature: {pattern}')
    forbidden = {'.pas', '.dpr', '.dproj', '.dfm', '.lpi', '.lpr', '.lps', '.obj', '.res'}
    for directory, folders, files in os.walk(ROOT):
        folders[:] = [f for f in folders if f not in {'.git', '.cache', 'artifacts', '.vs', '__pycache__'}]
        for file in files:
            require(Path(file).suffix.lower() not in forbidden, f'Non-native source/prebuilt artifact remains: {Path(directory) / file}')
    for asset in re.findall(r'ICON "([^"\n]+)"', (ROOT / 'native/Magicmida.rc').read_text()):
        require((ROOT / 'native' / asset).is_file(), f'Missing resource asset: {asset}')
    require('BEA_ENGINE_STATIC' in (ROOT / 'Native.Common.props').read_text(), 'BeaEngine ABI setting')
    for license in ('LICENSE', 'third_party/beaengine/src/COPYING.txt', 'third_party/beaengine/src/COPYING.LESSER.txt'):
        require((ROOT / license).is_file(), f'Missing license: {license}')
    print(f'PASS: {len(projects)} projects, 4 configurations each, {len(own_sources)} C++ sources, '
          f'3,003 API mappings, {len(patterns)} unpacker signatures, licenses and filters')


if __name__ == '__main__':
    try:
        main()
    except (AssertionError, ET.ParseError, OSError) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        sys.exit(1)
