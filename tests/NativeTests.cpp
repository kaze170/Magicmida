// SPDX-License-Identifier: GPL-3.0-only
#include "Test.hpp"
#include "ThemidaCommon.hpp"
#include "Patcher.hpp"
#include <iostream>
using namespace mm;
namespace {
Bytes fixture() {
    Bytes data(0xa00);
    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x80;
    store(data, 0, dos);
    IMAGE_NT_HEADERS nt{};
    nt.Signature = IMAGE_NT_SIGNATURE;
    nt.FileHeader.NumberOfSections = 2;
    nt.FileHeader.SizeOfOptionalHeader = sizeof(nt.OptionalHeader);
#ifdef _WIN64
    nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt.OptionalHeader.ImageBase = 0x140000000ULL;
#else
    nt.FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
    nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    nt.OptionalHeader.ImageBase = 0x400000;
    nt.OptionalHeader.BaseOfData = 0x2000;
#endif
    nt.OptionalHeader.SizeOfHeaders = 0x200;
    nt.OptionalHeader.SizeOfImage = 0x3000;
    nt.OptionalHeader.SectionAlignment = 0x1000;
    nt.OptionalHeader.FileAlignment = 0x200;
    nt.OptionalHeader.AddressOfEntryPoint = 0x1000;
    nt.OptionalHeader.SizeOfCode = 0x600;
    nt.OptionalHeader.NumberOfRvaAndSizes = 16;
    store(data, 0x80, nt);
    IMAGE_SECTION_HEADER text{};
    std::memcpy(text.Name, ".text", 5);
    text.VirtualAddress = 0x1000;
    text.Misc.VirtualSize = 0x600;
    text.SizeOfRawData = 0x600;
    text.PointerToRawData = 0x200;
    text.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
    IMAGE_SECTION_HEADER rdata{};
    std::memcpy(rdata.Name, ".rdata", 6);
    rdata.VirtualAddress = 0x2000;
    rdata.Misc.VirtualSize = 0x400;
    rdata.SizeOfRawData = 0x200;
    rdata.PointerToRawData = 0x800;
    rdata.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;
    store(data, 0x80 + sizeof(nt), text);
    store(data, 0x80 + sizeof(nt) + sizeof(text), rdata);
    return data;
}
void peTests() {
    using test::rejects;
    using test::require;
    auto bytes = fixture();
    PEImage pe(bytes);
    require(pe.sections.size() == 2, "PE sections");
    require(pe.sections[0].name() == ".text", "section name");
    require(!pe.sectionAt(0x800), "section lookup rejects gaps and lower bounds");
    require(pe.sectionAt(0x2000) == 1, "section lookup start");
    require(!pe.sectionAt(0x2400), "exclusive section end");
    require(pe.fileOffset(0x1020, 4) == 0x220, "RVA conversion");
    require(pe.fileOffset(0x100) == 0x100, "header RVA conversion");
    rejects([&] { pe.fileOffset(0x2300); }, "virtual-only data has no file offset");
    rejects([&] { pe.fileOffset(0x21ff, 2); }, "RVA range crossing raw boundary");
    Section s;
    s.rename("abcdefghijk");
    require(s.name() == "abcdefgh", "truncate section name");
    s.rename("x");
    require(s.name() == "x" && s.header.Name[7] == 0, "rename clears trailing bytes");
    const auto sectionEnd = 0x80 + sizeof(IMAGE_NT_HEADERS) + 2 * sizeof(IMAGE_SECTION_HEADER);
    bytes[sectionEnd] = 0xa5;
    pe.save(bytes);
    require(bytes[sectionEnd] == 0xa5, "save preserves unused header data");
    for (std::size_t cut = 0; cut < sectionEnd; ++cut)
        rejects([&] { PEImage bad(std::span<const BYTE>(bytes).first(cut)); }, "truncated PE rejected");
    auto mutate = [&](auto value, std::size_t offset) {
        auto copy = fixture();
        store(copy, offset, value);
        rejects([&] { PEImage bad(copy); }, "invalid header rejected");
    };
    mutate(WORD(0), 0);
    mutate(LONG(-1), offsetof(IMAGE_DOS_HEADER, e_lfanew));
    mutate(LONG(INT32_MAX), offsetof(IMAGE_DOS_HEADER, e_lfanew));
    mutate(DWORD(0), 0x80);
    mutate(WORD(IMAGE_FILE_MACHINE_ARM64),
           0x80 + offsetof(IMAGE_NT_HEADERS, FileHeader) + offsetof(IMAGE_FILE_HEADER, Machine));
    mutate(WORD(0),
           0x80 + offsetof(IMAGE_NT_HEADERS, FileHeader) + offsetof(IMAGE_FILE_HEADER, NumberOfSections));
    mutate(DWORD(0), 0x80 + offsetof(IMAGE_NT_HEADERS, OptionalHeader) +
                         offsetof(IMAGE_OPTIONAL_HEADER, FileAlignment));
    mutate(DWORD(3), 0x80 + offsetof(IMAGE_NT_HEADERS, OptionalHeader) +
                         offsetof(IMAGE_OPTIONAL_HEADER, SectionAlignment));
    pe.sanitize();
    require(pe.sections[0].header.PointerToRawData == 0x1000, "memory-layout sections");
    require(pe.sections[0].header.Characteristics & IMAGE_SCN_MEM_WRITE, "merged .text writable");
    bytes.resize(0x3000);
    auto &added = pe.append(".import", 0x123);
    require(added.header.VirtualAddress == 0x3000 && added.header.SizeOfRawData == 0x200,
            "new section alignment");
    bytes.resize(0x3200);
    pe.save(bytes);
    PEImage roundtrip(bytes);
    require(roundtrip.sections.size() == 3 && roundtrip.sections[2].name() == ".import",
            "section append roundtrip");
    require(roundtrip.nt.OptionalHeader.SizeOfImage == 0x4000, "image size section aligned");
    auto small = fixture();
    PEImage full(small);
    for (int i = 0; i < 20; ++i)
        full.append(".extra", 0x1000);
    rejects([&] { full.save(small); }, "section table overflow rejected");
}
void manifestTests() {
    using test::rejects;
    using test::require;
    auto data = fixture();
    PEImage pe(data);
    pe.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE] = {0x2080, 0x80};
    const std::size_t base = 0x880;
    IMAGE_RESOURCE_DIRECTORY root{};
    root.NumberOfIdEntries = 1;
    store(data, base, root);
    IMAGE_RESOURCE_DIRECTORY_ENTRY type{};
    type.Id = 24;
    type.DataIsDirectory = 1;
    type.OffsetToDirectory = 0x20;
    store(data, base + 16, type);
    store(data, base + 0x20, root);
    store<DWORD>(data, base + 0x30, 2);
    pe.switchManifest(data, 2, 1);
    require(load<DWORD>(data, base + 0x30) == 1, "DLL-to-EXE manifest at nonzero resource offset");
    pe.switchManifest(data, 1, 2);
    require(load<DWORD>(data, base + 0x30) == 2, "EXE-to-DLL manifest");
    pe.switchManifest(data, 1, 9);
    require(load<DWORD>(data, base + 0x30) == 2, "manifest mismatch unchanged");
    type.OffsetToDirectory = 0x7fffffff;
    store(data, base + 16, type);
    rejects([&] { pe.switchManifest(data, 2, 1); }, "malformed resource directory bounded");
}
void trimTests() {
    auto original = fixture();
    PEImage pe(original);
    pe.sections[0].header.PointerToRawData = 0x1000;
    pe.sections[0].header.SizeOfRawData = 0x201000;
    pe.sections[0].header.Misc.VirtualSize = 0x201000;
    pe.sections[1].header.PointerToRawData = 0x202000;
    pe.sections[1].header.VirtualAddress = 0x202000;
    pe.sections[1].header.SizeOfRawData = 0x200;
    Bytes data(0x202200);
    data[0x1000] = 0x55;
    data[0x202000] = 0xa5;
    auto oldSize = data.size();
    pe.trimHugeSections(data);
    test::require(pe.sections[0].header.SizeOfRawData == 0x200, "trim large zero tail");
    test::require(pe.sections[1].header.PointerToRawData == 0x1200, "trim shifts following raw offsets");
    test::require(data[pe.fileOffset(0x202000)] == 0xa5, "trim retains following section and RVA conversion");
    test::require(data.size() < oldSize, "trim reduces physical image");
}
void disassemblyTests() {
    DISASM dis{};
    const std::array<BYTE, 6> call{0xff, 0x15, 0x10, 0, 0, 0};
    test::require(disassemble(dis, call, 0x1000) == 6, "BeaEngine indirect call length");
    test::require(dis.Operand1.Memory.Displacement == 0x10, "BeaEngine operand ABI");
    const std::array<BYTE, 1> ret{0xc3};
    test::require(disassemble(dis, ret) == 1, "single-byte instruction at end");
    const std::array<BYTE, 1> truncated{0xe8};
    test::rejects([&] { disassemble(dis, truncated); }, "truncated instruction rejected");
    test::rejects([&] { disassemble(dis, {}); }, "empty disassembly rejected");
}
struct TemporaryFolder {
    Path path;
    TemporaryFolder() {
        path = std::filesystem::temp_directory_path() /
               (L"Magicmida 測試 " + std::to_wstring(GetCurrentProcessId()) + L"-" +
                std::to_wstring(GetTickCount64()));
        std::filesystem::create_directory(path);
    }
    ~TemporaryFolder() {
        std::error_code error;
        std::filesystem::remove_all(path, error);
    }
};
void fileTests() {
    TemporaryFolder dir;
    auto file = dir.path / L"空白 測試.bin";
    Bytes first{1, 2, 3}, second{4, 5, 6, 7};
    writeFileAtomic(file, first);
    test::require(readFile(file) == first, "Unicode file IO");
    writeFileAtomic(file, second);
    test::require(readFile(file) == second, "atomic replacement");
    check(SetFileAttributesW(file.c_str(), FILE_ATTRIBUTE_READONLY), "SetFileAttributes(test)");
    try {
        test::rejects([&] { writeFileAtomic(file, first); }, "failed replacement reported");
        check(SetFileAttributesW(file.c_str(), FILE_ATTRIBUTE_NORMAL), "SetFileAttributes(test restore)");
    } catch (...) {
        SetFileAttributesW(file.c_str(), FILE_ATTRIBUTE_NORMAL);
        throw;
    }
    test::require(readFile(file) == second, "failed write preserves original");
    unsigned files = 0;
    for (auto &entry : std::filesystem::directory_iterator(dir.path)) {
        (void)entry;
        ++files;
    }
    test::require(files == 1, "temporary output cleaned up");
    test::require(unpackedPath(Path(L"C:\\space path\\target.dll")) == Path(L"C:\\space path\\targetU.dll"),
                  "U output suffix");
    test::require(widen(narrow(L"繁體中文 Δ")) == L"繁體中文 Δ", "UTF-8 roundtrip");
}
Bytes sectionFixture(bool reference) {
    auto bytes = fixture();
    PEImage pe(bytes);
    pe.nt.OptionalHeader.SizeOfHeaders = 0x400;
    pe.nt.OptionalHeader.SizeOfImage = 0x6000;
    pe.nt.OptionalHeader.MajorLinkerVersion = 9; // not tied to MSVC14 or a game
#ifndef _WIN64
    pe.nt.OptionalHeader.BaseOfData = 0x2000;
#endif
    auto section = [](const char *name, DWORD va, DWORD raw, DWORD size, DWORD flags) {
        Section s;
        s.rename(name);
        s.header.VirtualAddress = va;
        s.header.PointerToRawData = raw;
        s.header.Misc.VirtualSize = 0x1000;
        s.header.SizeOfRawData = size;
        s.header.Characteristics = flags;
        return s;
    };
    constexpr DWORD code = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    constexpr DWORD read = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    constexpr DWORD write = read | IMAGE_SCN_MEM_WRITE;
    if (reference) {
        pe.sections = {section(".text", 0x1000, 0x400, 0x200, code),
                       section(".rdata", 0x2000, 0x600, 0x200, read),
                       section(".data", 0x3000, 0x800, 0x200, write),
                       section(".bss", 0x4000, 0, 0,
                               IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE),
                       section(".aux", 0x5000, 0xa00, 0x200, code)};
        bytes.resize(0xc00);
    } else {
        auto merged = section(".merged", 0x1000, 0x400, 0x4000, code | IMAGE_SCN_MEM_WRITE);
        merged.header.Misc.VirtualSize = 0x4000;
        pe.sections = {merged, section(".aux", 0x5000, 0x4400, 0x200, code)};
        bytes.resize(0x4600);
        for (auto offset : {0x400, 0x1400, 0x2400, 0x3400, 0x4400})
            bytes[offset] = BYTE(offset / 0x100);
        bytes.insert(bytes.end(), {0xde, 0xad, 0xbe, 0xef}); // overlay must survive
    }
    pe.save(bytes);
    return bytes;
}
Bytes mappedPayload(const Bytes &bytes) {
    PEImage pe(bytes);
    Bytes mapped(pe.nt.OptionalHeader.SizeOfImage);
    for (const auto &s : pe.sections) {
        bounds(bytes.size(), s.header.PointerToRawData, s.header.SizeOfRawData);
        bounds(mapped.size(), s.header.VirtualAddress, s.header.SizeOfRawData);
        std::copy_n(bytes.begin() + s.header.PointerToRawData, s.header.SizeOfRawData,
                    mapped.begin() + s.header.VirtualAddress);
    }
    return mapped;
}
void patcherTests() {
    TemporaryFolder folder;
    auto target = folder.path / L"ordinary application.exe", ref = folder.path / L"same build reference.exe";
    auto source = sectionFixture(false), reference = sectionFixture(true);
    writeFileAtomic(target, source);
    writeFileAtomic(ref, reference);
    test::require(Patcher(target, {}).createData(ref), "reference layout supported on both architectures");
    auto restored = readFile(target);
    PEImage pe(restored);
    test::require(pe.sections.size() == 5,
                  "merged section restored into code, readonly, writable and BSS regions");
    test::require(pe.sections[1].name() == ".rdata" && !(pe.sections[1].header.Characteristics &
                                                         (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)),
                  "reference readonly permissions restored");
    test::require((pe.sections[2].header.Characteristics & IMAGE_SCN_MEM_WRITE) &&
                      !(pe.sections[2].header.Characteristics & IMAGE_SCN_MEM_EXECUTE),
                  "reference writable non-executable data restored");
    test::require(pe.sections[3].header.SizeOfRawData == 0x1000 && restored[0x3400] == 0x34,
                  "initialized former BSS is not discarded");
    test::require(mappedPayload(source) == mappedPayload(restored),
                  "reference split preserves all mapped bytes");
    test::require(std::equal(source.begin() + 0x400, source.end(), restored.begin() + 0x400),
                  "reference split changes no raw payload or overlay bytes");
    test::require(Patcher(target, {}).createData(ref) && readFile(target) == restored,
                  "reference restoration is idempotent");
    auto renamed = folder.path / L"MapleStory.exe";
    writeFileAtomic(renamed, source);
    Patcher(renamed, {}).createData(ref);
    test::require(readFile(renamed) == restored, "filename never selects reconstruction strategy");
    Patcher(target, {}).shrink();
    auto compact = readFile(target);
    PEImage compactPE(compact);
    test::require(compact.size() < restored.size(), "compaction reduces zero-padded file size");
    test::require(compactPE.sections.size() == 5 && compactPE.sections.back().name() == ".aux",
                  "compaction keeps executable sections without directory references");
    test::require(mappedPayload(compact) == mappedPayload(restored),
                  "compaction preserves complete virtual memory image");
    test::require(std::equal(source.end() - 4, source.end(), compact.end() - 4),
                  "compaction preserves overlay");
    Patcher(target, {}).shrink();
    test::require(readFile(target) == compact, "compaction is idempotent");
    writeFileAtomic(target, source);
#ifdef _WIN64
    test::require(!Patcher(target, {}).createData() && readFile(target) == source,
                  "PE32+ without reference must not invent data boundaries");
#else
    test::require(Patcher(target, {}).createData(),
                  "PE32 BaseOfData works without compiler or filename assumptions");
    auto automatic = readFile(target);
    PEImage autoPE(automatic);
    test::require(autoPE.sections.size() == 3 && autoPE.sections[1].header.VirtualAddress == 0x2000,
                  "automatic split uses BaseOfData RVA with nonidentity raw offsets");
    test::require(mappedPayload(automatic) == mappedPayload(source), "automatic split preserves bytes");
    test::require(autoPE.sections[1].header.Characteristics & IMAGE_SCN_MEM_EXECUTE,
                  "automatic split does not guess non-executable data permissions");
    test::require(!Patcher(target, {}).createData() && readFile(target) == automatic,
                  "already separated automatic layout is a no-op");
#endif
    auto rejectsLayout = [&](Bytes input, Bytes layout, const char *message) {
        writeFileAtomic(target, input);
        writeFileAtomic(ref, layout);
        test::rejects([&] { Patcher(target, {}).createData(ref); }, message);
        test::require(readFile(target) == input, "failed reconstruction leaves input file intact");
    };
    auto smallHeader = source;
    PEImage small(smallHeader);
    small.nt.OptionalHeader.SizeOfHeaders = 0x200;
    small.save(smallHeader);
    rejectsLayout(smallHeader, reference, "insufficient section header capacity rejected");
    auto occupied = source;
    PEImage occupiedPE(occupied);
    auto headerEnd = std::size_t(occupiedPE.ntOffset) + sizeof(occupiedPE.nt) +
                     occupiedPE.sections.size() * sizeof(IMAGE_SECTION_HEADER);
    occupied[headerEnd] = 0x55;
    rejectsLayout(occupied, reference, "nonzero header padding is not overwritten");
    auto headerDir = source;
    PEImage hd(headerDir);
    hd.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE] = {rva32(headerEnd), 4};
    hd.save(headerDir);
    rejectsLayout(headerDir, reference, "even zero-filled header directories are protected");
    auto overlap = reference;
    PEImage overlapPE(overlap);
    overlapPE.sections[1].header.VirtualAddress = 0x1000;
    overlapPE.save(overlap);
    rejectsLayout(source, overlap, "overlapping reference rejected");
    auto outside = reference;
    PEImage outsidePE(outside);
    outsidePE.sections.back().header.VirtualAddress = 0x7000;
    outsidePE.nt.OptionalHeader.SizeOfImage = 0x8000;
    outsidePE.save(outside);
    rejectsLayout(source, outside, "unmapped reference section rejected");
    auto noExecute = reference;
    PEImage nx(noExecute);
    nx.sections.front().header.Characteristics &= ~IMAGE_SCN_MEM_EXECUTE;
    nx.save(noExecute);
    rejectsLayout(source, noExecute, "non-executable entry point rejected");
    auto tlsSource = source;
    PEImage tlsPE(tlsSource);
    tlsPE.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS] = {0x2080, sizeof(IMAGE_TLS_DIRECTORY)};
    IMAGE_TLS_DIRECTORY tls{};
    tls.AddressOfIndex = tlsPE.nt.OptionalHeader.ImageBase + 0x3000;
    tls.AddressOfCallBacks = tlsPE.nt.OptionalHeader.ImageBase + 0x2180;
    store(tlsSource, 0x1480, tls);
    store<Address>(tlsSource, 0x1580, Address(tlsPE.nt.OptionalHeader.ImageBase + 0x1000));
    tlsPE.save(tlsSource);
    auto readonlyIndex = reference;
    PEImage ri(readonlyIndex);
    ri.sections[2].header.Characteristics &= ~IMAGE_SCN_MEM_WRITE;
    ri.save(readonlyIndex);
    rejectsLayout(tlsSource, readonlyIndex, "TLS index must remain writable");
    auto invalidCallback = tlsSource;
    store<Address>(invalidCallback, 0x1580, Address(tlsPE.nt.OptionalHeader.ImageBase + 0x2000));
    rejectsLayout(invalidCallback, reference, "TLS callbacks must remain executable");
    writeFileAtomic(target, tlsSource);
    writeFileAtomic(ref, reference);
    test::require(Patcher(target, {}).createData(ref), "valid TLS layout accepted");
    test::require(mappedPayload(readFile(target)) == mappedPayload(tlsSource),
                  "TLS directory, callbacks and index bytes preserved");
    auto debugSource = source;
    PEImage debugPE(debugSource);
    debugPE.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG] = {0x2100,
                                                                            sizeof(IMAGE_DEBUG_DIRECTORY)};
    IMAGE_DEBUG_DIRECTORY debug{};
    debug.Type = IMAGE_DEBUG_TYPE_CODEVIEW;
    debug.SizeOfData = 0x100;
    debug.PointerToRawData = 0x2580;
    debug.AddressOfRawData = 0x3180;
    store(debugSource, 0x1500, debug);
    debugSource[0x2580] = 0x52;
    debugPE.save(debugSource);
    writeFileAtomic(target, debugSource);
    Patcher(target, {}).createData(ref);
    Patcher(target, {}).shrink();
    auto debugFile = readFile(target);
    PEImage debugOut(debugFile);
    auto relocated = load<IMAGE_DEBUG_DIRECTORY>(debugFile, debugOut.fileOffset(0x2100, sizeof(debug)));
    test::require(relocated.PointerToRawData == debugOut.fileOffset(0x3180, 0x100),
                  "debug file pointer relocated after compaction");
    test::require(std::equal(debugSource.begin() + 0x2580, debugSource.begin() + 0x2680,
                             debugFile.begin() + relocated.PointerToRawData),
                  "debug zero tail retained at declared size");
    debug.PointerToRawData = 0x4600;
    debug.SizeOfData = 4;
    debug.AddressOfRawData = 0;
    store(debugSource, 0x1500, debug);
    writeFileAtomic(target, debugSource);
    Patcher(target, {}).shrink();
    debugFile = readFile(target);
    PEImage overlayPE(debugFile);
    relocated = load<IMAGE_DEBUG_DIRECTORY>(debugFile, overlayPE.fileOffset(0x2100, sizeof(debug)));
    test::require(relocated.PointerToRawData == debugFile.size() - 4, "debug overlay file pointer relocated");
    auto gap = source;
    gap.insert(gap.begin() + 0x4400, 0x400, 0);
    gap[0x4500] = 0x55;
    PEImage gapPE(gap);
    gapPE.sections[1].header.PointerToRawData = 0x4800;
    gapPE.save(gap);
    writeFileAtomic(target, gap);
    test::rejects([&] { Patcher(target, {}).shrink(); }, "compaction refuses nonzero unclassified raw gaps");
    test::require(readFile(target) == gap, "failed compaction leaves original file intact");
}
void processCopyTests() {
    TemporaryFolder folder;
    auto input = folder.path / L"copy.dll";
    auto original = readFile(executablePath());
    writeFileAtomic(input, original);
    Patcher(input, {}).dumpProcess(GetCurrentProcessId());
    auto output = folder.path / L"copy.novm.dll";
    auto copied = readFile(output);
    PEImage pe(copied);
    auto base = reinterpret_cast<Address>(GetModuleHandleW(nullptr));
    for (const auto &s : pe.sections)
        if ((s.header.Characteristics & IMAGE_SCN_MEM_EXECUTE) && s.header.SizeOfRawData) {
            auto bytes =
                readMemory(GetCurrentProcess(), base + s.header.VirtualAddress, s.header.SizeOfRawData);
            test::require(std::equal(bytes.begin(), bytes.end(), copied.begin() + s.header.PointerToRawData),
                          "process copy uses actual module base and executable section ranges");
        }
    test::require(readFile(input) == original, "process copy preserves selected file and extension");
    PEImage mismatch(original);
    ++mismatch.nt.FileHeader.TimeDateStamp;
    mismatch.save(original);
    writeFileAtomic(input, original);
    test::rejects([&] { Patcher(input, {}).dumpProcess(GetCurrentProcessId()); },
                  "process/file timestamp mismatch rejected");
    test::require(readFile(output) == copied, "failed process copy does not replace earlier output");
}
void temporaryDllTests() {
    TemporaryFolder folder;
    auto data = fixture();
    PEImage pe(data);
    pe.nt.FileHeader.Characteristics |= IMAGE_FILE_DLL;
    pe.save(data);
    auto dll = folder.path / L"fixture.dll";
    writeFileAtomic(dll, data);
    auto existing = dll;
    existing += L".MM-" + std::to_wstring(GetCurrentProcessId()) + L".exe";
    const Bytes marker{9, 8, 7};
    writeFileAtomic(existing, marker);
    class FailingProbe final : public DebuggerCore {
        void onStart() override {}
        void onHardware(HANDLE, Address, CONTEXT &) override {}
        SoftAction onSoftware(HANDLE, Address) override { return SoftAction::Clear; }

      public:
        using DebuggerCore::DebuggerCore;
    };
    std::atomic_bool cancel = false;
    {
        FailingProbe probe(dll, {}, cancel);
        test::require(!probe.run(), "existing DLL temporary path rejected");
    }
    test::require(readFile(existing) == marker, "failed DLL preparation never deletes existing file");
}
void memoryTests() {
    void *reserve = VirtualAlloc(nullptr, 0x3000, MEM_RESERVE, PAGE_NOACCESS);
    if (!reserve)
        winError("VirtualAlloc(test)");
    try {
        auto base = reinterpret_cast<Address>(reserve);
        if (!VirtualAlloc(reserve, 0x1000, MEM_COMMIT, PAGE_READWRITE) ||
            !VirtualAlloc(reinterpret_cast<void *>(base + 0x2000), 0x1000, MEM_COMMIT, PAGE_READWRITE))
            winError("VirtualAlloc(test commit)");
        *static_cast<BYTE *>(reserve) = 0x5a;
        *reinterpret_cast<BYTE *>(base + 0x2000) = 0xa5;
        DWORD old{};
        check(VirtualProtect(reserve, 0x1000, PAGE_READONLY, &old), "VirtualProtect(test)");
        writeValue<BYTE>(GetCurrentProcess(), base, 0x33);
        MEMORY_BASIC_INFORMATION mbi{};
        VirtualQuery(reserve, &mbi, sizeof(mbi));
        test::require(mbi.Protect == PAGE_READONLY, "remote write restores page protection");
        auto image = Dumper::imageMemory(GetCurrentProcess(), base, 0x3000);
        test::require(image[0] == 0x33 && image[0x2000] == 0xa5 && image[0x1000] == 0,
                      "region dump handles reserved holes");
        writeValue<BYTE>(GetCurrentProcess(), base + 0x2000, 0xa6);
        VirtualQuery(reinterpret_cast<void *>(base + 0x2000), &mbi, sizeof(mbi));
        test::require(mbi.Protect == PAGE_READWRITE, "writable data remains non-executable");
        test::rejects([&] { protectMemory(GetCurrentProcess(), base, 0x3000, PAGE_NOACCESS); },
                      "guard rejects an uncommitted gap");
        VirtualQuery(reserve, &mbi, sizeof(mbi));
        test::require(mbi.Protect == PAGE_READONLY, "failed guard preflight preserves first page");
        Bytes invalidWrite(0x2000, 0x44);
        test::rejects(
            [&] { writeMemory(GetCurrentProcess(), base, invalidWrite.data(), invalidWrite.size()); },
            "write rejects an uncommitted gap");
        test::require(*static_cast<BYTE *>(reserve) == 0x33, "failed write preflight preserves data");
        if (!VirtualAlloc(reinterpret_cast<void *>(base + 0x1000), 0x1000, MEM_COMMIT, PAGE_READWRITE))
            winError("VirtualAlloc(test middle)");
        const std::array<BYTE, 2> crossing{0xcc, 0xdd};
        writeMemory(GetCurrentProcess(), base + 0xfff, crossing.data(), crossing.size());
        VirtualQuery(reserve, &mbi, sizeof(mbi));
        test::require(mbi.Protect == PAGE_READONLY, "cross-page write restores readonly region");
        VirtualQuery(reinterpret_cast<void *>(base + 0x1000), &mbi, sizeof(mbi));
        test::require(mbi.Protect == PAGE_READWRITE, "cross-page write preserves writable region");
        test::require(*reinterpret_cast<BYTE *>(base + 0xfff) == 0xcc &&
                          *reinterpret_cast<BYTE *>(base + 0x1000) == 0xdd,
                      "cross-page write content");
        protectMemory(GetCurrentProcess(), base, 0x3000, PAGE_NOACCESS);
        VirtualQuery(reserve, &mbi, sizeof(mbi));
        test::require(mbi.Protect == PAGE_NOACCESS, "guard applies across protection regions");
        protectMemory(GetCurrentProcess(), base, 0x3000, PAGE_READWRITE);
        test::rejects([&] { protectMemory(GetCurrentProcess(), base, 0, PAGE_READONLY); },
                      "empty guard range rejected");
        test::rejects(
            [&] { writeMemory(GetCurrentProcess(), UINTPTR_MAX, crossing.data(), crossing.size()); },
            "overflowing write range rejected");
    } catch (...) {
        VirtualFree(reserve, 0, MEM_RELEASE);
        throw;
    }
    VirtualFree(reserve, 0, MEM_RELEASE);
}
void importDumpTests() {
    TemporaryFolder folder;
    auto original = fixture();
    // Also make this fixture loadable: the final check asks the real Windows
    // loader to bind sparse imports, not just our own PE parser to accept them.
    PEImage originalPE(original);
    originalPE.nt.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
    originalPE.nt.OptionalHeader.MajorOperatingSystemVersion = 6;
    originalPE.nt.OptionalHeader.MajorSubsystemVersion = 6;
    originalPE.nt.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    originalPE.nt.OptionalHeader.SizeOfStackReserve = 0x100000;
    originalPE.nt.OptionalHeader.SizeOfStackCommit = 0x1000;
    originalPE.nt.OptionalHeader.SizeOfHeapReserve = 0x100000;
    originalPE.nt.OptionalHeader.SizeOfHeapCommit = 0x1000;
    originalPE.save(original);
    auto originalPath = folder.path / L"original.exe";
    writeFileAtomic(originalPath, original);
    void *allocation = VirtualAlloc(nullptr, 0x3000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!allocation)
        winError("VirtualAlloc(import fixture)");
    try {
        auto base = reinterpret_cast<Address>(allocation);
        std::memcpy(allocation, original.data(), 0x200);
        auto k = GetModuleHandleW(L"kernel32.dll");
        std::array<Address, 3> addresses{reinterpret_cast<Address>(GetProcAddress(k, "GetCurrentProcessId")),
                                         reinterpret_cast<Address>(GetProcAddress(k, "GetCurrentThreadId")),
                                         0};
        test::require(addresses[0] && addresses[1], "fixture APIs exist");
        std::memcpy(reinterpret_cast<void *>(base + 0x2000), addresses.data(), sizeof(addresses));
        Dumper d(GetCurrentProcess(), GetCurrentProcessId(), originalPath, base, base + 0x1000, {});
        test::require(d.isAPI(addresses[0]) && d.isAPI(addresses[1]), "exports and forwards resolve");
        test::require(d.iatSize(addresses) == 2, "IAT size excludes zero terminator");
        const std::array<Address, 2> invalid{};
        test::rejects([&] { d.iatSize(invalid); }, "empty IAT rejected");
        auto output = folder.path / L"originalU.exe";
        d.dump(output, base + 0x2000, false);
        auto file = readFile(output);
        PEImage pe(file);
        test::require(pe.sections.size() == 3 && pe.sections.back().name() == ".import",
                      "import section emitted");
        test::require(pe.nt.OptionalHeader.ImageBase == base, "actual ASLR image base recorded");
        auto dir = pe.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        auto descriptor = load<IMAGE_IMPORT_DESCRIPTOR>(
            file, pe.fileOffset(dir.VirtualAddress, sizeof(IMAGE_IMPORT_DESCRIPTOR)));
        test::require(descriptor.FirstThunk == 0x2000 && descriptor.OriginalFirstThunk != 0,
                      "IAT and separate lookup table emitted");
        auto dll = stringAt(file, pe.fileOffset(descriptor.Name));
        test::require(!dll.empty(), "import module named");
        for (unsigned i = 0; i < 2; ++i) {
            auto thunk = load<Address>(
                file, pe.fileOffset(descriptor.FirstThunk + i * sizeof(Address), sizeof(Address)));
            auto originalThunk = load<Address>(
                file, pe.fileOffset(descriptor.OriginalFirstThunk + i * sizeof(Address), sizeof(Address)));
            test::require(thunk == originalThunk, "IAT matches lookup table");
            if (!(thunk & IMAGE_ORDINAL_FLAG))
                test::require(!stringAt(file, pe.fileOffset(rva32(thunk + 2))).empty(),
                              "import hint/name bounded");
        }
        test::require(load<Address>(file, pe.fileOffset(descriptor.OriginalFirstThunk + 2 * sizeof(Address),
                                                        sizeof(Address))) == 0,
                      "lookup table terminated");
        for (auto &section : pe.sections)
            test::require(std::uint64_t(section.header.PointerToRawData) + section.header.SizeOfRawData <=
                              file.size(),
                          "dump raw section within file");
        // Place an import at the final word of the image: a synthesized extra
        // IAT terminator used to overflow the original image/section here.
        auto edgeHeader = original;
        PEImage edgePE(edgeHeader);
        edgePE.sections.back().header.Misc.VirtualSize = 0x1000;
        edgePE.save(edgeHeader);
        std::memcpy(allocation, edgeHeader.data(), 0x200);
        auto lastRva = DWORD(0x3000 - sizeof(Address));
        writeValue(GetCurrentProcess(), base + lastRva, addresses[0]);
        auto edgeOutput = folder.path / L"edge.exe";
        d.dump(edgeOutput, base + lastRva, false);
        auto edgeFile = readFile(edgeOutput);
        PEImage edgeDump(edgeFile);
        auto edgeIAT = edgeDump.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
        test::require(edgeIAT.VirtualAddress == lastRva && edgeIAT.Size == sizeof(Address),
                      "image-end IAT does not append an out-of-bounds terminator");
        test::require(load<Address>(edgeFile, edgeDump.fileOffset(lastRva, sizeof(Address))) != addresses[0],
                      "image-end API was rebuilt");
        writeValue<Address>(GetCurrentProcess(), base + lastRva, 0);
        // Hundreds of imports must grow .import beyond its initial page.
        std::vector<Address> large(301);
        for (std::size_t i = 0; i + 1 < large.size(); ++i)
            large[i] = addresses[i % 2];
        std::memcpy(reinterpret_cast<void *>(base + 0x2000), large.data(), large.size() * sizeof(Address));
        auto largeOutput = folder.path / L"large.exe";
        d.dump(largeOutput, base + 0x2000, false);
        auto largeFile = readFile(largeOutput);
        PEImage largeDump(largeFile);
        const auto &largeSection = largeDump.sections.back().header;
        test::require(largeSection.Misc.VirtualSize > 0x1000, "large import section grows past one page");
        test::require(largeDump.nt.OptionalHeader.SizeOfImage ==
                          largeDump.sectionAlign(largeSection.VirtualAddress + largeSection.Misc.VirtualSize),
                      "large import image size is aligned and covers all names/thunks");
        auto largeDir = largeDump.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        auto largeDescriptor = load<IMAGE_IMPORT_DESCRIPTOR>(
            largeFile, largeDump.fileOffset(largeDir.VirtualAddress, sizeof(IMAGE_IMPORT_DESCRIPTOR)));
        test::require(load<Address>(largeFile, largeDump.fileOffset(largeDescriptor.OriginalFirstThunk +
                                                                        300 * sizeof(Address),
                                                                    sizeof(Address))) == 0,
                      "large lookup terminator is in bounds");
        test::require(largeDump.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size ==
                          large.size() * sizeof(Address),
                      "large IAT includes only the existing terminator");
        std::memset(reinterpret_cast<void *>(base + 0x2000), 0, 0x1000);
        std::memcpy(allocation, original.data(), 0x200);
        auto ntClose = reinterpret_cast<Address>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtClose"));
        test::require(ntClose && d.isAPI(ntClose), "second module fixture export resolves");
        const std::array<Address, 10> sparse{addresses[0], 0,          0x11223344, 0x55667788,   0,
                                             addresses[1], 0x44556677, ntClose,    addresses[0], 0x12345678};
        std::memcpy(reinterpret_cast<void *>(base + 0x2000), sparse.data(), sizeof(sparse));
        test::require(d.iatSize(sparse) == 9, "IAT bound excludes nonzero trailing metadata");
        auto sparseOutput = folder.path / L"sparse.dll";
        Dumper sparseDumper(GetCurrentProcess(), GetCurrentProcessId(), originalPath, base, base, {});
        sparseDumper.dump(sparseOutput, base + 0x2000, true); // entry RVA 0: no code to execute
        auto sparseFile = readFile(sparseOutput);
        PEImage sparsePE(sparseFile);
        auto sparseDir = sparsePE.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        test::require(sparseDir.Size == 5 * sizeof(IMAGE_IMPORT_DESCRIPTOR),
                      "four sparse descriptors plus null descriptor");
        const std::array<std::size_t, 4> starts{0, 5, 7, 8};
        for (std::size_t i = 0; i < starts.size(); ++i) {
            auto slot = starts[i];
            auto desc = load<IMAGE_IMPORT_DESCRIPTOR>(
                sparseFile,
                sparsePE.fileOffset(sparseDir.VirtualAddress + i * sizeof(IMAGE_IMPORT_DESCRIPTOR),
                                    sizeof(IMAGE_IMPORT_DESCRIPTOR)));
            test::require(desc.FirstThunk == 0x2000 + slot * sizeof(Address),
                          "sparse FirstThunk has original index");
            auto lookup =
                load<Address>(sparseFile, sparsePE.fileOffset(desc.OriginalFirstThunk, sizeof(Address)));
            test::require(lookup != 0 &&
                              lookup == load<Address>(sparseFile,
                                                      sparsePE.fileOffset(desc.FirstThunk, sizeof(Address))),
                          "sparse lookup matches IAT");
            test::require(
                load<Address>(sparseFile, sparsePE.fileOffset(desc.OriginalFirstThunk + sizeof(Address),
                                                              sizeof(Address))) == 0,
                "each sparse lookup independently terminated");
            if (slot == 7)
                test::require(stringAt(sparseFile, sparsePE.fileOffset(desc.Name)) == "ntdll.dll",
                              "mixed module gets its own descriptor");
        }
        auto terminator = load<IMAGE_IMPORT_DESCRIPTOR>(
            sparseFile, sparsePE.fileOffset(sparseDir.VirtualAddress + 4 * sizeof(IMAGE_IMPORT_DESCRIPTOR),
                                            sizeof(IMAGE_IMPORT_DESCRIPTOR)));
        test::require(terminator.FirstThunk == 0 && terminator.OriginalFirstThunk == 0 &&
                          terminator.Name == 0,
                      "descriptor array terminated");
        for (auto slot : std::array<std::size_t, 6>{1, 2, 3, 4, 6, 9})
            test::require(load<Address>(sparseFile, sparsePE.fileOffset(0x2000 + slot * sizeof(Address),
                                                                        sizeof(Address))) == sparse[slot],
                          "unknown data, zeros and trailing metadata preserved on disk");
        test::require(sparsePE.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size ==
                          9 * sizeof(Address),
                      "IAT directory does not claim overwritten extra terminator");
        // Release its preferred image base before asking the loader to map the
        // dump. It deliberately has no relocations and no DllMain entry point.
        check(VirtualFree(allocation, 0, MEM_RELEASE), "VirtualFree(import fixture)");
        allocation = nullptr;
        HMODULE loaded = LoadLibraryW(sparseOutput.c_str());
        if (!loaded)
            winError("LoadLibrary(sparse import dump)");
        try {
            auto loadedBase = reinterpret_cast<Address>(loaded);
            for (auto slot : starts)
                test::require(
                    readValue<Address>(GetCurrentProcess(), loadedBase + 0x2000 + slot * sizeof(Address)) ==
                        sparse[slot],
                    "Windows loader binds each sparse API to the correct original slot");
            for (auto slot : std::array<std::size_t, 6>{1, 2, 3, 4, 6, 9})
                test::require(
                    readValue<Address>(GetCurrentProcess(), loadedBase + 0x2000 + slot * sizeof(Address)) ==
                        sparse[slot],
                    "Windows loader does not overwrite adjacent metadata");
        } catch (...) {
            FreeLibrary(loaded);
            throw;
        }
        check(FreeLibrary(loaded), "FreeLibrary(sparse import dump)");
    } catch (...) {
        VirtualFree(allocation, 0, MEM_RELEASE);
        throw;
    }
    VirtualFree(allocation, 0, MEM_RELEASE);
}
volatile LONG fixtureCounter = 0;
__declspec(noinline) void fixtureSoft() {
    InterlockedAdd(&fixtureCounter, 1);
}
__declspec(noinline) void fixtureHardware() {
    InterlockedAdd(&fixtureCounter, 2);
}
__declspec(noinline) int fixtureTrace(int value) {
    return value * 3 + 7;
}
class DebugProbe final : public DebuggerCore {
    Address soft_{}, hardware_{};
    void onStart() override {
        started = true;
        auto local = reinterpret_cast<Address>(GetModuleHandleW(nullptr));
        soft_ = imageBase_ + reinterpret_cast<Address>(&fixtureSoft) - local;
        hardware_ = imageBase_ + reinterpret_cast<Address>(&fixtureHardware) - local;
        setSoftBP(soft_);
        info(L"Probe software breakpoint armed at 0x" + hex(soft_));
        test::require(read<BYTE>(soft_) == 0xcc, "software breakpoint byte installed");
    }
    SoftAction onSoftware(HANDLE, Address a) override {
        test::require(a == soft_, "software breakpoint address");
        softHit = true;
        // Windows startup can restore the initial thread context after the
        // loader breakpoint, clearing debug registers installed in onStart().
        // Arm the hardware fixture at this first user-code stop instead. The
        // trace below must now restore a genuinely enabled breakpoint.
        setBreakpoint(hardware_);
        auto before = context(thread());
        info(L"Probe software hit; hardware armed: DR0=0x" + hex(before.Dr0) + L" DR7=0x" + hex(before.Dr7));
        test::require(before.Dr0 == hardware_ && (before.Dr7 & 1), "hardware breakpoint registers installed");
        auto local = reinterpret_cast<Address>(GetModuleHandleW(nullptr));
        auto start = imageBase_ + reinterpret_cast<Address>(&fixtureTrace) - local;
        test::require(trace(start, 16, [](unsigned count, CONTEXT &) { return count >= 1; }),
                      "single-step trace completes");
        auto after = context(thread());
        info(L"Probe trace restored; DR6=0x" + hex(after.Dr6) + L" DR7=0x" + hex(after.Dr7));
        test::require(before.Dr0 == after.Dr0 && before.Dr7 == after.Dr7,
                      "trace restores hardware breakpoints");
        test::require(ip(before) == ip(after) && sp(before) == sp(after), "trace restores control context");
        return SoftAction::Clear;
    }
    void onHardware(HANDLE, Address a, CONTEXT &) override {
        test::require(a == hardware_, "hardware breakpoint address");
        hardHit = true;
        info(L"Probe hardware hit.");
        resetBreakpoint(a);
        finished_ = true;
    }

  public:
    bool started = false, softHit = false, hardHit = false;
    using DebuggerCore::DebuggerCore;
};
void debuggerTests() {
    check(SetEnvironmentVariableW(L"MAGICMIDA_TEST_CHILD", L"1"), "SetEnvironmentVariable(test)");
    try {
        std::atomic_bool cancel = false;
        Logger logger = [](LogType, const std::wstring &text) { std::cout << narrow(text) << '\n'; };
        DebugProbe p(executablePath(), logger, cancel);
        bool result = p.run();
        test::require(p.started, "loader breakpoint must initialize debugger");
        test::require(p.softHit, "software callback observed");
        test::require(p.hardHit, "hardware callback observed");
        test::require(result, "debug event loop finishes");
        cancel = true;
        DebugProbe cancelled(executablePath(), logger, cancel);
        test::require(!cancelled.run(), "cancellation reports failure");
    } catch (...) {
        SetEnvironmentVariableW(L"MAGICMIDA_TEST_CHILD", nullptr);
        throw;
    }
    SetEnvironmentVariableW(L"MAGICMIDA_TEST_CHILD", nullptr);
}
} // namespace
int main() {
    if (GetEnvironmentVariableW(L"MAGICMIDA_TEST_CHILD", nullptr, 0)) {
        auto sites = L"Probe child sites: soft=0x" + hex(reinterpret_cast<Address>(&fixtureSoft)) +
                     L" hard=0x" + hex(reinterpret_cast<Address>(&fixtureHardware));
        OutputDebugStringW(sites.c_str());
        fixtureSoft();
        fixtureHardware();
        return fixtureCounter == 3 ? 0 : 3;
    }
    try {
        portableTests();
        peTests();
        manifestTests();
        trimTests();
        disassemblyTests();
        fileTests();
        patcherTests();
        processCopyTests();
        temporaryDllTests();
        memoryTests();
        importDumpTests();
        debuggerTests();
        std::cout << test::checks << " checks passed (" << sizeof(Address) * 8 << "-bit)\n";
        return 0;
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
