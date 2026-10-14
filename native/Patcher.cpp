// SPDX-License-Identifier: GPL-3.0-only
#include "Patcher.hpp"
#include <tlhelp32.h>
namespace mm {
namespace {
DWORD extent(const IMAGE_SECTION_HEADER &s) {
    return std::max(s.Misc.VirtualSize, s.SizeOfRawData);
}
void validateLayout(const PEImage &pe, std::span<const BYTE> bytes) {
    if (pe.sections.empty() || pe.sections.size() > 96)
        throw std::runtime_error("Invalid PE section count");
    const auto &oh = pe.nt.OptionalHeader;
    bounds(bytes.size(), 0, oh.SizeOfHeaders);
    if (std::uint64_t(pe.ntOffset) + sizeof(pe.nt) + pe.sections.size() * sizeof(IMAGE_SECTION_HEADER) >
        oh.SizeOfHeaders)
        throw std::runtime_error("Section headers exceed SizeOfHeaders");
    std::vector<std::pair<std::uint64_t, std::uint64_t>> raw, virtualRanges;
    for (const auto &s : pe.sections) {
        const auto &h = s.header;
        if (h.VirtualAddress % oh.SectionAlignment || h.SizeOfRawData % oh.FileAlignment ||
            (h.SizeOfRawData && h.PointerToRawData % oh.FileAlignment))
            throw std::runtime_error("Unaligned PE section");
        if (extent(h)) {
            auto end = pe.sectionAlign(rva32(std::uint64_t(h.VirtualAddress) + extent(h)));
            if (h.VirtualAddress < pe.sectionAlign(oh.SizeOfHeaders) || end > oh.SizeOfImage)
                throw std::runtime_error("Section outside image bounds");
            virtualRanges.emplace_back(h.VirtualAddress, end);
        }
        if (h.SizeOfRawData) {
            bounds(bytes.size(), h.PointerToRawData, h.SizeOfRawData);
            if (h.PointerToRawData < oh.SizeOfHeaders)
                throw std::runtime_error("Section overlaps PE headers");
            raw.emplace_back(h.PointerToRawData, std::uint64_t(h.PointerToRawData) + h.SizeOfRawData);
        }
        if (h.PointerToRelocations || h.PointerToLinenumbers || h.NumberOfRelocations ||
            h.NumberOfLinenumbers)
            throw std::runtime_error("COFF section relocation/line metadata is not supported for rewriting");
    }
    for (auto *ranges : {&raw, &virtualRanges}) {
        std::sort(ranges->begin(), ranges->end());
        for (std::size_t i = 1; i < ranges->size(); ++i)
            if ((*ranges)[i].first < (*ranges)[i - 1].second)
                throw std::runtime_error("Overlapping PE sections");
    }
}
void validateEntryAndTLS(const PEImage &pe, std::span<const BYTE> bytes) {
    auto executable = [&](DWORD rva) {
        auto idx = pe.sectionAt(rva);
        return idx && (pe.sections[*idx].header.Characteristics & IMAGE_SCN_MEM_EXECUTE);
    };
    if (pe.nt.OptionalHeader.AddressOfEntryPoint && !executable(pe.nt.OptionalHeader.AddressOfEntryPoint))
        throw std::runtime_error("Section layout would make the entry point non-executable");
    const auto &dir = pe.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (pe.nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_TLS || !dir.VirtualAddress)
        return;
    if (dir.Size < sizeof(IMAGE_TLS_DIRECTORY))
        throw std::runtime_error("Truncated TLS directory");
    auto tls =
        load<IMAGE_TLS_DIRECTORY>(bytes, pe.fileOffset(dir.VirtualAddress, sizeof(IMAGE_TLS_DIRECTORY)));
    auto toRVA = [&](std::uint64_t va) {
        if (va < pe.nt.OptionalHeader.ImageBase ||
            va - pe.nt.OptionalHeader.ImageBase >= pe.nt.OptionalHeader.SizeOfImage)
            throw std::runtime_error("TLS VA outside image");
        return rva32(va - pe.nt.OptionalHeader.ImageBase);
    };
    if (tls.AddressOfIndex) {
        auto rva = toRVA(tls.AddressOfIndex);
        auto idx = pe.sectionAt(rva);
        if (!idx || !(pe.sections[*idx].header.Characteristics & IMAGE_SCN_MEM_WRITE) ||
            std::uint64_t(rva) + sizeof(DWORD) >
                std::uint64_t(pe.sections[*idx].header.VirtualAddress) + extent(pe.sections[*idx].header))
            throw std::runtime_error("Section layout would make the TLS index unwritable");
    }
    if (tls.AddressOfCallBacks) {
        auto rva = toRVA(tls.AddressOfCallBacks);
        for (unsigned i = 0; i < 1024; ++i) {
            auto callback = load<Address>(
                bytes, pe.fileOffset(rva32(std::uint64_t(rva) + i * sizeof(Address)), sizeof(Address)));
            if (!callback)
                return;
            if (!executable(toRVA(callback)))
                throw std::runtime_error("Section layout would make a TLS callback non-executable");
        }
        throw std::runtime_error("Unterminated TLS callback table");
    }
}
void updateSizes(PEImage &pe) {
    std::uint64_t code = 0, initialized = 0, uninitialized = 0;
    for (const auto &s : pe.sections) {
        auto &h = s.header;
        if (h.Characteristics & IMAGE_SCN_CNT_CODE)
            code += h.SizeOfRawData;
        if (h.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
            initialized += h.SizeOfRawData;
        if (h.Characteristics & (IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA))
            uninitialized += extent(h) - h.SizeOfRawData;
    }
    pe.nt.OptionalHeader.SizeOfCode = rva32(code);
    pe.nt.OptionalHeader.SizeOfInitializedData = rva32(initialized);
    pe.nt.OptionalHeader.SizeOfUninitializedData = rva32(uninitialized);
}
} // namespace
void Patcher::save() {
    pe_.nt.OptionalHeader.CheckSum = 0;
    // Rewriting headers invalidates Authenticode. Preserve any overlay bytes,
    // but do not claim that the original certificate still authenticates them.
    pe_.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] = {};
    updateSizes(pe_);
    pe_.save(data_);
    validateLayout(pe_, data_);
    writeFileAtomic(path_, data_);
}
void Patcher::applyLayout(const PEImage &layout) {
    validateLayout(pe_, data_);
    if (layout.nt.FileHeader.Machine != pe_.nt.FileHeader.Machine ||
        layout.nt.OptionalHeader.SectionAlignment != pe_.nt.OptionalHeader.SectionAlignment)
        throw std::runtime_error("Reference architecture/section alignment differs from target");
    std::vector<std::vector<Section>> references(pe_.sections.size());
    for (const auto &ref : layout.sections) {
        const auto &h = ref.header;
        if (!extent(h))
            continue;
        auto parent = pe_.sectionAt(h.VirtualAddress);
        if (!parent || h.VirtualAddress % pe_.nt.OptionalHeader.SectionAlignment)
            throw std::runtime_error("Reference section is not mapped in target");
        const auto &source = pe_.sections[*parent].header;
        if (std::uint64_t(h.VirtualAddress) + extent(h) >
            std::uint64_t(source.VirtualAddress) + extent(source))
            throw std::runtime_error(
                "Reference section crosses target section boundary (different layout/build)");
        references[*parent].push_back(ref);
    }
    auto result = pe_;
    result.sections.clear();
    for (std::size_t i = 0; i < pe_.sections.size(); ++i) {
        const auto &source = pe_.sections[i];
        const auto &h = source.header;
        auto &refs = references[i];
        if (refs.empty()) {
            result.sections.push_back(source);
            continue;
        }
        std::sort(refs.begin(), refs.end(), [](const auto &a, const auto &b) {
            return a.header.VirtualAddress < b.header.VirtualAddress;
        });
        DWORD end = rva32(std::uint64_t(h.VirtualAddress) + extent(h));
        DWORD cursor = h.VirtualAddress;
        auto append = [&](DWORD begin, DWORD limit, const Section *ref) {
            if (begin == limit)
                return;
            Section part = ref ? *ref : source;
            if (!ref)
                part.rename(".keep");
            auto delta = begin - h.VirtualAddress;
            part.header.VirtualAddress = begin;
            part.header.Misc.VirtualSize = limit - begin;
            part.header.SizeOfRawData =
                delta < h.SizeOfRawData ? std::min(h.SizeOfRawData - delta, limit - begin) : 0;
            part.header.PointerToRawData =
                part.header.SizeOfRawData ? rva32(std::uint64_t(h.PointerToRawData) + delta) : 0;
            // A live dump's former BSS can contain initialized state. Never
            // discard those bytes just because the reference called it BSS.
            if (part.header.SizeOfRawData &&
                (part.header.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)) {
                part.header.Characteristics &= ~IMAGE_SCN_CNT_UNINITIALIZED_DATA;
                part.header.Characteristics |= IMAGE_SCN_CNT_INITIALIZED_DATA;
            }
            result.sections.push_back(part);
        };
        for (const auto &ref : refs) {
            auto begin = ref.header.VirtualAddress;
            if (begin < cursor)
                throw std::runtime_error("Overlapping reference sections");
            append(cursor, begin, nullptr);
            cursor = std::min(end, pe_.sectionAlign(rva32(std::uint64_t(begin) + extent(ref.header))));
            append(begin, cursor, &ref);
        }
        append(cursor, end, nullptr);
    }
    auto oldEnd =
        std::size_t(pe_.ntOffset) + sizeof(pe_.nt) + pe_.sections.size() * sizeof(IMAGE_SECTION_HEADER);
    auto newEnd =
        std::size_t(pe_.ntOffset) + sizeof(pe_.nt) + result.sections.size() * sizeof(IMAGE_SECTION_HEADER);
    if (newEnd > pe_.nt.OptionalHeader.SizeOfHeaders)
        throw std::runtime_error("No room for additional section headers");
    if (newEnd > oldEnd) {
        if (!std::all_of(data_.begin() + oldEnd, data_.begin() + newEnd, [](BYTE b) { return b == 0; }))
            throw std::runtime_error("New section headers would overwrite existing header data");
        for (unsigned i = 0; i < pe_.nt.OptionalHeader.NumberOfRvaAndSizes; ++i) {
            const auto &d = pe_.nt.OptionalHeader.DataDirectory[i];
            if (i != IMAGE_DIRECTORY_ENTRY_SECURITY && d.VirtualAddress && d.VirtualAddress < newEnd &&
                std::uint64_t(d.VirtualAddress) + std::max(DWORD(1), d.Size) > oldEnd)
                throw std::runtime_error("New section headers overlap a PE data directory");
        }
    }
    validateLayout(result, data_);
    validateEntryAndTLS(result, data_);
    pe_ = std::move(result);
}
bool Patcher::createData(const Path &reference) {
    if (!reference.empty()) {
        auto bytes = readFile(reference);
        PEImage layout(bytes);
        validateLayout(layout, bytes);
        applyLayout(layout);
        save();
        log(log_, LogType::Good,
            L"Section layout applied from reference; RVAs and target payload retained. Reference must be "
            L"from the same build.");
        return true;
    }
#ifndef _WIN64
    auto boundary = pe_.nt.OptionalHeader.BaseOfData;
    auto idx = pe_.sectionAt(boundary);
    if (idx && boundary % pe_.nt.OptionalHeader.SectionAlignment == 0) {
        const auto &old = pe_.sections[*idx];
        auto delta = boundary - old.header.VirtualAddress;
        auto ep = pe_.nt.OptionalHeader.AddressOfEntryPoint;
        if (delta && delta < extent(old.header) && (old.header.Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            !(ep >= boundary &&
              std::uint64_t(ep) < std::uint64_t(old.header.VirtualAddress) + extent(old.header))) {
            auto layout = pe_;
            layout.sections = {old, old};
            auto &text = layout.sections[0];
            text.rename(".text");
            text.header.Misc.VirtualSize = delta;
            text.header.SizeOfRawData = std::min(delta, old.header.SizeOfRawData);
            auto &data = layout.sections[1];
            data.rename(".data");
            data.header.VirtualAddress = boundary;
            data.header.Misc.VirtualSize = extent(old.header) - delta;
            data.header.SizeOfRawData =
                delta < old.header.SizeOfRawData ? old.header.SizeOfRawData - delta : 0;
            data.header.Characteristics = (old.header.Characteristics & ~IMAGE_SCN_CNT_CODE) |
                                          IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ |
                                          IMAGE_SCN_MEM_WRITE;
            applyLayout(layout);
            save();
            log(log_, LogType::Good,
                L"Split at PE32 BaseOfData. Existing executable permissions retained; no .rdata boundary "
                L"guessed.");
            return true;
        }
    }
#endif
    log(log_, LogType::Info,
        L"No safe automatic data split available (or sections already separated). File unchanged; use a "
        L"same-build reference PE to restore .rdata/.data permissions.");
    return false;
}
void Patcher::shrink() {
    validateLayout(pe_, data_);
    if (pe_.nt.FileHeader.PointerToSymbolTable || pe_.nt.FileHeader.NumberOfSymbols)
        throw std::runtime_error("COFF symbol table present; refusing unsupported raw-file rewrite");
    const auto original = pe_;
    auto oldOverlay = std::size_t(pe_.nt.OptionalHeader.SizeOfHeaders);
    for (const auto &s : original.sections)
        if (s.header.SizeOfRawData)
            oldOverlay = std::max<std::size_t>(oldOverlay, std::size_t(s.header.PointerToRawData) +
                                                               s.header.SizeOfRawData);
    std::vector<std::pair<std::size_t, std::size_t>> ranges;
    for (const auto &section : original.sections)
        if (section.header.SizeOfRawData)
            ranges.emplace_back(section.header.PointerToRawData,
                                std::size_t(section.header.PointerToRawData) + section.header.SizeOfRawData);
    std::sort(ranges.begin(), ranges.end());
    std::size_t previous = original.nt.OptionalHeader.SizeOfHeaders;
    for (const auto &[begin, end] : ranges) {
        if (!std::all_of(data_.begin() + previous, data_.begin() + begin, [](BYTE b) { return b == 0; }))
            throw std::runtime_error(
                "Nonzero data in raw-file gaps; refusing to discard unclassified metadata");
        previous = end;
    }
    const auto debug = pe_.nt.OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DEBUG
                           ? pe_.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG]
                           : IMAGE_DATA_DIRECTORY{};
    std::vector<IMAGE_DEBUG_DIRECTORY> debugEntries;
    if (debug.VirtualAddress) {
        if (debug.Size % sizeof(IMAGE_DEBUG_DIRECTORY))
            throw std::runtime_error("Invalid debug directory size");
        auto off = pe_.fileOffset(debug.VirtualAddress, debug.Size);
        for (std::size_t i = 0; i < debug.Size / sizeof(IMAGE_DEBUG_DIRECTORY); ++i)
            debugEntries.push_back(
                load<IMAGE_DEBUG_DIRECTORY>(data_, off + i * sizeof(IMAGE_DEBUG_DIRECTORY)));
    }
    Bytes packed(data_.begin(), data_.begin() + pe_.nt.OptionalHeader.SizeOfHeaders);
    for (std::size_t i = 0; i < pe_.sections.size(); ++i) {
        auto &h = pe_.sections[i].header;
        auto old = h;
        DWORD n = h.SizeOfRawData;
        while (n && data_[h.PointerToRawData + n - 1] == 0)
            --n;
        // Debug records contain file offsets, not just RVAs. Retain their full
        // data, including zero tails, and fix up pointers after repacking.
        for (const auto &entry : debugEntries)
            if (entry.PointerToRawData >= old.PointerToRawData &&
                std::uint64_t(entry.PointerToRawData) + entry.SizeOfData <=
                    std::uint64_t(old.PointerToRawData) + old.SizeOfRawData)
                n = std::max(n, entry.PointerToRawData - old.PointerToRawData + entry.SizeOfData);
        if (debug.VirtualAddress >= old.VirtualAddress &&
            std::uint64_t(debug.VirtualAddress) + debug.Size <=
                std::uint64_t(old.VirtualAddress) + old.SizeOfRawData)
            n = std::max(n, debug.VirtualAddress - old.VirtualAddress + debug.Size);
        h.Misc.VirtualSize = extent(old); // trimmed raw zeros remain mapped zeros
        h.SizeOfRawData = pe_.fileAlign(n);
        h.PointerToRawData = h.SizeOfRawData ? pe_.fileAlign(rva32(packed.size())) : 0;
        if (h.SizeOfRawData) {
            packed.resize(h.PointerToRawData);
            packed.insert(packed.end(), data_.begin() + old.PointerToRawData,
                          data_.begin() + old.PointerToRawData + h.SizeOfRawData);
        }
    }
    auto newOverlay = packed.size();
    packed.insert(packed.end(), data_.begin() + oldOverlay, data_.end());
    auto remap = [&](DWORD offset, DWORD size) -> DWORD {
        bounds(data_.size(), offset, size);
        if (offset >= oldOverlay)
            return rva32(newOverlay + (offset - oldOverlay));
        if (offset < original.nt.OptionalHeader.SizeOfHeaders) {
            bounds(original.nt.OptionalHeader.SizeOfHeaders, offset, size);
            return offset;
        }
        for (std::size_t i = 0; i < original.sections.size(); ++i) {
            const auto &old = original.sections[i].header;
            if (offset >= old.PointerToRawData &&
                std::uint64_t(offset) + size <= std::uint64_t(old.PointerToRawData) + old.SizeOfRawData) {
                auto delta = offset - old.PointerToRawData;
                bounds(pe_.sections[i].header.SizeOfRawData, delta, size);
                return rva32(std::uint64_t(pe_.sections[i].header.PointerToRawData) + delta);
            }
        }
        throw std::runtime_error("Debug raw pointer outside retained file ranges");
    };
    if (debug.VirtualAddress) {
        auto off = pe_.fileOffset(debug.VirtualAddress, debug.Size);
        for (std::size_t i = 0; i < debugEntries.size(); ++i) {
            auto entry = debugEntries[i];
            if (entry.PointerToRawData)
                entry.PointerToRawData = remap(entry.PointerToRawData, entry.SizeOfData);
            store(packed, off + i * sizeof(entry), entry);
        }
    }
    data_ = std::move(packed);
    save();
    log(log_, LogType::Good,
        L"Compacted raw padding/zero tails; all sections, virtual extents and overlay retained. No VM "
        L"section removed.");
}
void Patcher::dumpProcess(DWORD pid) {
    validateLayout(pe_, data_);
    Handle p(OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid));
    if (!p)
        winError("OpenProcess");
    Handle snap(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid));
    if (!snap)
        winError("CreateToolhelp32Snapshot");
    MODULEENTRY32W module{};
    module.dwSize = sizeof(module);
    check(Module32FirstW(snap.get(), &module), "Module32First");
    auto base = reinterpret_cast<Address>(module.modBaseAddr);
    PEImage remote(readPEHeader(p.get(), base));
    if (remote.nt.FileHeader.TimeDateStamp != pe_.nt.FileHeader.TimeDateStamp)
        throw std::runtime_error("Process and file PE timestamps differ; choose the matching target");
    bool copied = false;
    for (const auto &s : pe_.sections) {
        const auto &h = s.header;
        if (!(h.Characteristics & IMAGE_SCN_MEM_EXECUTE) || !h.SizeOfRawData)
            continue;
        bounds(remote.nt.OptionalHeader.SizeOfImage, h.VirtualAddress, h.SizeOfRawData);
        auto bytes = readMemory(p.get(), base + h.VirtualAddress, h.SizeOfRawData);
        std::copy(bytes.begin(), bytes.end(), data_.begin() + h.PointerToRawData);
        copied = true;
    }
    if (!copied)
        throw std::runtime_error("No file-backed executable sections to copy");
    pe_.nt.OptionalHeader.CheckSum = 0;
    pe_.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] = {};
    pe_.save(data_);
    auto output = path_.parent_path() / (path_.stem().wstring() + L".novm" + path_.extension().wstring());
    writeFileAtomic(output, data_);
    log(log_, LogType::Good,
        L"Copied executable section bytes to " + output.wstring() + L"; this does not devirtualize code.");
}
} // namespace mm
