// SPDX-License-Identifier: GPL-3.0-only
#include "Patcher.hpp"
#include <tlhelp32.h>
namespace mm {
#ifndef _WIN64
std::optional<std::size_t> Patcher::find(std::string_view pattern, std::size_t start) const {
    if (start >= data_.size())
        return {};
    auto p = findPattern(std::span(data_).subspan(start), pattern);
    return p ? std::optional(start + *p) : std::nullopt;
}
void Patcher::save() {
    pe_.nt.OptionalHeader.CheckSum = 0;
    pe_.save(data_);
    writeFileAtomic(path_, data_);
}
void Patcher::createData() {
    if (lower(path_.filename().wstring()).find(L"maplestory") != std::wstring::npos)
        createMaple();
    else if (pe_.nt.OptionalHeader.MajorLinkerVersion == 14)
        createMSVC();
    else {
        log(log_, LogType::Info, L"Data section creation not available for this compiler.");
        return;
    }
    save();
}
void Patcher::split(DWORD rdata, DWORD data, DWORD end, DWORD zeroSize) {
    if (pe_.sections.size() < 2)
        throw std::runtime_error("Too few sections for split");
    const auto old = pe_.sections.front().header;
    const auto limit = pe_.sections[1].header.VirtualAddress;
    if (old.PointerToRawData != old.VirtualAddress || pe_.sections[1].header.PointerToRawData != limit ||
        rdata <= old.VirtualAddress || data <= rdata || end < data || end > limit || zeroSize > end - data)
        throw std::runtime_error("Invalid data section boundaries (requires a memory-layout dump)");
    auto make = [](std::string_view name, DWORD begin, DWORD len, bool writable) {
        Section s;
        s.rename(name);
        s.header.VirtualAddress = begin;
        s.header.PointerToRawData = begin;
        s.header.Misc.VirtualSize = len;
        s.header.SizeOfRawData = len;
        s.header.Characteristics =
            IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA | (writable ? IMAGE_SCN_MEM_WRITE : 0);
        return s;
    };
    std::vector<Section> added{make(".rdata", rdata, data - rdata, false),
                               make(".data", data, end - data, true)};
    added[1].header.SizeOfRawData -= zeroSize;
    if (end < limit)
        added.push_back(
            make(pe_.nt.OptionalHeader.MajorLinkerVersion >= 14 ? ".gfids" : ".vmp", end, limit - end, true));
    pe_.sections.insert(pe_.sections.begin() + 1, added.begin(), added.end());
    auto &text = pe_.sections.front();
    text.rename(".text");
    text.header.Misc.VirtualSize = rdata - old.VirtualAddress;
    text.header.SizeOfRawData = text.header.Misc.VirtualSize;
    text.header.Characteristics &= ~IMAGE_SCN_MEM_WRITE;
}
void Patcher::createMSVC() {
    auto start = pe_.nt.OptionalHeader.BaseOfData;
    auto &text = pe_.sections.front().header;
    if (start <= text.VirtualAddress || start >= std::uint64_t(text.VirtualAddress) + text.Misc.VirtualSize ||
        (start & 0xfff)) {
        log(log_, LogType::Info, L"Assuming sections are not merged.");
        pe_.sections.front().rename(".text");
        text.Characteristics &= ~IMAGE_SCN_MEM_WRITE;
        return;
    }
    auto p = find("8BF033FF393E74??56E8", 0x1000);
    if (!p || *p < 5 || data_[*p - 5] != 0xe8)
        throw std::runtime_error("MSVC dynamic TLS sequence not found");
    auto fn = static_cast<std::int64_t>(*p) + load<std::int32_t>(data_, *p - 4);
    if (fn < 0)
        throw std::runtime_error("Invalid TLS callback getter");
    if (load<BYTE>(data_, static_cast<std::size_t>(fn)) == 0xe9)
        fn += load<std::int32_t>(data_, static_cast<std::size_t>(fn) + 1) + 5;
    if (fn < 0 || load<BYTE>(data_, static_cast<std::size_t>(fn)) != 0xb8)
        throw std::runtime_error("MSVC TLS getter mismatch");
    auto va = load<DWORD>(data_, static_cast<std::size_t>(fn) + 1);
    if (va < pe_.nt.OptionalHeader.ImageBase)
        throw std::runtime_error("Invalid TLS pointer");
    DWORD tls = va - pe_.nt.OptionalHeader.ImageBase;
    if (!load<DWORD>(data_, pe_.fileOffset(tls, 4)))
        tls = 0;
    auto data = tls ? (tls + 0x1000) & ~DWORD(0xfff) : start + 0x1000;
    split(start, data, pe_.sections.at(1).header.VirtualAddress);
}
void Patcher::createMaple() {
    auto start = find("10000000200000004000000060000000", 0x2000000);
    if (!start && pe_.nt.OptionalHeader.MajorLinkerVersion == 6) {
        auto p = find("68????????68??????00E8????????83C410C3", 0x100000);
        if (p) {
            auto va = load<DWORD>(data_, *p + 6);
            if (va >= pe_.nt.OptionalHeader.ImageBase && !(va & 0xfff))
                start = va - pe_.nt.OptionalHeader.ImageBase;
        }
    }
    if (!start) {
        auto a = find("2E3F41565F636F6D5F6572726F724040", 0x700000);
        auto b = find("2E3F41563F245A4C69737440554D4150494E464F4043416374696F6E4672616D6540404040", 0x700000);
        if (b && (!a || *b < *a))
            a = b;
        if (a && *a >= 8) {
            start = *a - 8;
            auto rem = *start & 0xfff;
            if (rem == 0xb4 || rem == 0xf8 || rem == 0xfc)
                *start &= ~std::size_t(0xfff);
        }
    }
    if (!start || (*start & 0xfff))
        throw std::runtime_error("MapleStory .data boundary not found/aligned");
    auto limit = pe_.sections.at(1).header.PointerToRawData;
    bounds(data_.size(), *start, limit - *start);
    std::size_t zeroEnd{}, zeroSize{}, pos = limit;
    while (pos > *start) {
        --pos;
        if (!data_[pos]) {
            if (!zeroSize)
                zeroEnd = pos + 1;
            ++zeroSize;
        } else {
            if (zeroSize > 0x2000)
                break;
            zeroSize = 0;
        }
    }
    if (!zeroSize)
        throw std::runtime_error("MapleStory zero-filled .data tail not found");
    if ((zeroEnd & 0xfff) == 1) {
        --zeroEnd;
        --zeroSize;
    }
    if (zeroEnd & 0xfff)
        throw std::runtime_error("MapleStory .data end not aligned");
    auto zeroStart = alignUp(rva32(zeroEnd - zeroSize), 0x1000);
    split(pe_.nt.OptionalHeader.BaseOfData, rva32(*start), rva32(zeroEnd), rva32(zeroEnd - zeroStart));
}
void Patcher::shrink() {
    auto &oh = pe_.nt.OptionalHeader;
    Bytes result(data_.begin(), data_.begin() + std::min<std::size_t>(data_.size(), oh.SizeOfHeaders));
    std::vector<Section> kept;
    for (std::size_t i = 0; i < pe_.sections.size(); ++i) {
        auto s = pe_.sections[i];
        auto &h = s.header;
        bool keep = i == 0 || s.name() == ".data" || s.name() == ".rdata";
        for (unsigned j = 0; j < oh.NumberOfRvaAndSizes; ++j) {
            auto d = oh.DataDirectory[j];
            if (j != IMAGE_DIRECTORY_ENTRY_SECURITY && d.Size && d.VirtualAddress >= h.VirtualAddress &&
                std::uint64_t(d.VirtualAddress) + d.Size <=
                    std::uint64_t(h.VirtualAddress) + h.Misc.VirtualSize)
                keep = true;
        }
        if (!keep)
            continue;
        bounds(data_.size(), h.PointerToRawData, h.SizeOfRawData);
        auto next = pe_.fileAlign(rva32(result.size()));
        result.resize(next);
        result.insert(result.end(), data_.begin() + h.PointerToRawData,
                      data_.begin() + h.PointerToRawData + h.SizeOfRawData);
        h.PointerToRawData = next;
        kept.push_back(s);
    }
    if (kept.empty())
        throw std::runtime_error("No sections retained");
    pe_.sections = std::move(kept);
    data_ = std::move(result);
    oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] = {};
    shrinkExports();
    save();
}
void Patcher::shrinkExports() {
    auto &dir = pe_.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size)
        return;
    auto idx = pe_.sectionAt(dir.VirtualAddress);
    if (!idx)
        return;
    auto &s = pe_.sections[*idx];
    auto &h = s.header;
    auto newSize = pe_.fileAlign(dir.Size);
    if (newSize >= h.SizeOfRawData)
        return;
    // Only compact a dedicated export section; don't discard unrelated directories.
    for (unsigned i = 1; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
        auto d = pe_.nt.OptionalHeader.DataDirectory[i];
        if (i != IMAGE_DIRECTORY_ENTRY_SECURITY && d.Size && pe_.sectionAt(d.VirtualAddress) == idx)
            return;
    }
    auto off = pe_.fileOffset(dir.VirtualAddress, dir.Size);
    bounds(data_.size(), off, dir.Size);
    Bytes exports(data_.begin() + off, data_.begin() + off + dir.Size);
    auto e = load<IMAGE_EXPORT_DIRECTORY>(exports, 0);
    auto oldRva = dir.VirtualAddress;
    auto delta = oldRva - h.VirtualAddress;
    auto adjust = [&](DWORD v) {
        if (v < oldRva || v - oldRva >= dir.Size)
            throw std::runtime_error("Export data outside directory");
        return v - delta;
    };
    e.Name = adjust(e.Name);
    auto namesOffset = e.AddressOfNames - oldRva, functionsOffset = e.AddressOfFunctions - oldRva;
    e.AddressOfFunctions = adjust(e.AddressOfFunctions);
    e.AddressOfNames = adjust(e.AddressOfNames);
    e.AddressOfNameOrdinals = adjust(e.AddressOfNameOrdinals);
    for (DWORD i = 0; i < e.NumberOfNames; ++i) {
        auto p = namesOffset + i * 4;
        store(exports, p, adjust(load<DWORD>(exports, p)));
    }
    for (DWORD i = 0; i < e.NumberOfFunctions; ++i) {
        auto p = functionsOffset + i * 4;
        auto v = load<DWORD>(exports, p);
        if (v >= oldRva && v - oldRva < dir.Size)
            store(exports, p, v - delta);
    }
    store(exports, 0, e);
    exports.resize(newSize);
    auto removed = h.SizeOfRawData - newSize;
    bounds(data_.size(), h.PointerToRawData, h.SizeOfRawData);
    std::copy(exports.begin(), exports.end(), data_.begin() + h.PointerToRawData);
    data_.erase(data_.begin() + h.PointerToRawData + newSize,
                data_.begin() + h.PointerToRawData + h.SizeOfRawData);
    for (std::size_t i = *idx + 1; i < pe_.sections.size(); ++i)
        pe_.sections[i].header.PointerToRawData -= removed;
    h.SizeOfRawData = newSize;
    h.Characteristics &= ~(IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE);
    s.rename(".export");
    dir.VirtualAddress = h.VirtualAddress;
}
void Patcher::dumpProcess(DWORD pid) {
    Handle p(OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid));
    if (!p)
        winError("OpenProcess");
    Handle snap(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid));
    if (!snap)
        winError("CreateToolhelp32Snapshot");
    MODULEENTRY32W m{};
    m.dwSize = sizeof(m);
    check(Module32FirstW(snap.get(), &m), "Module32First");
    auto &h = pe_.sections.front().header;
    auto end = pe_.nt.OptionalHeader.BaseOfData;
    if (end <= h.VirtualAddress)
        throw std::runtime_error("Invalid code range");
    auto code = readMemory(p.get(), reinterpret_cast<Address>(m.modBaseAddr) + h.VirtualAddress,
                           end - h.VirtualAddress);
    bounds(data_.size(), h.PointerToRawData, code.size());
    std::copy(code.begin(), code.end(), data_.begin() + h.PointerToRawData);
    auto out = path_;
    out.replace_extension(L".novm.exe");
    writeFileAtomic(out, data_);
    log(log_, LogType::Good, L"Dumped code to " + out.wstring());
}
#endif
} // namespace mm
