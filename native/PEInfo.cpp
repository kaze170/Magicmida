// SPDX-License-Identifier: GPL-3.0-only
#include "PEInfo.hpp"
namespace mm {
Bytes readPEHeader(HANDLE process, Address base) {
    auto dos = readValue<IMAGE_DOS_HEADER>(process, base);
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)) ||
        dos.e_lfanew > 1024 * 1024)
        throw std::runtime_error("Invalid remote DOS header");
    auto offset = static_cast<std::size_t>(dos.e_lfanew);
    if (base > UINTPTR_MAX - offset - sizeof(IMAGE_NT_HEADERS))
        throw std::runtime_error("Remote header address overflow");
    auto nt = readValue<IMAGE_NT_HEADERS>(process, base + offset);
    if (nt.Signature != IMAGE_NT_SIGNATURE || !nt.FileHeader.NumberOfSections ||
        nt.FileHeader.NumberOfSections > 96)
        throw std::runtime_error("Invalid remote NT header");
    return readMemory(process, base,
                      offset + sizeof(nt) +
                          std::size_t(nt.FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER));
}
std::string Section::name() const {
    const auto *p = reinterpret_cast<const char *>(header.Name);
    auto n = std::find(p, p + 8, '\0');
    return {p, n};
}
void Section::rename(std::string_view s) {
    std::memset(header.Name, 0, 8);
    std::memcpy(header.Name, s.data(), std::min<std::size_t>(8, s.size()));
}
PEImage::PEImage(std::span<const std::uint8_t> image) {
    auto dos = load<IMAGE_DOS_HEADER>(image, 0);
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0)
        throw std::runtime_error("Invalid DOS header");
    ntOffset = static_cast<DWORD>(dos.e_lfanew);
    nt = load<IMAGE_NT_HEADERS>(image, ntOffset);
    if (nt.Signature != IMAGE_NT_SIGNATURE)
        throw std::runtime_error("Invalid PE signature");
#ifdef _WIN64
    constexpr WORD machine = IMAGE_FILE_MACHINE_AMD64, magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
#else
    constexpr WORD machine = IMAGE_FILE_MACHINE_I386, magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
#endif
    if (nt.FileHeader.Machine != machine || nt.OptionalHeader.Magic != magic)
        throw std::runtime_error("Wrong architecture: use the matching Win32 or x64 Magicmida build");
    if (nt.FileHeader.SizeOfOptionalHeader != sizeof(nt.OptionalHeader) || !nt.FileHeader.NumberOfSections ||
        nt.FileHeader.NumberOfSections > 96 ||
        nt.OptionalHeader.NumberOfRvaAndSizes > IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
        throw std::runtime_error("Unsupported or malformed PE header");
    fileAlign(0);
    sectionAlign(0);
    bounds(image.size(), ntOffset,
           sizeof(nt) + std::size_t(nt.FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER));
    sections.reserve(nt.FileHeader.NumberOfSections);
    for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
        Section s{
            load<IMAGE_SECTION_HEADER>(image, ntOffset + sizeof(nt) + i * sizeof(IMAGE_SECTION_HEADER))};
        if (std::uint64_t(s.header.VirtualAddress) +
                    std::max(s.header.Misc.VirtualSize, s.header.SizeOfRawData) >
                UINT32_MAX ||
            std::uint64_t(s.header.PointerToRawData) + s.header.SizeOfRawData > UINT32_MAX)
            throw std::runtime_error("Section RVA or raw-offset overflow");
        sections.push_back(s);
    }
}
std::optional<std::size_t> PEImage::sectionAt(DWORD rva) const {
    for (std::size_t i = 0; i < sections.size(); ++i) {
        auto &h = sections[i].header;
        if (rva >= h.VirtualAddress && rva - h.VirtualAddress < std::max(h.Misc.VirtualSize, h.SizeOfRawData))
            return i;
    }
    return {};
}
std::size_t PEImage::fileOffset(DWORD rva, std::size_t n) const {
    if (rva < nt.OptionalHeader.SizeOfHeaders) {
        bounds(nt.OptionalHeader.SizeOfHeaders, rva, n);
        return rva;
    }
    auto i = sectionAt(rva);
    if (!i)
        throw std::runtime_error("RVA outside PE sections");
    auto &s = sections[*i].header;
    auto delta = rva - s.VirtualAddress;
    bounds(s.SizeOfRawData, delta, n);
    return std::size_t(s.PointerToRawData) + delta;
}
void PEImage::accessMapped(std::span<const BYTE> file, DWORD rva, std::size_t length, BYTE *output) const {
    bounds(nt.OptionalHeader.SizeOfImage, rva, length);
    std::size_t completed = 0;
    while (completed < length) {
        auto current = rva32(std::uint64_t(rva) + completed);
        std::size_t count, backed, offset;
        if (current < nt.OptionalHeader.SizeOfHeaders) {
            count = std::min<std::size_t>(length - completed, nt.OptionalHeader.SizeOfHeaders - current);
            backed = count;
            offset = current;
        } else {
            auto index = sectionAt(current);
            if (!index)
                throw std::runtime_error("Mapped RVA range crosses a section gap");
            const auto &h = sections[*index].header;
            auto delta = current - h.VirtualAddress;
            count = std::min<std::size_t>(length - completed,
                                          std::max(h.Misc.VirtualSize, h.SizeOfRawData) - delta);
            backed = delta < h.SizeOfRawData ? std::min<std::size_t>(count, h.SizeOfRawData - delta) : 0;
            offset = backed ? rva32(std::uint64_t(h.PointerToRawData) + delta) : 0;
        }
        bounds(file.size(), offset, backed); // missing raw bytes are NOT BSS
        if (output) {
            if (backed)
                std::memcpy(output + completed, file.data() + offset, backed);
            std::fill(output + completed + backed, output + completed + count, BYTE(0));
        }
        completed += count;
    }
}
void PEImage::sanitize() {
    for (auto &s : sections) {
        s.header.PointerToRawData = s.header.VirtualAddress;
        s.header.SizeOfRawData = fileAlign(s.header.Misc.VirtualSize);
    }
    nt.OptionalHeader.SizeOfHeaders = sections.front().header.PointerToRawData;
    sections.front().header.Characteristics |= IMAGE_SCN_MEM_WRITE;
}
void PEImage::save(Bytes &image) const {
    if (sections.empty() || sections.size() > maxPESections)
        throw std::runtime_error("Cannot save: invalid PE section count");
    auto end = std::uint64_t(ntOffset) + sizeof(nt) + sections.size() * sizeof(IMAGE_SECTION_HEADER);
    if (end > nt.OptionalHeader.SizeOfHeaders)
        throw std::runtime_error("No space for new section headers");
    bounds(image.size(), 0, nt.OptionalHeader.SizeOfHeaders);
    auto hdr = nt;
    hdr.FileHeader.NumberOfSections = static_cast<WORD>(sections.size());
    store(image, ntOffset, hdr);
    for (std::size_t i = 0; i < sections.size(); ++i)
        store(image, ntOffset + sizeof(nt) + i * sizeof(IMAGE_SECTION_HEADER), sections[i].header);
    // Clear only obsolete section headers, not arbitrary header padding which
    // may contain live directory data.
    auto oldEnd = std::uint64_t(ntOffset) + sizeof(nt) +
                  std::size_t(nt.FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    if (oldEnd > end && oldEnd <= hdr.OptionalHeader.SizeOfHeaders)
        std::fill(image.begin() + end, image.begin() + oldEnd, 0);
}
Section &PEImage::append(std::string_view name, DWORD size) {
    if (sections.size() >= maxPESections)
        throw std::runtime_error("Cannot append: PE section table is full");
    std::array<SectionExtent, maxPESections> extents{};
    for (std::size_t i = 0; i < sections.size(); ++i) {
        const auto &h = sections[i].header;
        extents[i] = {h.VirtualAddress, h.Misc.VirtualSize, h.PointerToRawData, h.SizeOfRawData};
    }
    auto plan = planSectionAppend(std::span(extents).first(sections.size()), nt.OptionalHeader.SizeOfHeaders,
                                  nt.OptionalHeader.SizeOfImage, nt.OptionalHeader.FileAlignment,
                                  nt.OptionalHeader.SectionAlignment, size);
    Section s;
    s.rename(name);
    s.header.VirtualAddress = plan.virtualAddress;
    s.header.Misc.VirtualSize = size;
    s.header.SizeOfRawData = plan.rawSize;
    s.header.PointerToRawData = plan.rawOffset;
    s.header.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;
    // Publish SizeOfImage only after vector insertion succeeds.
    sections.push_back(s);
    nt.OptionalHeader.SizeOfImage = plan.imageSize;
    return sections.back();
}
void PEImage::switchManifest(Bytes &image, DWORD from, DWORD to) const {
    const auto &dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    if (!dir.VirtualAddress || !dir.Size)
        return;
    auto base = fileOffset(dir.VirtualAddress, dir.Size);
    bounds(image.size(), base, dir.Size);
    auto data = std::span<const std::uint8_t>(image).subspan(base, dir.Size);
    auto root = load<IMAGE_RESOURCE_DIRECTORY>(data, 0);
    for (unsigned i = root.NumberOfNamedEntries;
         i < unsigned(root.NumberOfNamedEntries) + root.NumberOfIdEntries; ++i) {
        auto e = load<IMAGE_RESOURCE_DIRECTORY_ENTRY>(data, sizeof(root) +
                                                                i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
        if (e.Id != 24 || !e.DataIsDirectory)
            continue;
        auto sub = load<IMAGE_RESOURCE_DIRECTORY>(data, e.OffsetToDirectory);
        if (sub.NumberOfNamedEntries || sub.NumberOfIdEntries != 1)
            return;
        auto off = e.OffsetToDirectory + sizeof(sub);
        auto id = load<DWORD>(data, off);
        if (id == from)
            store(image, base + off, to);
        return;
    }
}
void PEImage::trimHugeSections(Bytes &image) {
    for (std::size_t i = 0; i < sections.size(); ++i) {
        auto &h = sections[i].header;
        bounds(image.size(), h.PointerToRawData, h.SizeOfRawData);
        DWORD n = h.SizeOfRawData;
        while (n && image[h.PointerToRawData + n - 1] == 0)
            --n;
        auto size = fileAlign(n);
        if (h.SizeOfRawData - size <= 1024 * 1024)
            continue;
        auto delta = h.SizeOfRawData - size;
        auto off = h.PointerToRawData + size;
        image.erase(image.begin() + off, image.begin() + off + delta);
        h.SizeOfRawData = size;
        for (std::size_t j = i + 1; j < sections.size(); ++j)
            sections[j].header.PointerToRawData -= delta;
    }
}
} // namespace mm
