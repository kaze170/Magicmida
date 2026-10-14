// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "Utils.hpp"
namespace mm {
struct Section {
    IMAGE_SECTION_HEADER header{};
    std::string name() const;
    void rename(std::string_view name);
};
Bytes readPEHeader(HANDLE process, Address base);
class PEImage {
  public:
    DWORD ntOffset{};
    IMAGE_NT_HEADERS nt{};
    std::vector<Section> sections;
    explicit PEImage(std::span<const std::uint8_t> header);
    std::optional<std::size_t> sectionAt(DWORD rva) const;
    std::size_t fileOffset(DWORD rva, std::size_t length = 1) const;
    DWORD fileAlign(DWORD n) const { return alignUp(n, nt.OptionalHeader.FileAlignment); }
    DWORD sectionAlign(DWORD n) const { return alignUp(n, nt.OptionalHeader.SectionAlignment); }
    void sanitize();
    void save(Bytes &image) const;
    Section &append(std::string_view name, DWORD size);
    void switchManifest(Bytes &image, DWORD from, DWORD to) const;
    void trimHugeSections(Bytes &image);
};
} // namespace mm
