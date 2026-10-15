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
    void accessMapped(std::span<const BYTE> file, DWORD rva, std::size_t length, BYTE *output) const;

  public:
    DWORD ntOffset{};
    IMAGE_NT_HEADERS nt{};
    std::vector<Section> sections;
    explicit PEImage(std::span<const std::uint8_t> header);
    std::optional<std::size_t> sectionAt(DWORD rva) const;
    std::size_t fileOffset(DWORD rva, std::size_t length = 1) const;
    // Interpret a declared mapped image, not a raw-file offset: virtual tails
    // are zero-filled, but holes and truncated file-backed bytes are errors.
    void validateMappedRange(std::span<const BYTE> file, DWORD rva, std::size_t length) const {
        accessMapped(file, rva, length, nullptr);
    }
    template <class T> T mappedValue(std::span<const BYTE> file, DWORD rva) const {
        static_assert(std::is_trivially_copyable_v<T>);
        T value{};
        accessMapped(file, rva, sizeof(T), reinterpret_cast<BYTE *>(&value));
        return value;
    }
    DWORD fileAlign(DWORD n) const { return alignUp(n, nt.OptionalHeader.FileAlignment); }
    DWORD sectionAlign(DWORD n) const { return alignUp(n, nt.OptionalHeader.SectionAlignment); }
    void sanitize();
    void save(Bytes &image) const;
    Section &append(std::string_view name, DWORD size);
    void switchManifest(Bytes &image, DWORD from, DWORD to) const;
    void trimHugeSections(Bytes &image);
};
} // namespace mm
