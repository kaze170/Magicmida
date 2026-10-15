// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "Binary.hpp"
#include <algorithm>

namespace mm {
inline constexpr std::size_t maxPESections = 96;
struct SectionExtent {
    std::uint32_t virtualAddress{}, virtualSize{}, rawOffset{}, rawSize{};
};
struct SectionAppendPlan {
    std::uint32_t virtualAddress{}, rawOffset{}, rawSize{}, imageSize{};
};
// Plans metadata only; callers remain responsible for payload/overlay placement
// and header capacity. Check every declared extent, never just the final row.
inline SectionAppendPlan planSectionAppend(std::span<const SectionExtent> sections, std::uint32_t headersSize,
                                           std::uint32_t imageSize, std::uint32_t fileAlignment,
                                           std::uint32_t sectionAlignment, std::uint32_t size) {
    if (sections.empty() || sections.size() >= maxPESections)
        throw std::runtime_error("Cannot append: invalid or full PE section table");
    if (!size)
        throw std::runtime_error("Cannot append an empty PE section");
    alignUp(0, fileAlignment);
    alignUp(0, sectionAlignment);
    std::uint32_t virtualEnd = std::max(headersSize, imageSize), rawEnd = headersSize;
    for (const auto &section : sections) {
        auto extent = std::max(section.virtualSize, section.rawSize);
        if (extent)
            virtualEnd = std::max(virtualEnd, rva32(std::uint64_t(section.virtualAddress) + extent));
        // BSS has no file-backed bytes; its raw pointer is not an allocation.
        if (section.rawSize)
            rawEnd = std::max(rawEnd, rva32(std::uint64_t(section.rawOffset) + section.rawSize));
    }
    SectionAppendPlan result{alignUp(virtualEnd, sectionAlignment), alignUp(rawEnd, fileAlignment),
                             alignUp(size, fileAlignment), 0};
    rva32(std::uint64_t(result.rawOffset) + result.rawSize);
    result.imageSize = alignUp(rva32(std::uint64_t(result.virtualAddress) + std::max(size, result.rawSize)),
                               sectionAlignment);
    return result;
}
} // namespace mm
