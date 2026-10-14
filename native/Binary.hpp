// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <vector>
namespace mm {
inline void bounds(std::size_t size, std::size_t offset, std::size_t count) {
    if (offset > size || count > size - offset)
        throw std::runtime_error("Truncated or malformed binary");
}
template <class T> T load(std::span<const std::uint8_t> data, std::size_t offset) {
    static_assert(std::is_trivially_copyable_v<T>);
    bounds(data.size(), offset, sizeof(T));
    T value;
    std::memcpy(&value, data.data() + offset, sizeof(T));
    return value;
}
template <class T> void store(std::span<std::uint8_t> data, std::size_t offset, const T &value) {
    static_assert(std::is_trivially_copyable_v<T>);
    bounds(data.size(), offset, sizeof(T));
    std::memcpy(data.data() + offset, &value, sizeof(T));
}
inline std::uint32_t alignUp(std::uint32_t value, std::uint32_t alignment) {
    if (!alignment || (alignment & (alignment - 1)))
        throw std::runtime_error("Invalid PE alignment");
    auto result = (std::uint64_t(value) + alignment - 1) & ~std::uint64_t(alignment - 1);
    if (result > UINT32_MAX)
        throw std::runtime_error("PE alignment overflow");
    return static_cast<std::uint32_t>(result);
}
inline std::uint32_t rva32(std::uint64_t value) {
    if (value > UINT32_MAX)
        throw std::runtime_error("PE RVA overflow");
    return static_cast<std::uint32_t>(value);
}
inline std::string_view stringAt(std::span<const std::uint8_t> bytes, std::size_t offset) {
    bounds(bytes.size(), offset, 1);
    const auto *start = reinterpret_cast<const char *>(bytes.data() + offset);
    const auto *end = static_cast<const char *>(std::memchr(start, 0, bytes.size() - offset));
    if (!end)
        throw std::runtime_error("Unterminated binary string");
    return {start, static_cast<std::size_t>(end - start)};
}
// Unlike the Pascal helpers, a match at offset zero is not confused with not found.
inline std::optional<std::size_t> findPattern(std::span<const std::uint8_t> data, std::string_view text) {
    if (text.empty() || text.size() % 2)
        throw std::invalid_argument("Invalid pattern length");
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        throw std::invalid_argument("Invalid pattern digit");
    };
    std::vector<int> pattern;
    for (std::size_t i = 0; i < text.size(); i += 2) {
        if (text[i] == '?' && text[i + 1] == '?')
            pattern.push_back(-1);
        else
            pattern.push_back(nibble(text[i]) * 16 + nibble(text[i + 1]));
    }
    if (pattern.size() > data.size())
        return {};
    for (std::size_t i = 0; i <= data.size() - pattern.size(); ++i) {
        bool match = true;
        for (std::size_t j = 0; j < pattern.size(); ++j)
            if (pattern[j] >= 0 && data[i + j] != pattern[j]) {
                match = false;
                break;
            }
        if (match)
            return i;
    }
    return {};
}
} // namespace mm
