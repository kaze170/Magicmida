// SPDX-License-Identifier: GPL-3.0-only
#include "Test.hpp"
#include "Binary.hpp"
#include "OneCoreUAP.hpp"
#include <array>
#include <random>
using namespace mm;
void portableTests() {
    using test::rejects;
    using test::require;
    std::vector<std::uint8_t> bytes{0x00, 0xff, 0xab, 0x55};
    require(findPattern(bytes, "00FF") == 0, "match at offset zero");
    require(findPattern(bytes, "AB55") == 2, "match at last possible offset");
    require(findPattern(bytes, "00FFAB55") == 0, "exact-sized pattern");
    require(findPattern(bytes, "FF??55") == 1, "wildcard in middle");
    require(findPattern(bytes, "????????") == 0, "all wildcard pattern");
    require(!findPattern(bytes, "00FFAB5500"), "pattern longer than input");
    require(!findPattern({}, "FF"), "empty input");
    require(!findPattern(bytes, "1234"), "not-found is distinct from zero");
    for (auto bad : {"", "F", "?F", "F?", "GG", "0X", "AA BB"})
        rejects([&] { findPattern(bytes, bad); }, "reject malformed pattern");
    bytes.assign(80, 0xaa);
    bytes.back() = 0x42;
    std::string longPattern(160, '?');
    longPattern.replace(158, 2, "42");
    require(findPattern(bytes, longPattern) == 0, "wildcard masks beyond 32 bits");
    require(alignUp(0, 0x200) == 0 && alignUp(1, 0x200) == 0x200 && alignUp(0x200, 0x200) == 0x200,
            "alignment");
    require(alignUp(0xfffff000, 0x1000) == 0xfffff000, "upper aligned value");
    rejects([] { alignUp(1, 0); }, "zero alignment");
    rejects([] { alignUp(1, 3); }, "non-power-of-two alignment");
    rejects([] { alignUp(UINT32_MAX, 0x200); }, "alignment overflow");
    rejects([] { rva32(UINT64_MAX); }, "RVA overflow");
    require(rva32(UINT32_MAX) == UINT32_MAX, "max valid RVA");
    std::array<std::uint8_t, 9> packed{};
    store<std::uint64_t>(packed, 1, 0x0123456789abcdefULL);
    require(load<std::uint64_t>(packed, 1) == 0x0123456789abcdefULL, "unaligned load/store");
    rejects([&] { load<std::uint64_t>(packed, 2); }, "truncated load");
    rejects([&] { store<std::uint64_t>(packed, SIZE_MAX, 1); }, "overflowing store offset");
    rejects([] { bounds(1, SIZE_MAX, 2); }, "overflowing bounds");
    std::array<std::uint8_t, 5> string{'h', 'i', 0, 'x', 'y'};
    require(stringAt(string, 0) == "hi", "bounded string");
    require(stringAt(string, 2).empty(), "empty bounded string");
    rejects([&] { stringAt(string, 3); }, "unterminated string");
    rejects([&] { stringAt(string, 5); }, "out-of-range string");
    require(oneCoreModule("CreateNewAdvertisingId") == "api-ms-win-appmodel-advertisingid-l1-1-0.dll",
            "first OneCore API");
    require(oneCoreModule("SHCreateDirectoryExW") == "api-ms-win-shell-shdirectory-l1-1-0.dll",
            "last OneCore API");
    require(oneCoreModule("__not_an_api__").empty(), "unknown OneCore API");
    std::mt19937 random(0x170);
    // Exercise boundary matches and absent patterns against a simple reference.
    for (unsigned round = 0; round < 1000; ++round) {
        std::vector<std::uint8_t> data(random() % 64);
        for (auto &b : data)
            b = static_cast<std::uint8_t>(random());
        unsigned value = random() % 256;
        char digits[] = "0123456789ABCDEF";
        std::string pattern{digits[value >> 4], digits[value & 15]};
        auto got = findPattern(data, pattern);
        std::optional<std::size_t> expected;
        for (std::size_t i = 0; i < data.size(); ++i)
            if (data[i] == value) {
                expected = i;
                break;
            }
        require(got == expected, "randomized pattern reference comparison");
    }
}
#ifdef MM_PORTABLE_MAIN
int main() {
    try {
        portableTests();
        std::cout << test::checks << " portable checks passed\n";
        return 0;
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
#endif
