// SPDX-License-Identifier: GPL-3.0-only
#include "Test.hpp"
#include "Binary.hpp"
#include "OneCoreUAP.hpp"
#include "ImportPlan.hpp"
#include "SectionLayout.hpp"
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
    {
        constexpr std::uint64_t a = 0x7fff0737b090ULL, b = 0x7fff07377300ULL, c = 0x7fff0969a1f0ULL;
        ImportCandidates candidates{{a, {{"kernelbase.dll", "Alpha"}, {"kernel32.dll", "Alpha"}}},
                                    {b, {{"kernelbase.dll", "Beta"}, {"kernel32.dll", "Beta"}}},
                                    {c, {{"user32.dll", "Gamma"}}}};
        const std::vector<std::uint64_t> normal{a, b, 0};
        auto plan = planImports(normal, candidates, {});
        require(plan.runs.size() == 1 && plan.runs[0].dll == "kernel32.dll" && plan.runs[0].names.size() == 2,
                "module vote prefers kernel32 over kernelbase");
        const std::vector<std::uint64_t> gaps{a, 0, 0x11223344, 0x55667788, 0, b, 0x44556677, a, 0};
        plan = planImports(gaps, candidates, {});
        require(plan.runs.size() == 3, "metadata groups and interior holes do not abort IAT planning");
        require(plan.runs[0].first == 0 && plan.runs[1].first == 5 && plan.runs[2].first == 7,
                "holes retain exact FirstThunk indices");
        require(plan.unclassified.size() == 2 && plan.unclassified[0].first == 2 &&
                    plan.unclassified[0].count == 2 && plan.unclassified[1].first == 6,
                "unknown data ranges retained");
        const std::vector<std::uint64_t> mixed{a, c, b, 0};
        plan = planImports(mixed, candidates, {});
        require(plan.runs.size() == 3 && plan.runs[1].dll == "user32.dll" && plan.runs[1].first == 1,
                "mixed modules split without dropping real APIs");
        const std::vector<std::uint64_t> unknown{0x11223344, 0, 0x55667788};
        rejects([&] { planImports(unknown, candidates, {}); }, "all-unresolved table must still fail");
        const std::vector<std::uint64_t> zero{0, 0};
        rejects([&] { planImports(zero, candidates, {}); }, "all-zero table must still fail");
        const std::vector<std::uint64_t> leading{0x778899, 0, a, 0};
        plan = planImports(leading, candidates, {});
        require(plan.runs[0].first == 2 && plan.unclassified[0].first == 0,
                "leading metadata does not shift first import");
        auto aliases = candidates;
        aliases[a].insert(aliases[a].end(), 20, ImportSymbol{"kernelbase.dll", "Alias"});
        require(planImports(normal, aliases, {}).runs[0].dll == "kernel32.dll",
                "duplicate aliases cannot inflate votes");
        std::reverse(aliases[a].begin(), aliases[a].end());
        require(planImports(normal, aliases, {}).runs[0].dll == "kernel32.dll",
                "module choice independent of candidate order");
        ImportCandidates contracts{{a, {{"ntdll.dll", "RtlQueryPerformanceCounter"}}},
                                   {b, {{"kernelbase.dll", "QueryPerformanceFrequency"}}}};
        OriginalImports withApiSet{{"api-ms-win-core-profile-l1-1-0.dll", "QueryPerformanceCounter"}};
        plan = planImports(normal, contracts, withApiSet);
        require(plan.runs.size() == 1 && plan.runs[0].dll == "api-ms-win-core-profile-l1-1-0.dll" &&
                    plan.runs[0].names[0] == "QueryPerformanceCounter",
                "OneCore contract remaps compatible names");
        withApiSet.emplace("ntdll.dll", "RtlQueryPerformanceCounter");
        plan = planImports(normal, contracts, withApiSet);
        require(plan.runs[0].dll == "ntdll.dll", "explicit original import prevents API-set rewriting");
        ImportCandidates ordinal{{a, {{"sample.dll", "#42"}}}};
        plan = planImports(std::span(normal).first(1), ordinal, {});
        require(plan.runs[0].names[0] == "#42", "ordinal import retained");
        std::mt19937 planRandom(20261015);
        for (unsigned iteration = 0; iteration < 100; ++iteration) {
            const std::uint64_t choices[]{0, a, b, c, 0x9988776655443322ULL};
            std::vector<std::uint64_t> input(32);
            for (auto &value : input)
                value = choices[planRandom() % 5];
            input[0] = a;
            auto randomPlan = planImports(input, candidates, {});
            std::vector<unsigned> covered(input.size());
            for (const auto &run : randomPlan.runs) {
                require(!run.names.empty() && run.first + run.names.size() <= input.size(),
                        "planned run bounded");
                for (std::size_t j = 0; j < run.names.size(); ++j) {
                    auto index = run.first + j;
                    require(candidates.contains(input[index]), "run never crosses an unknown slot");
                    const auto &symbols = candidates.at(input[index]);
                    require(std::any_of(symbols.begin(), symbols.end(),
                                        [&](const auto &symbol) {
                                            return symbol.dll == run.dll && symbol.name == run.names[j];
                                        }),
                            "run only contains matching-module exports");
                    ++covered[index];
                }
            }
            for (const auto &range : randomPlan.unclassified) {
                require(range.count > 0 && range.first + range.count <= input.size(),
                        "unclassified range bounded");
                for (auto j = range.first; j < range.first + range.count; ++j) {
                    require(input[j] != 0 && !candidates.contains(input[j]),
                            "only unknown nonzero data is preserved as unclassified");
                    ++covered[j];
                }
            }
            for (std::size_t j = 0; j < input.size(); ++j)
                require(covered[j] == unsigned(input[j] != 0),
                        "every nonzero slot classified exactly once, zero slots untouched");
        }
        candidates[a] = {{"", "Alpha"}};
        rejects([&] { planImports(normal, candidates, {}); }, "invalid candidate not silently discarded");
    }
    {
        std::vector<SectionExtent> sections{{0x1000, 0x1000, 0x2000, 0x400}, {0x2000, 0x1000, 0x400, 0x200}};
        auto plan = [&](std::uint32_t size = 0x123) {
            return planSectionAppend(sections, 0x400, 0x3000, 0x200, 0x1000, size);
        };
        auto p = plan();
        require(p.rawOffset == 0x2400 && p.virtualAddress == 0x3000 && p.rawSize == 0x200 &&
                    p.imageSize == 0x4000,
                "append uses maximum extents rather than final header");
        sections.push_back({0x3000, 0x1000, 0, 0});
        p = plan();
        require(p.rawOffset == 0x2400 && p.virtualAddress == 0x4000,
                "BSS tail cannot reset raw append position to zero");
        std::reverse(sections.begin(), sections.end());
        require(plan().rawOffset == p.rawOffset && plan().virtualAddress == p.virtualAddress,
                "append placement is independent of header ordering");
        require(planSectionAppend(sections, 0x400, 0x9000, 0x200, 0x1000, 1).virtualAddress == 0x9000,
                "append does not reduce reserved image extent");
        sections = {{0x1000, 0x2000, 0xfffffff0u, 0}};
        require(plan().rawOffset == 0x400, "raw-empty BSS ignores unused raw pointer and retains headers");
        rejects([&] { plan(0); }, "empty appended section rejected");
        rejects([&] { planSectionAppend(sections, 0x400, 0x3000, 3, 0x1000, 1); },
                "invalid append file alignment rejected");
        rejects([&] { planSectionAppend(sections, 0x400, 0x3000, 0x200, 0, 1); },
                "invalid append section alignment rejected");
        rejects([&] { planSectionAppend(sections, 0x400, 0xfffff000u, 0x200, 0x1000, 0x1000); },
                "new virtual extent overflow rejected");
        sections = {{0x1000, 0x1000, 0xffffff00u, 0x200}};
        rejects([&] { plan(); }, "existing raw extent overflow rejected");
        sections = {{0xfffff000u, 0x2000, 0x400, 0x200}};
        rejects([&] { plan(); }, "existing virtual extent overflow rejected");
        sections = {{0x1000, 0x1000, 0xffffe000u, 0x1000}};
        rejects([&] { plan(0x2000); }, "new raw extent overflow rejected");
        sections.clear();
        rejects([&] { plan(); }, "empty section table rejected");
        sections.resize(maxPESections);
        rejects([&] { plan(); }, "full section table rejected");
        std::mt19937 rng(20261015);
        for (unsigned iteration = 0; iteration < 250; ++iteration) {
            sections.clear();
            std::uint64_t expectedVirtual = 0x5000, expectedRaw = 0x400;
            auto count = 1 + rng() % 40;
            for (unsigned i = 0; i < count; ++i) {
                SectionExtent h{std::uint32_t(0x1000 + i * 0x2000), std::uint32_t(1 + rng() % 0x1000),
                                std::uint32_t(0x400 + (count - i) * 0x2000),
                                std::uint32_t((rng() % 5) * 0x200)};
                if (!h.rawSize)
                    h.rawOffset = 0;
                expectedVirtual = std::max(expectedVirtual, std::uint64_t(h.virtualAddress) +
                                                                std::max(h.virtualSize, h.rawSize));
                if (h.rawSize)
                    expectedRaw = std::max(expectedRaw, std::uint64_t(h.rawOffset) + h.rawSize);
                sections.push_back(h);
            }
            std::shuffle(sections.begin(), sections.end(), rng);
            std::uint32_t size = 1 + rng() % 0x2000;
            p = planSectionAppend(sections, 0x400, 0x5000, 0x200, 0x1000, size);
            require(p.virtualAddress == ((expectedVirtual + 0xfff) & ~std::uint64_t(0xfff)),
                    "randomized virtual append placement");
            require(p.rawOffset == ((expectedRaw + 0x1ff) & ~std::uint64_t(0x1ff)),
                    "randomized raw append placement");
            require(p.rawSize >= size && p.rawSize % 0x200 == 0 && p.imageSize % 0x1000 == 0,
                    "randomized append alignment");
            for (const auto &h : sections) {
                require(p.virtualAddress >=
                            std::uint64_t(h.virtualAddress) + std::max(h.virtualSize, h.rawSize),
                        "appended RVA does not overlap any prior section");
                require(!h.rawSize || p.rawOffset >= std::uint64_t(h.rawOffset) + h.rawSize,
                        "appended raw range does not overlap any prior section");
            }
        }
    }
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
