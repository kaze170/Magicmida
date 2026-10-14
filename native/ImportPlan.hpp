// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "OneCoreUAP.hpp"
#include <algorithm>
#include <cstdint>
#include <iterator>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mm {
// Architecture-independent planning lets the same regression tests cover PE32
// and PE32+ addresses, including x64 imports far above the 4 GiB boundary.
struct ImportSymbol {
    std::string dll;
    std::string name;
};
using ImportCandidates = std::map<std::uint64_t, std::vector<ImportSymbol>>;
using OriginalImports = std::set<std::pair<std::string, std::string>>;
struct ImportRun {
    std::size_t first{};
    std::string dll;
    std::vector<std::string> names;
};
struct UnclassifiedImportRange {
    std::size_t first{}, count{};
};
struct ImportPlan {
    std::vector<ImportRun> runs;
    std::vector<UnclassifiedImportRange> unclassified;
};
inline bool preferredImportModule(std::string_view name) {
    constexpr std::string_view preferred[] = {"kernel32.dll", "ole32.dll",    "advapi32.dll",
                                              "netapi32.dll", "comdlg32.dll", "crypt32.dll",
                                              "gdi32.dll",    "dbghelp.dll",  "setupapi.dll"};
    return std::find(std::begin(preferred), std::end(preferred), name) != std::end(preferred);
}
inline ImportPlan planImports(std::span<const std::uint64_t> slots, const ImportCandidates &candidates,
                              const OriginalImports &original) {
    ImportPlan result;
    bool allowSets = std::any_of(original.begin(), original.end(),
                                 [](const auto &p) { return p.first.starts_with("api-ms-win"); });
    auto unclassified = [&](std::size_t index) {
        if (!result.unclassified.empty() &&
            result.unclassified.back().first + result.unclassified.back().count == index)
            ++result.unclassified.back().count;
        else
            result.unclassified.push_back({index, 1});
    };
    for (std::size_t first = 0; first < slots.size();) {
        if (!slots[first]) {
            ++first;
            continue;
        }
        auto end = first;
        while (end < slots.size() && slots[end])
            ++end;
        // A module gets at most one vote per slot, regardless of export aliases.
        std::map<std::string, std::size_t> votes;
        for (auto i = first; i < end; ++i)
            if (auto it = candidates.find(slots[i]); it != candidates.end()) {
                std::set<std::string> seen;
                for (const auto &c : it->second) {
                    if (c.dll.empty() || c.name.empty())
                        throw std::runtime_error("Invalid import candidate");
                    if (seen.insert(c.dll).second)
                        ++votes[c.dll];
                }
            }
        if (votes.empty()) {
            // A heuristic IAT span can contain pointers/metadata between real
            // import groups. Do not make up an import or erase these bytes.
            for (auto i = first; i < end; ++i)
                unclassified(i);
            first = end;
            continue;
        }
        auto better = [&](const std::string &a, const std::string &b) {
            if (votes.at(a) != votes.at(b))
                return votes.at(a) > votes.at(b);
            if (preferredImportModule(a) != preferredImportModule(b))
                return preferredImportModule(a);
            return a < b; // stable, independent of Toolhelp enumeration order
        };
        std::string winner = votes.begin()->first;
        for (const auto &[dll, count] : votes) {
            (void)count;
            if (better(dll, winner))
                winner = dll;
        }
        std::vector<std::optional<ImportSymbol>> chosen(end - first);
        std::string apiSet;
        bool haveSet = false, sameSet = true, keepOriginal = false;
        for (auto i = first; i < end; ++i) {
            auto it = candidates.find(slots[i]);
            if (it == candidates.end() || it->second.empty())
                continue;
            const auto &choices = it->second;
            auto pick =
                std::find_if(choices.begin(), choices.end(), [&](const auto &c) { return c.dll == winner; });
            if (pick == choices.end()) {
                // A valid API without a candidate in the winning module is not
                // bogus data: retain it using its actual DLL, in a separate run.
                pick = choices.begin();
                for (auto c = choices.begin(); c != choices.end(); ++c)
                    if (better(c->dll, pick->dll))
                        pick = c;
            }
            chosen[i - first] = *pick;
            auto lookup = std::string_view(pick->name);
            if (lookup.starts_with("RtlQueryPerformance"))
                lookup.remove_prefix(3);
            std::string set(oneCoreModule(lookup));
            if (!haveSet) {
                apiSet = set;
                haveSet = true;
            } else if (apiSet != set)
                sameSet = false;
            if (original.contains({pick->dll, pick->name}))
                keepOriginal = true;
        }
        bool useSet = allowSets && sameSet && !apiSet.empty() && !keepOriginal;
        for (auto i = first; i < end; ++i) {
            auto &symbol = chosen[i - first];
            if (!symbol) {
                unclassified(i);
                continue;
            }
            if (useSet) {
                symbol->dll = apiSet;
                if (symbol->name.starts_with("RtlQueryPerformance"))
                    symbol->name.erase(0, 3);
            }
            // FirstThunk must refer to the real slot. Never compact a hole or
            // write an OFT over a skipped slot or a different module's imports.
            if (result.runs.empty() || result.runs.back().dll != symbol->dll ||
                result.runs.back().first + result.runs.back().names.size() != i)
                result.runs.push_back({i, symbol->dll, {}});
            result.runs.back().names.push_back(symbol->name);
        }
        first = end;
    }
    if (result.runs.empty())
        throw std::runtime_error("No resolvable imports in IAT candidate range");
    return result;
}
} // namespace mm
