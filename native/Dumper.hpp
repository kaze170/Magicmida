// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "PEInfo.hpp"
namespace mm {
inline constexpr std::size_t maxImports = 5120;
class Dumper {
    struct Export {
        std::string name, forward;
        Address address{};
    };
    struct Module {
        Address base{};
        DWORD size{};
        std::string name;
        std::vector<Export> exports;
    };
    struct Candidate {
        std::size_t module, entry;
    };
    HANDLE process_;
    DWORD pid_;
    Path original_;
    Address base_, oep_;
    Logger log_;
    std::vector<Module> modules_;
    std::map<Address, std::vector<Candidate>> candidates_;
    std::set<std::pair<std::string, std::string>> originalImports_;
    void snapshot();
    void gather(Module &m, const Path &path);
    Address resolve(std::size_t module, std::size_t entry,
                    std::set<std::pair<std::size_t, std::size_t>> &visited);
    void originalImports();

  public:
    Dumper(HANDLE process, DWORD pid, Path original, Address base, Address oep, Logger logger);
    bool isAPI(Address address) const { return candidates_.contains(address); }
    std::size_t iatSize(std::span<const Address> values) const;
    void dump(const Path &path, Address iat, bool dll);
    static Bytes imageMemory(HANDLE process, Address base, std::size_t size);
    static void dumpDotNet(HANDLE process, Address base, const Path &path);
};
} // namespace mm
