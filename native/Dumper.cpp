// SPDX-License-Identifier: GPL-3.0-only
#include "Dumper.hpp"
#include <tlhelp32.h>
namespace mm {
Bytes Dumper::imageMemory(HANDLE p, Address base, std::size_t size) {
    if (size && base > UINTPTR_MAX - (size - 1))
        throw std::runtime_error("Image address range overflow");
    Bytes data(size);
    for (std::size_t offset = 0; offset < size;) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQueryEx(p, reinterpret_cast<void *>(base + offset), &mbi, sizeof(mbi)))
            winError("VirtualQueryEx");
        auto end = reinterpret_cast<Address>(mbi.BaseAddress) + mbi.RegionSize;
        if (end <= base + offset)
            throw std::runtime_error("Invalid memory region");
        auto n = std::min<std::size_t>(size - offset, end - base - offset);
        if (mbi.State == MEM_COMMIT) {
            DWORD old{}, ignored{};
            bool change = (mbi.Protect & PAGE_GUARD) || ((mbi.Protect & 255) == PAGE_NOACCESS);
            if (change)
                check(VirtualProtectEx(p, reinterpret_cast<void *>(base + offset), n, PAGE_READONLY, &old),
                      "VirtualProtectEx(dump)");
            bool ok = readMemory(p, base + offset, data.data() + offset, n);
            DWORD error = GetLastError();
            if (change)
                check(VirtualProtectEx(p, reinterpret_cast<void *>(base + offset), n, old, &ignored),
                      "VirtualProtectEx(restore dump)");
            if (!ok)
                winError("ReadProcessMemory(dump)", error);
        } else if (mbi.State != MEM_RESERVE)
            throw std::runtime_error("Unmapped region inside image");
        offset += n;
    }
    return data;
}
Dumper::Dumper(HANDLE p, DWORD pid, Path original, Address base, Address oep, Logger l)
    : process_(p), pid_(pid), original_(std::move(original)), base_(base), oep_(oep), log_(std::move(l)) {
    originalImports();
    snapshot();
}
void Dumper::originalImports() {
    auto data = readFile(original_);
    PEImage pe(data);
    auto dir = pe.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size)
        return;
    try {
        for (std::size_t i = 0; i < dir.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR); ++i) {
            auto d = load<IMAGE_IMPORT_DESCRIPTOR>(
                data,
                pe.fileOffset(rva32(std::uint64_t(dir.VirtualAddress) + i * sizeof(IMAGE_IMPORT_DESCRIPTOR)),
                              sizeof(IMAGE_IMPORT_DESCRIPTOR)));
            if (!d.Name)
                break;
            std::string dll = lower(std::string(stringAt(data, pe.fileOffset(d.Name))));
            auto thunk = d.OriginalFirstThunk ? d.OriginalFirstThunk : d.FirstThunk;
            for (std::size_t j = 0; j < maxImports; ++j) {
                auto v = load<Address>(
                    data, pe.fileOffset(rva32(std::uint64_t(thunk) + j * sizeof(Address)), sizeof(Address)));
                if (!v)
                    break;
                auto name = (v & IMAGE_ORDINAL_FLAG)
                                ? "#" + std::to_string(v & 0xffff)
                                : std::string(stringAt(data, pe.fileOffset(rva32(v + 2))));
                originalImports_.emplace(dll, name);
            }
        }
    } catch (const std::exception &e) {
        log(log_, LogType::Info, L"Original imports incomplete: " + widen(e.what()));
    }
}
void Dumper::gather(Module &m, const Path &path) {
    auto head = readPEHeader(process_, m.base);
    PEImage pe(head);
    auto dir = pe.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || dir.Size < sizeof(IMAGE_EXPORT_DIRECTORY))
        return;
    bounds(m.size, dir.VirtualAddress, dir.Size);
    auto bytes = readMemory(process_, m.base + dir.VirtualAddress, dir.Size);
    auto offset = [&](DWORD rva, std::size_t n) {
        if (rva < dir.VirtualAddress)
            throw std::runtime_error("Export outside directory");
        bounds(bytes.size(), rva - dir.VirtualAddress, n);
        return rva - dir.VirtualAddress;
    };
    auto e = load<IMAGE_EXPORT_DIRECTORY>(bytes, 0);
    if (e.NumberOfFunctions > 1000000 || e.NumberOfNames > 1000000)
        throw std::runtime_error("Invalid export count");
    std::vector<std::string> names(e.NumberOfFunctions);
    for (DWORD i = 0; i < e.NumberOfNames; ++i) {
        auto index = load<WORD>(bytes, offset(rva32(std::uint64_t(e.AddressOfNameOrdinals) + i * 2), 2));
        if (index >= names.size())
            throw std::runtime_error("Invalid export ordinal");
        auto rva = load<DWORD>(bytes, offset(rva32(std::uint64_t(e.AddressOfNames) + i * 4), 4));
        names[index] = stringAt(bytes, offset(rva, 1));
    }
    for (DWORD i = 0; i < e.NumberOfFunctions; ++i) {
        auto rva = load<DWORD>(bytes, offset(rva32(std::uint64_t(e.AddressOfFunctions) + i * 4), 4));
        if (!rva)
            continue;
        Export ex;
        ex.name = names[i].empty() ? "#" + std::to_string(e.Base + i) : names[i];
        ex.address = m.base + rva;
        if (rva >= dir.VirtualAddress && rva - dir.VirtualAddress < dir.Size)
            ex.forward = stringAt(bytes, rva - dir.VirtualAddress);
        m.exports.push_back(std::move(ex));
    }
    // user32 patches forwarding entries at load time. Recover their original
    // names/forward strings from the disk image without loading a second DLL.
    if (m.name == "user32.dll") {
        auto disk = readFile(path);
        PEImage dp(disk);
        auto dd = dp.nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (dd.VirtualAddress && dd.Size) {
            auto de = load<IMAGE_EXPORT_DIRECTORY>(
                disk, dp.fileOffset(dd.VirtualAddress, sizeof(IMAGE_EXPORT_DIRECTORY)));
            for (DWORD i = 0; i < de.NumberOfNames; ++i) {
                auto ni = load<DWORD>(disk, dp.fileOffset(de.AddressOfNames + i * 4, 4));
                auto ord = load<WORD>(disk, dp.fileOffset(de.AddressOfNameOrdinals + i * 2, 2));
                if (ord >= de.NumberOfFunctions)
                    throw std::runtime_error("Invalid user32 export ordinal");
                auto rva = load<DWORD>(disk, dp.fileOffset(de.AddressOfFunctions + ord * 4, 4));
                if (rva >= dd.VirtualAddress && rva - dd.VirtualAddress < dd.Size) {
                    auto name = stringAt(disk, dp.fileOffset(ni));
                    for (auto &ex : m.exports)
                        if (ex.name == name)
                            ex.forward = stringAt(disk, dp.fileOffset(rva));
                }
            }
        }
    }
}
Address Dumper::resolve(std::size_t mi, std::size_t ei, std::set<std::pair<std::size_t, std::size_t>> &seen) {
    if (!seen.emplace(mi, ei).second || seen.size() > 32)
        return 0;
    auto &ex = modules_[mi].exports[ei];
    if (ex.forward.empty())
        return ex.address;
    auto dot = ex.forward.rfind('.');
    if (dot == std::string::npos)
        return 0;
    auto dll = lower(ex.forward.substr(0, dot)) + ".dll", name = ex.forward.substr(dot + 1);
    if (dll.starts_with("api-") || dll.starts_with("ext-")) {
        // Resolve the API-set contract locally, then translate the owning module's
        // RVA into the target. Never assume ASLR bases match between processes.
        HMODULE h = LoadLibraryExW(widen(dll).c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!h)
            return 0;
        auto proc = GetProcAddress(h, name.starts_with('#')
                                          ? MAKEINTRESOURCEA(static_cast<WORD>(std::stoul(name.substr(1))))
                                          : name.c_str());
        HMODULE owner{};
        Address result{};
        if (proc && GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                       reinterpret_cast<LPCWSTR>(proc), &owner)) {
            wchar_t file[32768]{};
            if (GetModuleFileNameW(owner, file, 32768)) {
                auto own = lower(narrow(Path(file).filename().wstring()));
                for (auto &m : modules_)
                    if (m.name == own)
                        result = m.base + reinterpret_cast<Address>(proc) - reinterpret_cast<Address>(owner);
            }
        }
        FreeLibrary(h);
        return result;
    }
    for (std::size_t m = 0; m < modules_.size(); ++m)
        if (modules_[m].name == dll)
            for (std::size_t e = 0; e < modules_[m].exports.size(); ++e)
                if (modules_[m].exports[e].name == name)
                    return resolve(m, e, seen);
    return 0;
}
void Dumper::snapshot() {
    Handle snap(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid_));
    if (!snap)
        winError("CreateToolhelp32Snapshot");
    MODULEENTRY32W e{};
    e.dwSize = sizeof(e);
    check(Module32FirstW(snap.get(), &e), "Module32First");
    do {
        if (reinterpret_cast<Address>(e.modBaseAddr) == base_)
            continue;
        Module m;
        m.base = reinterpret_cast<Address>(e.modBaseAddr);
        m.size = e.modBaseSize;
        m.name = lower(narrow(e.szModule));
        gather(m, e.szExePath);
        modules_.push_back(std::move(m));
    } while (Module32NextW(snap.get(), &e));
    for (std::size_t m = 0; m < modules_.size(); ++m)
        for (std::size_t i = 0; i < modules_[m].exports.size(); ++i) {
            std::set<std::pair<std::size_t, std::size_t>> seen;
            auto target = resolve(m, i, seen);
            if (target)
                candidates_[target].push_back({m, i});
        }
}
std::size_t Dumper::iatSize(std::span<const Address> values) const {
    std::optional<std::size_t> last;
    for (std::size_t i = 0; i < values.size() && (!last || (i - *last) * sizeof(Address) < 0x100); ++i)
        if (isAPI(values[i]))
            last = i;
    if (!last)
        throw std::runtime_error("No resolved imports in IAT");
    return *last + 1;
}
void Dumper::dump(const Path &output, Address iat, bool dll) {
    if (iat < base_)
        throw std::runtime_error("IAT precedes image base");
    auto header = readPEHeader(process_, base_);
    PEImage pe(header);
    pe.sanitize();
    auto size = pe.nt.OptionalHeader.SizeOfImage;
    auto image = imageMemory(process_, base_, size);
    auto iatRva = rva32(iat - base_);
    bounds(image.size(), iatRva, sizeof(Address));
    auto count = std::min(maxImports, (image.size() - iatRva) / sizeof(Address));
    std::vector<Address> slots(count);
    std::memcpy(slots.data(), image.data() + iatRva, count * sizeof(Address));
    slots.resize(iatSize(slots));
    struct Group {
        std::size_t first;
        std::string dll;
        std::vector<std::string> names;
    };
    std::vector<Group> groups;
    bool allowSets = std::any_of(originalImports_.begin(), originalImports_.end(),
                                 [](auto &p) { return p.first.starts_with("api-ms-win"); });
    auto score = [](std::string_view name) {
        constexpr std::string_view preferred[] = {"kernel32.dll", "ole32.dll",    "advapi32.dll",
                                                  "netapi32.dll", "comdlg32.dll", "crypt32.dll",
                                                  "gdi32.dll",    "dbghelp.dll",  "setupapi.dll"};
        return std::find(std::begin(preferred), std::end(preferred), name) != std::end(preferred);
    };
    for (std::size_t i = 0; i < slots.size();) {
        if (!slots[i]) {
            ++i;
            continue;
        }
        auto end = i;
        while (end < slots.size() && slots[end])
            ++end;
        std::map<std::size_t, unsigned> votes;
        for (auto j = i; j < end; ++j)
            if (auto it = candidates_.find(slots[j]); it != candidates_.end()) {
                std::set<std::size_t> once;
                for (auto c : it->second)
                    if (once.insert(c.module).second)
                        ++votes[c.module];
            }
        if (votes.empty())
            throw std::runtime_error("Unresolved IAT group");
        auto winner = votes.begin()->first;
        for (auto [m, n] : votes)
            if (n > votes[winner] ||
                (n == votes[winner] && score(modules_[m].name) > score(modules_[winner].name)))
                winner = m;
        Group g{i, modules_[winner].name, {}};
        std::string apiSet;
        bool sameSet = true;
        for (auto j = i; j < end; ++j) {
            auto it = candidates_.find(slots[j]);
            if (it == candidates_.end())
                throw std::runtime_error("Unresolved IAT slot; refusing to emit a broken import table");
            auto chosen = std::find_if(it->second.begin(), it->second.end(),
                                       [&](auto c) { return c.module == winner; });
            auto c = chosen == it->second.end() ? it->second.front() : *chosen;
            auto name = modules_[c.module].exports[c.entry].name;
            auto lookup = name.starts_with("RtlQueryPerformance") ? name.substr(3) : name;
            std::string set(oneCoreModule(lookup));
            if (j == i)
                apiSet = set;
            else if (apiSet != set)
                sameSet = false;
            g.names.push_back(name);
        }
        if (allowSets && sameSet && !apiSet.empty() && !originalImports_.contains({g.dll, g.names.front()})) {
            g.dll = apiSet;
            for (auto &name : g.names)
                if (name.starts_with("RtlQueryPerformance"))
                    name.erase(0, 3);
        } else {
            for (auto j = i; j < end; ++j) {
                auto &cs = candidates_.at(slots[j]);
                if (std::none_of(cs.begin(), cs.end(), [&](auto c) { return c.module == winner; }))
                    throw std::runtime_error("Import group spans incompatible modules");
            }
        }
        groups.push_back(std::move(g));
        i = end;
    }
    Bytes import((groups.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR));
    auto appendString = [&](std::string_view s) {
        auto off = import.size();
        import.insert(import.end(), s.begin(), s.end());
        import.push_back(0);
        return off;
    };
    pe.trimHugeSections(image);
    auto &sect = pe.append(".import", 0x1000);
    auto start = sect.header.VirtualAddress;
    std::vector<Address> rebuilt(slots.size() + 1); // Include the final IAT terminator.
    for (std::size_t i = 0; i < groups.size(); ++i) {
        auto &g = groups[i];
        IMAGE_IMPORT_DESCRIPTOR d{};
        d.FirstThunk = rva32(std::uint64_t(iatRva) + g.first * sizeof(Address));
        d.Name = rva32(start + appendString(g.dll));
        std::vector<Address> lookup;
        for (std::size_t j = 0; j < g.names.size(); ++j) {
            auto &name = g.names[j];
            Address v;
            if (name.starts_with('#'))
                v = IMAGE_ORDINAL_FLAG | static_cast<Address>(std::stoul(name.substr(1)));
            else {
                if (import.size() % 2)
                    import.push_back(0);
                auto off = import.size();
                import.insert(import.end(), 2, 0);
                appendString(name);
                v = rva32(start + off);
            }
            rebuilt[g.first + j] = v;
            lookup.push_back(v);
        }
        lookup.push_back(0);
        while (import.size() % sizeof(Address))
            import.push_back(0);
        d.OriginalFirstThunk = rva32(start + import.size());
        auto ptr = reinterpret_cast<const std::uint8_t *>(lookup.data());
        import.insert(import.end(), ptr, ptr + lookup.size() * sizeof(Address));
        store(import, i * sizeof(d), d);
    }
    sect.header.Misc.VirtualSize = rva32(import.size());
    sect.header.SizeOfRawData = pe.fileAlign(rva32(import.size()));
    pe.nt.OptionalHeader.SizeOfImage = pe.sectionAlign(rva32(std::uint64_t(start) + import.size()));
    image.resize(std::size_t(sect.header.PointerToRawData) + sect.header.SizeOfRawData);
    std::fill(image.begin() + sect.header.PointerToRawData, image.end(), 0);
    std::copy(import.begin(), import.end(), image.begin() + sect.header.PointerToRawData);
    auto iatOffset = pe.fileOffset(iatRva, rebuilt.size() * sizeof(Address));
    bounds(image.size(), iatOffset, rebuilt.size() * sizeof(Address));
    std::memcpy(image.data() + iatOffset, rebuilt.data(), rebuilt.size() * sizeof(Address));
    auto &oh = pe.nt.OptionalHeader;
    oh.AddressOfEntryPoint = rva32(oep_ - base_);
    oh.ImageBase = base_;
    oh.CheckSum = 0;
    oh.DllCharacteristics &=
        ~(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY);
    oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] = {};
    oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT] = {};
    oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = {
        start, rva32((groups.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR))};
    oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT] = {iatRva, rva32(rebuilt.size() * sizeof(Address))};
    if (dll) {
        pe.nt.FileHeader.Characteristics |= IMAGE_FILE_DLL;
        pe.switchManifest(image, 1, 2);
    }
    pe.save(image);
    writeFileAtomic(output, image);
}
void Dumper::dumpDotNet(HANDLE p, Address base, const Path &path) {
    auto head = readPEHeader(p, base);
    PEImage pe(head);
    auto &last = pe.sections.back().header;
    auto size = pe.fileAlign(rva32(std::uint64_t(last.VirtualAddress) + last.Misc.VirtualSize));
    auto data = imageMemory(p, base, size);
    pe.sanitize();
    pe.nt.OptionalHeader.SizeOfImage = pe.sectionAlign(size);
    pe.sections.front().rename(".text");
    pe.save(data);
    writeFileAtomic(path, data);
}
} // namespace mm
