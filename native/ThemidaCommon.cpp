// SPDX-License-Identifier: GPL-3.0-only
#include "ThemidaCommon.hpp"
namespace mm {
int disassemble(DISASM &d, std::span<const std::uint8_t> data, Address va) {
    d = {};
    d.EIP = reinterpret_cast<Address>(data.data());
    d.VirtualAddr = va;
    d.Archi = sizeof(Address) * 8;
    d.SecurityBlock = static_cast<unsigned>(std::min<std::size_t>(data.size(), 15));
    if (data.empty())
        throw std::runtime_error("Disassembly outside code range");
    int n = Disasm(&d);
    if (n <= 0 || static_cast<std::size_t>(n) > data.size())
        throw std::runtime_error("Invalid instruction at code boundary");
    return n;
}
void ThemidaCommon::initPE() {
    auto &p = *filePE_;
    auto &oh = p.nt.OptionalHeader;
    auto &first = p.sections.front().header;
    if (oh.AddressOfEntryPoint >= first.VirtualAddress &&
        oh.AddressOfEntryPoint - first.VirtualAddress < first.Misc.VirtualSize)
        throw std::runtime_error("Selected binary does not appear packed (entrypoint in .text)");
    imageEnd_ = imageBase_ + oh.SizeOfImage;
    linker_ = oh.MajorLinkerVersion;
#ifdef _WIN64
    baseOfData_ = rva32(std::uint64_t(first.VirtualAddress) + oh.SizeOfCode);
#else
    baseOfData_ = oh.BaseOfData;
#endif
    if (baseOfData_ <= first.VirtualAddress || baseOfData_ >= oh.SizeOfImage)
        throw std::runtime_error("Invalid code/data boundary");
    if (p.sections.size() > 2) {
        auto a = imageBase_ + p.ntOffset + sizeof(p.nt) + 2 * sizeof(IMAGE_SECTION_HEADER) + 1;
#ifdef _WIN64
        if (p.sections[2].header.Name[1] == 'i')
            write<BYTE>(a, 'p');
#else
        write<BYTE>(a, 'p');
#endif
    }
    info(L"Image boundary: " + hex(imageEnd_) + L"; linker " + std::to_wstring(linker_) + L"." +
         std::to_wstring(oh.MinorLinkerVersion));
}
void ThemidaCommon::injectScylla(bool required) {
    auto folder = executablePath().parent_path();
#ifdef _WIN64
    auto injector = folder / L"InjectorCLIx64.exe", hook = folder / L"HookLibraryx64.dll";
#else
    auto injector = folder / L"InjectorCLIx86.exe", hook = folder / L"HookLibraryx86.dll";
#endif
    if (!std::filesystem::exists(injector)) {
        if (required)
            throw std::runtime_error("ScyllaHide injector is required for x64");
        return;
    }
    if (!std::filesystem::exists(hook))
        throw std::runtime_error("ScyllaHide HookLibrary DLL not found");
    if (!std::filesystem::exists(folder / L"scylla_hide.ini"))
        throw std::runtime_error("ScyllaHide profile not found");
#ifdef _WIN64
    auto file = readFile(injector);
    PEImage pe(file);
    if (pe.nt.FileHeader.TimeDateStamp < 0x6484fef9)
        throw std::runtime_error("ScyllaHide x64 injector is too old");
#endif
    std::wstring cmd = L"\"" + injector.wstring() + L"\" pid:" + std::to_wstring(pid_) + L" \"" +
                       hook.wstring() + L"\" nowait";
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    check(CreateProcessW(injector.c_str(), cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                         folder.c_str(), &si, &pi),
          "ScyllaHide injector");
    Handle p(pi.hProcess),
        t(pi.hThread); // Injection proceeds while the debuggee resumes, as in the Pascal build.
    good(L"ScyllaHide injector started.");
}
void ThemidaCommon::selectTM(Address a) {
    for (auto &s : filePE_->sections) {
        auto &h = s.header;
        Region r{imageBase_ + h.VirtualAddress, h.Misc.VirtualSize};
        if (r.contains(a)) {
            tm_ = r;
            tmBytes_ = read(r.address, r.size);
            ancient_ = s.name() == "Themida ";
            info(L"Themida section: " + hex(r.address));
            return;
        }
    }
    throw std::runtime_error("Unable to locate Themida section");
}
Address ThemidaCommon::findTM(std::string_view pattern, Address start) const {
    auto off = start ? start - tm_.address : 0;
    if (start && !tm_.contains(start))
        return 0;
    auto p = findPattern(std::span(tmBytes_).subspan(off), pattern);
    return p ? tm_.address + off + *p : 0;
}
void ThemidaCommon::checkVirtualOEP(Address a) {
    auto b = read(a, 5);
    auto dest = a + 5 + load<std::int32_t>(b, 1);
    if (b[0] == 0xe9 && tm_.contains(dest)) {
        vmOEP_ = true;
        warning(L"OEP is virtualized: " + hex(a));
    }
}
void ThemidaCommon::onDll(const std::wstring &name, Address base) {
    DebuggerCore::onDll(name, base);
    if (Path(name).filename() == L"mscoree.dll") {
        corExeMain_ = api(L"mscoree.dll", "_CorExeMain");
        setSoftBP(corExeMain_);
        info(L"Set .NET entrypoint breakpoint.");
    }
}
bool ThemidaCommon::dotNet(Address a) {
    if (a != corExeMain_ || !a)
        return false;
    Dumper::dumpDotNet(process_.get(), imageBase_, unpackedPath(executable_));
    good(L".NET process dumped.");
    terminateSuccess();
    return true;
}
Address ThemidaCommon::correctOEP(Address hit) {
    if (linker_ != 9 && linker_ != 10 && linker_ != 11 && linker_ != 12 && linker_ != 14) {
        warning(L"Cannot infer stolen OEP for this compiler.");
        return hit;
    }
    auto start = imageBase_ + filePE_->sections.front().header.VirtualAddress;
    auto code = read(start, baseOfData_ - filePE_->sections.front().header.VirtualAddress);
    for (std::size_t i = 0; i + 10 <= code.size(); ++i)
        if (code[i] == 0xe8 && code[i + 5] == 0xe9 &&
            start + i + 5 + load<std::int32_t>(code, i + 1) == hit) {
            good(L"Recovered OEP: " + hex(start + i));
            return start + i;
        }
    return hit;
}
Address ThemidaCommon::determineIAT(Address oep, Dumper &dumper) {
    auto text = imageBase_ + filePE_->sections.front().header.VirtualAddress;
    auto code = read(text, baseOfData_ - filePE_->sections.front().header.VirtualAddress);
    Address codeEnd = text + code.size();
    unsigned instructions = 0;
    std::set<Address> visited;
    std::function<Address(Address, bool)> search = [&](Address a, bool whole) -> Address {
        if (!visited.insert(a).second)
            return 0;
        while (a >= text && a < codeEnd && (whole || instructions < 200)) {
            if (cancel_)
                throw std::runtime_error("Cancelled");
            auto offset = a - text;
            DISASM d{};
            int n;
            try {
                n = disassemble(d, std::span(code).subspan(offset), a);
            } catch (const std::exception &) {
                if (!whole)
                    break;
                ++a;
                continue;
            }
            ++instructions;
            if (n == 6 && code[offset] == 0xff && (code[offset + 1] == 0x15 || code[offset + 1] == 0x25)) {
#ifdef _WIN64
                Address ptr = a + 6 + load<std::int32_t>(code, offset + 2);
#else
                Address ptr = load<DWORD>(code, offset + 2);
#endif
                Address value{};
                if (rpm(ptr, &value, sizeof(value)) && (dumper.isAPI(value) || tm_.contains(value)))
                    return ptr;
            }
            if (code[offset] == 0xe8 && !whole) {
                auto dest = static_cast<Address>(d.Instruction.AddrValue);
                if (dest >= text && dest < codeEnd) {
                    auto r = search(dest, false);
                    if (r)
                        return r;
                } else
                    return 0;
            }
            if (!whole && (code[offset] == 0xc2 || code[offset] == 0xc3))
                return 0;
            a += static_cast<unsigned>(n);
        }
        return 0;
    };
    Address ref{};
    if (code.size() >= 4 && load<DWORD>(code, 0) == 0x6f4720ff) {
        std::size_t off = 0;
        for (; off + 2 <= code.size(); ++off)
            if (load<WORD>(code, off) == 0xff20) {
                off += 2;
                break;
            }
        while (off < code.size()) {
            DISASM d{};
            int n;
            try {
                n = disassemble(d, std::span(code).subspan(off), text + off);
            } catch (const std::exception &) {
                ++off;
                continue;
            }
#ifdef _WIN64
            if (n == 7 && d.Instruction.Opcode == 0x8b && off + 11 <= code.size() &&
                load<DWORD>(code, off + 7) == 0x24048948) {
                auto ptr = text + off + 7 + static_cast<std::int64_t>(d.Operand2.Memory.Displacement);
                Address value{};
                if (rpm(ptr, &value, sizeof(value)) && dumper.isAPI(value)) {
                    ref = ptr;
                    break;
                }
            }
#else
            if (n == 6 && d.Instruction.Opcode == 0x8b && off + 10 <= code.size() &&
                (load<DWORD>(code, off + 6) & 0xffffff) == 0x240489) {
                auto ptr = static_cast<Address>(d.Operand2.Memory.Displacement);
                Address value{};
                if (rpm(ptr, &value, sizeof(value)) && dumper.isAPI(value)) {
                    ref = ptr;
                    break;
                }
            }
#endif
            off += static_cast<unsigned>(n);
        }
    } else
        ref = search(vmOEP_ ? text : oep, vmOEP_);
    if (!ref) {
        instructions = 0;
        visited.clear();
        ref = search(text, true);
    }
    if (!ref && !guardAddresses_.empty()) {
        auto site = guardAddresses_.front();
        auto b = read(site, 6);
        Address target{};
        if (b[0] == 0xe8 || b[0] == 0xe9)
            target = site + 5 + load<std::int32_t>(b, 1);
        else if (b[1] == 0xe8 || b[1] == 0xe9)
            target = site + 6 + load<std::int32_t>(b, 2);
        if (target) {
            auto index = filePE_->sectionAt(baseOfData_);
            if (!index)
                throw std::runtime_error("No data section");
            auto &s = filePE_->sections[*index].header;
            auto dataStart = imageBase_ + baseOfData_;
            auto dataEnd = imageBase_ + s.VirtualAddress + s.Misc.VirtualSize;
            for (auto r : {Region{dataStart, dataEnd - dataStart}, Region{text, code.size()}}) {
                auto bdata = read(r.address, r.size);
                for (std::size_t i = 0; i + sizeof(Address) <= bdata.size(); i += sizeof(Address))
                    if (load<Address>(bdata, i) == target) {
                        ref = r.address + i;
                        break;
                    }
                if (ref)
                    break;
            }
        }
    }
    if (!ref)
        throw std::runtime_error("Unable to obtain IAT reference");
    Address result{};
    unsigned zeros = 0;
    std::size_t count = 0;
    for (Address seeker = ref; seeker >= imageBase_ + sizeof(Address) && count < maxImports;
         seeker -= sizeof(Address), ++count) {
        Address value{};
        if (!rpm(seeker, &value, sizeof(value)))
            break;
        if (!value) {
            if (++zeros > 64)
                break;
        } else if (dumper.isAPI(value) || (v3_ && tm_.contains(value))) {
            result = seeker;
            zeros = 0;
        } else
            break;
    }
    if (!result || count == maxImports)
        throw std::runtime_error("Cannot determine bounded IAT start");
    good(L"IAT: " + hex(result));
    return result;
}
void ThemidaCommon::traceImports(Address iat, Dumper &dumper) {
    if (iat < imageBase_ || iat >= imageEnd_)
        throw std::runtime_error("IAT outside image");
    auto count = std::min(maxImports, (imageEnd_ - iat) / sizeof(Address));
    auto bytes = Dumper::imageMemory(process_.get(), iat, count * sizeof(Address));
    unsigned trash = 0;
    bool usedExit = false;
    for (std::size_t i = 0; i < count; ++i) {
        auto value = load<Address>(bytes, i * sizeof(Address));
        if (tm_.contains(value)) {
            trash = 0;
            auto c = context(thread());
            Address startSP = sp(c), resolved{};
            bool inVM = false;
            bool ok = trace(value, 500000, [&](unsigned count, CONTEXT &ctx) {
                if (count > 100 && count < 5000) {
                    DWORD ins{};
                    if (rpm(ip(ctx), &ins, 4) && ins ==
#ifdef _WIN64
                                                     0x0cb10ff0
#else
                    0x4cb10ff0
#endif
                    ) {
                        inVM = true;
                        return true;
                    }
                }
                if (sp(ctx) < startSP && (ip(ctx) == sleepAPI_ || ip(ctx) == strlenAPI_)) {
                    auto ret = read<Address>(sp(ctx));
                    // x64: pop return address; x86 stdcall: pop return + one argument.
                    sp(ctx) += 8;
                    ip(ctx) = ret;
                }
                if (!tm_.contains(ip(ctx)) && sp(ctx) >= startSP) {
                    resolved = ip(ctx);
                    return true;
                }
                return false;
            });
            if (!ok)
                throw std::runtime_error("Import trace instruction limit reached");
            if (inVM) {
                if (usedExit)
                    throw std::runtime_error("More than one unresolved VM import");
                resolved = api(L"kernel32.dll", "ExitProcess");
                usedExit = true;
            }
            if (!resolved || !dumper.isAPI(resolved))
                throw std::runtime_error("Import tracing did not resolve to an exported API");
            store(bytes, i * sizeof(Address), resolved);
            info(L"Trace " + hex(value) + L" -> " + hex(resolved));
        } else if (!value || !dumper.isAPI(value)) {
            if (++trash > 64)
                break;
        } else
            trash = 0;
    }
    write(iat, std::span<const std::uint8_t>(bytes));
}
} // namespace mm
