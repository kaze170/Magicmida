// SPDX-License-Identifier: GPL-3.0-only
// Native port of the x86 Themida 1.x / 2.x / 3.x state machine.
#include "Themida.hpp"
namespace mm {
#ifndef _WIN64
void Themida::onStart() {
    if (executable_.filename().wstring().size() >= 50)
        warning(L"Long filenames crash some Themida versions; use fewer than 50 characters.");
    initPE();
    auto &oh = filePE_->nt.OptionalHeader;
    auto &sections = filePE_->sections;
    compressed_ = sections.front().header.Misc.VirtualSize != sections.front().header.SizeOfRawData;
    if (sections.size() >= 2) {
        auto &last = sections.back().header;
        v2Sections_ = last.Misc.VirtualSize == 0x1000 && last.SizeOfRawData == 0x1000 &&
                      sections[sections.size() - 2].header.Misc.VirtualSize == 0x1000;
    }
    closeAPI_ = api(L"kernel32.dll", "CloseHandle");
    allocAPI_ = api(L"ntdll.dll", "ZwAllocateVirtualMemory");
    heapAPI_ = api(L"ntdll.dll", "RtlAllocateHeap");
    protectAPI_ = api(L"kernel32.dll", "VirtualProtect");
    sleepAPI_ = api(L"kernel32.dll", "Sleep");
    strlenAPI_ = api(L"kernel32.dll", "lstrlenA");
    setBreakpoint(closeAPI_);
    if (std::filesystem::exists(executablePath().parent_path() / L"InjectorCLIx86.exe"))
        injectScylla(false);
    else {
        setInfoAPI_ = api(L"ntdll.dll", "ZwSetInformationThread");
        setBreakpoint(setInfoAPI_);
        BOOL wow{};
        check(IsWow64Process(process_.get(), &wow), "IsWow64Process");
        wow64_ = wow != FALSE;
        if (wow64_) {
            queryInfoAPI_ = api(L"ntdll.dll", "ZwQueryInformationProcess");
            setBreakpoint(queryInfoAPI_);
        } else {
            fastCall_ = api(L"ntdll.dll", "KiFastSystemCall");
            setSoftBP(fastCall_);
            queryInfoService_ = read<DWORD>(api(L"ntdll.dll", "ZwQueryInformationProcess") + 1);
        }
    }
    auto dir = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (dir.Size >= sizeof(IMAGE_TLS_DIRECTORY32)) {
        auto tls = read<IMAGE_TLS_DIRECTORY32>(imageBase_ + dir.VirtualAddress);
        if (tls.AddressOfCallBacks > tls.AddressOfIndex && tls.AddressOfCallBacks - tls.AddressOfIndex <= 16)
            tlsTotal_ = (tls.AddressOfCallBacks - tls.AddressOfIndex) / 4;
    }
}
void Themida::onHardware(HANDLE t, Address a, CONTEXT &c) {
    if (c.Eip == closeAPI_) {
        auto ret = read<Address>(c.Esp);
        if (ret >= imageBase_ && ret < imageEnd_) {
            resetBreakpoint(closeAPI_);
            if (compressed_)
                setBreakpoint(imageBase_ + 0x1000, BreakType::Access);
            else
                setBreakpoint(allocAPI_);
        }
    } else if (c.Eip == allocAPI_) {
        auto frame = read<Address>(c.Ebp);
        auto delta = static_cast<std::int64_t>(frame) - c.Ebp;
        auto ret = read<Address>((delta > -0x40 && delta < 0x40) ? frame + 4 : c.Ebp + 4);
        info(L"Allocate virtual memory called from " + hex(ret));
        if (ret & 0x80000000)
            throw std::runtime_error("Unexpected kernel address in allocation stack");
        if (ret > imageBase_ && ret < imageEnd_ && ++allocCount_ == (compressed_ ? 4u : 5u)) {
            resetBreakpoint(allocAPI_);
            if (v3_)
                installGuard(PAGE_NOACCESS);
            else
                iatFix(ret);
        }
    } else if (c.Eip == cmpBase_) {
        resetBreakpoint(cmpBase_);
        iatFix3(c.Eip);
    } else if (c.Eip == magicJump_) {
        resetBreakpoint(magicJump_);
        iatFix4();
    } else if (c.Eip == magic_[0] && magic_[0]) {
        resetBreakpoint(magic_[0]);
        iatFix5(c.Eax);
    } else if (c.Eip == magicV1_) {
        resetBreakpoint(magicV1_);
        iatFixV1(magicV1_);
    } else if (c.Eip == heapAPI_) {
        warning(L"Special IAT patch did not trigger; falling back to the code guard.");
        resetBreakpoint(heapAPI_);
        clearSoftBPs();
        installGuard(PAGE_NOACCESS);
    } else if (c.Eip == protectAPI_)
        installGuard(PAGE_NOACCESS);
    else if (c.Eip == setInfoAPI_) {
        auto ret = read<Address>(c.Esp);
        auto cls = read<DWORD>(c.Esp + 8);
        if (ret >= imageBase_ && ret < imageEnd_ && cls == 17) {
            good(L"Ignoring ThreadHideFromDebugger.");
            c.Esp += 20;
            c.Eip = ret;
            c.Eax = 0;
            c.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
            setContext(t, c);
        }
    } else if (wow64_ && c.Eip == queryInfoAPI_) {
        auto cls = read<DWORD>(c.Esp + 8);
        if (cls == 7 || cls == 30) {
            auto ret = read<Address>(c.Esp);
            write<DWORD>(read<Address>(c.Esp + 12), 0);
            c.Esp += 24;
            c.Eip = ret;
            c.Eax = cls == 7 ? 0 : 0xc0000353;
            c.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
            setContext(t, c);
            good(L"Masked process debug information.");
        }
    } else if (a == imageBase_ + 0x1000) {
        ++baseAccessCount_;
        if (!baseAccessed_) {
            resetBreakpoint(a);
            setBreakpoint(a, BreakType::Write);
            baseAccessed_ = true;
        } else {
            auto expected = imageBase_ + 0x1000 + filePE_->sections.front().header.Misc.VirtualSize - 4;
            bool found = read<WORD>(c.Eip) == 0xa4f3 || c.Eax == expected || c.Ebx == expected ||
                         c.Ecx == expected || c.Edx == expected || c.Esi == expected || c.Edi == expected;
            if (found) {
                resetBreakpoint(a);
                setBreakpoint(allocAPI_);
            } else if (baseAccessCount_ == 3 && !v2Sections_) {
                v3_ = true;
                info(L"Assuming Themida v3.");
                selectTM(c.Eip);
                resetBreakpoint(a);
                setBreakpoint(allocAPI_);
            }
        }
    }
}
DWORD Themida::onStep(Address a) {
    if (guardStepping_) {
        protect(guardStart_, guardEnd_ - guardStart_, guardProtection_);
        guardStepping_ = false;
        return DBG_CONTINUE;
    }
    return DebuggerCore::onStep(a);
}
void Themida::iatFix(Address caller) {
    selectTM(caller);
    cmpBase_ = findTM("74??8B8D????????8B093B8D????????7410");
    if (cmpBase_) {
        setBreakpoint(cmpBase_);
        return;
    }
    auto p = findTM("3D000001000F83");
    if (!p)
        throw std::runtime_error("Themida 1.x cmp eax, 10000 not found");
    magicV1_ = findTM("3B8D????????0F84????0000", p);
    if (!magicV1_)
        throw std::runtime_error("Themida 1.x base compare not found");
    setBreakpoint(magicV1_);
}
void Themida::iatFix3(Address a) {
    magicJump_ = findTM("4B0F84????0000", a);
    if (!magicJump_)
        throw std::runtime_error("Magic jumps not found");
    setBreakpoint(magicJump_);
}
bool Themida::newIATBreakpoint(Address &a) {
    for (;;) {
        a = findTM("39??9C", a);
        if (!a)
            return false;
        if (a > tm_.address && read<BYTE>(a - 1) == 0x66) {
            ++a;
            continue;
        }
        DISASM dis{};
        int n = disassemble(dis, std::span(tmBytes_).subspan(a - tm_.address), a);
        if (n != 2 || a > magic_[0])
            return false;
        a += 3;
        return true;
    }
}
void Themida::iatFix4() {
    if (!findTM("83F8500F82"))
        throw std::runtime_error("cmp eax, 50 not found");
    auto r = findTM("3985????????0F84");
    if (!r)
        throw std::runtime_error("IAT compare not found");
    iatJumper_ = r + 6;
    auto subtract = [&](Address start) {
        auto p = findTM("2BD90F84", start);
        if (!p)
            p = findTM("29CB0F84", start);
        if (!p)
            throw std::runtime_error("IAT subtraction pattern not found");
        return p;
    };
    magic_[1] = subtract(r);
    magic_[2] = subtract(magic_[1] + 1);
    magic_[3] = subtract(magic_[2] + 1);
    auto target = magic_[1] + 8 + load<std::int32_t>(tmBytes_, magic_[1] + 4 - tm_.address);
    if (magic_[2] + 8 + load<std::int32_t>(tmBytes_, magic_[2] + 4 - tm_.address) != target)
        throw std::runtime_error("IAT jump targets disagree");
    Address p = magic_[1];
    bool found = false;
    while (p >= tm_.address) {
        if (load<WORD>(tmBytes_, p - tm_.address) == 0x840f &&
            p + 6 + load<std::int32_t>(tmBytes_, p + 2 - tm_.address) == target) {
            found = true;
            break;
        }
        if (p == tm_.address)
            break;
        --p;
    }
    if (!found)
        throw std::runtime_error("First magic jump not found");
    magic_[0] = p;
    auto b1 = read<BYTE>(p - 1), b2 = read<BYTE>(magic_[1]), b3 = read<BYTE>(magic_[2]),
         b4 = read<BYTE>(magic_[3]);
    newVersion_ = ((b1 == 0x4b && b2 == 0x2b && b3 == 0x2b && b4 == 0x2b) || b2 == 0x29);
    if (findTM("68????????E9??????FF68????????E9??????FF68????????E9??????FF"))
        newVersion_ = false;
    if (findTM("68????????68????????E9??????FF68????????68????????E9??????FF"))
        newVersion_ = true;
    r = findTM("3BC89CE9");
    if (r) {
        do {
            r += 3;
            setSoftBP(r);
            r = findTM("3BC89CE9", r);
        } while (r);
    } else {
        r = tm_.address;
        for (;;) {
            bool valid = newIATBreakpoint(r);
            if (!r)
                break;
            if (valid)
                setSoftBP(r);
            r += 2;
        }
    }
    installGuard(PAGE_READONLY);
    setBreakpoint(magic_[0]);
}
void Themida::iatFix5(Address eax) {
    info(L"First API: " + hex(eax));
    write<WORD>(iatJumper_, 0xe990);
    std::array<BYTE, 6> nops{0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
    write(magic_[0], std::span<const BYTE>(nops));
    for (unsigned i = 1; i < 4; ++i)
        write(magic_[i] + 2, std::span<const BYTE>(nops));
    good(L"IAT jumps patched.");
}
void Themida::iatFixV1(Address first) {
    auto second = findTM("3B8D????????0F84????0000", first + 12);
    auto third = second ? findTM("3B8D????????0F84????0000", second + 12) : 0;
    auto jump = findTM("3985????????0F84");
    if (!second || !third || !jump)
        throw std::runtime_error("Incomplete Themida 1.x IAT patterns");
    write<WORD>(jump + 6, 0xe990);
    std::array<BYTE, 6> nops{0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
    for (auto p : {first, second, third})
        write(p + 6, std::span<const BYTE>(nops));
    guardStart_ = imageBase_ + filePE_->sections.front().header.VirtualAddress;
    guardEnd_ = std::min(imageBase_ + 0x100000, imageEnd_);
    guardProtection_ = PAGE_NOACCESS;
    protect(guardStart_, guardEnd_ - guardStart_, guardProtection_);
}
bool Themida::installEFL(Address a, const CONTEXT &c, EFLPatch &patch) {
    std::array<Address, 3> bases{};
    // These comparisons refer to target module bases, not local module handles.
    const wchar_t *dlls[] = {L"kernel32.dll", L"user32.dll", L"advapi32.dll"};
    for (unsigned i = 0; i < 3; ++i)
        bases[i] = moduleBase(dlls[i]);
    auto code = std::span(tmBytes_).subspan(a - tm_.address);
    DISASM dis{};
    auto n = disassemble(dis, code, a);
    if (n == 5 && code[0] == 0xe9)
        throw std::runtime_error("Unexpected old-style EFL jump");
    WORD compare{};
    for (auto m : bases) {
        if (c.Eax == m)
            compare = 0xf881;
        else if (c.Ecx == m)
            compare = 0xf981;
        else if (c.Edx == m)
            compare = 0xfa81;
        else if (c.Ebx == m)
            compare = 0xfb81;
        else if (c.Ebp == m)
            compare = 0xfd81;
        else if (c.Esi == m)
            compare = 0xfe81;
        else if (c.Edi == m)
            compare = 0xff81;
        if (compare)
            break;
    }
    if (!compare)
        return false;
    auto dest = reinterpret_cast<Address>(
        VirtualAllocEx(process_.get(), nullptr, 128, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!dest)
        winError("VirtualAllocEx(EFL)");
    Bytes hook(128);
    store(hook, 0, compare);
    store(hook, 2, bases[0]);
    store<WORD>(hook, 6, 0x2874);
    store(hook, 8, compare);
    store(hook, 10, bases[1]);
    store<WORD>(hook, 14, 0x2074);
    store(hook, 16, compare);
    store(hook, 18, bases[2]);
    store<WORD>(hook, 22, 0x1874);
    store<WORD>(hook, 24, 0x1deb);
    store<std::uint64_t>(hook, 0x30, 0x90000002462404c7ULL);
    std::size_t total = 0;
    while (total < 5)
        total += disassemble(dis, code.subspan(total), a + total);
    bounds(hook.size(), 0x37, total + 5);
    std::copy_n(code.begin(), total, hook.begin() + 0x37);
    patch.original.assign(code.begin(), code.begin() + total);
    patch.address = a;
    hook[0x37 + total] = 0xe9;
    store<DWORD>(hook, 0x38 + total, static_cast<DWORD>(a + total - (dest + 0x37 + total) - 5));
    write(dest, std::span<const BYTE>(hook));
    Bytes jump{0xe9, 0, 0, 0, 0};
    store<DWORD>(jump, 1, dest - a - 5);
    write(a, std::span<const BYTE>(jump));
    auto before = read(a - 9, 6);
    auto rel = load<DWORD>(before, 2);
    if (before[0] == 0x0f && (before[1] == 0x84 || before[1] == 0x85) && rel >= 4 && rel <= 7)
        write<DWORD>(a - 7, (dest + 0x37 + rel - 3) - (a - 9) - 6);
    good(L"EFL patch at " + hex(a));
    return true;
}
SoftAction Themida::onSoftware(HANDLE t, Address a) {
    auto c = context(t, CONTEXT_FULL);
    if (!wow64_ && a == fastCall_ && a) {
        auto cls = read<DWORD>(c.Esp + 12);
        if (c.Eax == queryInfoService_ && (cls == 7 || cls == 30)) {
            auto ret = read<Address>(c.Esp);
            write<DWORD>(read<Address>(c.Esp + 16), 0);
            c.Esp += 4;
            c.Eip = ret;
            c.Eax = cls == 7 ? 0 : 0xc0000353;
        } else {
            c.Edx = c.Esp;
            c.Eip = fastCall_ + 2;
        }
        setContext(t, c);
        return SoftAction::KeepNoStep;
    }
    if (dotNet(a))
        return SoftAction::Clear;
    if (!newVersion_) {
        auto k = moduleBase(L"kernel32.dll"), u = moduleBase(L"user32.dll"),
             adv = moduleBase(L"advapi32.dll");
        if (c.Eax != k && c.Eax != u && c.Eax != adv) {
            if (!hasBreakpoint(heapAPI_))
                setBreakpoint(heapAPI_);
            return SoftAction::Keep;
        }
        clearSoftBPs();
        auto target = a + 5 + load<std::int32_t>(tmBytes_, a + 1 - tm_.address);
        auto dest = reinterpret_cast<Address>(
            VirtualAllocEx(process_.get(), nullptr, 128, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
        if (!dest)
            winError("VirtualAllocEx(IAT)");
        Bytes hook(41);
        store<WORD>(hook, 0, 0xf881);
        store(hook, 2, k);
        store<DWORD>(hook, 6, 0xf8811574);
        store(hook, 10, adv);
        store<DWORD>(hook, 14, 0xf8810d74);
        store(hook, 18, u);
        store<WORD>(hook, 22, 0x0574);
        hook[24] = 0xe9;
        store<DWORD>(hook, 25, target - dest - 29);
        store<std::uint64_t>(hook, 29, 0xe9000002872404c7ULL);
        store<DWORD>(hook, 37, target - dest - 41);
        write(dest, std::span<const BYTE>(hook));
        Bytes jump{0xe9, 0, 0, 0, 0};
        store<DWORD>(jump, 1, dest - a - 5);
        write(a, std::span<const BYTE>(jump));
        good(L"Special IAT patch installed.");
    } else {
        for (auto &patch : efl_)
            if (!patch.address) {
                if (installEFL(a, c, patch))
                    return SoftAction::Clear;
                break;
            }
        clearSoftBPs();
        info(L"EFL patch search complete.");
    }
    installGuard(ancient_ ? PAGE_NOACCESS : PAGE_READONLY);
    return SoftAction::Clear;
}
bool Themida::exceptionHandler(Address a) {
    auto data = read(a, 64);
    for (std::size_t i = 0; i + 4 <= data.size(); ++i)
        if (load<DWORD>(data, i) == 0x00b8838b)
            return true;
    return false;
}
void Themida::installGuard(DWORD p) {
    guardStart_ = imageBase_ + filePE_->sections.front().header.VirtualAddress;
    guardEnd_ = imageBase_ + baseOfData_;
    guardProtection_ = p;
    protect(guardStart_, guardEnd_ - guardStart_, p);
    if (!v3_ && !hasBreakpoint(protectAPI_))
        setBreakpoint(protectAPI_);
}
DWORD Themida::onAccess(HANDLE t, const EXCEPTION_RECORD &e) {
    if (e.NumberParameters < 2 || !guardStart_ || e.ExceptionInformation[1] < guardStart_ ||
        e.ExceptionInformation[1] >= guardEnd_)
        return DebuggerCore::onAccess(t, e);
    protect(guardStart_, guardEnd_ - guardStart_, PAGE_EXECUTE_READWRITE);
    auto a = reinterpret_cast<Address>(e.ExceptionAddress);
    if (a >= guardEnd_ || a < guardStart_) {
        if (a >= imageBase_ && a < imageEnd_)
            guardAddresses_.push_back(e.ExceptionInformation[1]);
        guardStepping_ = true;
        auto c = context(t, CONTEXT_CONTROL);
        c.EFlags |= 0x100;
        setContext(t, c);
        return DBG_CONTINUE;
    }
    auto c = context(t, CONTEXT_CONTROL);
    auto ret = read<Address>(c.Esp);
    if (tlsCount_ < tlsTotal_) {
        auto args = read(c.Esp + 4, 12);
        if (tm_.contains(ret) && !exceptionHandler(ret) && !(load<DWORD>(args, 0) & 0xfff) &&
            load<DWORD>(args, 4) <= 3) {
            ++tlsCount_;
            good(L"TLS " + std::to_wstring(tlsCount_) + L": " + hex(a));
            c.Eip = ret;
            c.Esp += 16;
            setContext(t, c);
            installGuard(guardProtection_);
            return DBG_CONTINUE;
        }
    }
    Address oep = a;
    restoreMSVC6(t, oep);
    if (isDll_ && linker_ == 9)
        restoreMSVC9DLL(oep);
    checkVirtualOEP(oep);
    if (!ancient_ && tm_.contains(ret) && !exceptionHandler(ret))
        oep = correctOEP(oep);
    good(L"OEP: " + hex(oep));
    finish(oep);
    return DBG_CONTINUE;
}
void Themida::restoreMSVC6(HANDLE t, Address &oep) {
    if (read<WORD>(oep) != 0xd48a)
        return;
    Bytes code{0x55, 0x8b, 0xec, 0x6a, 0xff, 0x68, 0,    0,    0,    0, 0x68, 0, 0,    0,    0,    0x64,
               0xa1, 0,    0,    0,    0,    0x50, 0x64, 0x89, 0x25, 0, 0,    0, 0,    0x83, 0xec, 0x58,
               0x53, 0x56, 0x57, 0x89, 0x65, 0xe8, 0xff, 0x15, 0,    0, 0,    0, 0x33, 0xd2};
    auto gap = read(oep - code.size() - 3, 3);
    if (gap[0] != 0xc2 && gap[2] != 0xc3)
        throw std::runtime_error("Stolen MSVC6 OEP gap mismatch");
    auto values = read(imageBase_ + baseOfData_, 512 * sizeof(Address));
    auto getVersion = api(L"kernel32.dll", "GetVersion");
    Address slot{};
    for (std::size_t i = 0; i < 512; ++i)
        if (load<Address>(values, i * 4) == getVersion) {
            slot = imageBase_ + baseOfData_ + i * 4;
            break;
        }
    if (!slot)
        throw std::runtime_error("GetVersion not found for MSVC6 OEP");
    auto c = context(t, CONTEXT_CONTROL | CONTEXT_INTEGER);
    if (c.Esp != c.Ebp - 0x74)
        throw std::runtime_error("MSVC6 OEP stack mismatch");
    store<DWORD>(code, 40, slot);
    store<DWORD>(code, 6, read<DWORD>(c.Ebp - 8));
    store<DWORD>(code, 11, read<DWORD>(c.Ebp - 12));
    auto corrected = oep - code.size();
    write(corrected, std::span<const BYTE>(code));
    oep = corrected;
}
void Themida::restoreMSVC9DLL(Address &oep) {
    const std::array<BYTE, 11> code{0x8b, 0xff, 0x55, 0x8b, 0xec, 0x83, 0x7d, 0x0c, 1, 0x75, 5};
    if (read<BYTE>(oep) == 0xe8 && read<BYTE>(oep - code.size()) == 0xe9) {
        oep -= code.size();
        write(oep, std::span<const BYTE>(code));
    }
}
void Themida::fixCallSites(Address iat) {
    if (guardAddresses_.empty())
        return;
    std::sort(guardAddresses_.begin(), guardAddresses_.end());
    std::vector<Address> sites;
    for (auto a : guardAddresses_)
        if (sites.empty() || a - sites.back() >= 6)
            sites.push_back(a);
    if (iat < imageBase_ || iat >= imageEnd_)
        throw std::runtime_error("IAT outside image");
    auto count = std::min(maxImports, (imageEnd_ - iat) / sizeof(Address));
    auto values = Dumper::imageMemory(process_.get(), iat, count * sizeof(Address));
    std::map<Address, Address> table;
    for (std::size_t i = 0; i < count; ++i) {
        auto value = load<Address>(values, i * 4);
        if (value)
            table[value] = iat + i * 4;
    }
    for (auto a : sites) {
        auto b = read(a, 6);
        Address target{};
        bool jump = false;
        if (b[0] == 0xe8 || b[0] == 0xe9) {
            target = a + 5 + load<std::int32_t>(b, 1);
            jump = b[0] == 0xe9;
        } else if (b[1] == 0xe8 || b[1] == 0xe9) {
            target = a + 6 + load<std::int32_t>(b, 2);
            jump = b[1] == 0xe9;
        } else
            continue;
        auto found = table.find(target);
        if (found == table.end()) {
            warning(L"Call site target not in IAT: " + hex(a));
            continue;
        }
        b[0] = 0xff;
        b[1] = jump ? 0x25 : 0x15;
        store(b, 2, found->second);
        write(a, std::span<const BYTE>(b));
    }
}
void Themida::finish(Address oep) {
    for (auto &patch : efl_)
        if (patch.address && !patch.original.empty())
            write(patch.address, std::span<const BYTE>(patch.original));
    Dumper d(process_.get(), pid_, executable_, imageBase_, oep, log_);
    auto iat = determineIAT(oep, d);
    if (v3_)
        traceImports(iat, d);
    fixCallSites(iat);
    if (vmOEP_ && v3_)
        mitigateHeaderAntiDump(process_.get(), imageBase_, oep, iat, protectAPI_, log_);
    auto output = unpackedPath(executable_);
    d.dump(output, iat, isDll_);
    // End the debuggee before optional disk-only processing, as in the Pascal build.
    check(TerminateProcess(process_.get(), 0), "TerminateProcess");
    if (createData_)
        Patcher(output, log_).createData();
    finished_ = true;
    good(L"Saved " + output.wstring());
}
#endif
} // namespace mm
