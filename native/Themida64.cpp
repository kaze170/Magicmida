// SPDX-License-Identifier: GPL-3.0-only
#include "Themida64.hpp"
namespace mm {
#ifdef _WIN64
void Themida64::onStart() {
    v3_ = true;
    injectScylla(true);
    initPE();
    allocAPI_ = api(L"kernel32.dll", "VirtualAlloc");
    sleepAPI_ = api(L"kernel32.dll", "Sleep");
    strlenAPI_ = api(L"kernel32.dll", "lstrlenA");
    if (filePE_->sections.front().name() == ".text")
        installGuard();
    else {
        closeAPI_ = api(L"kernel32.dll", "CloseHandle");
        setBreakpoint(closeAPI_);
    }
    auto d = filePE_->nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (d.Size >= sizeof(IMAGE_TLS_DIRECTORY64)) {
        auto t = read<IMAGE_TLS_DIRECTORY64>(imageBase_ + d.VirtualAddress);
        auto here = imageBase_ + d.VirtualAddress;
        if (here > t.AddressOfCallBacks && here - t.AddressOfCallBacks <= 8 * 5)
            tlsTotal_ = static_cast<unsigned>((here - t.AddressOfCallBacks) / 8 - 1);
    }
}
void Themida64::installGuard() {
    guardStart_ = imageBase_ + filePE_->sections.front().header.VirtualAddress;
    guardEnd_ = imageBase_ + baseOfData_;
    protect(guardStart_, guardEnd_ - guardStart_, PAGE_NOACCESS);
}
void Themida64::onHardware(HANDLE, Address a, CONTEXT &c) {
    if (c.Rip == closeAPI_) {
        auto ret = read<Address>(c.Rsp);
        if (ret >= imageBase_ && ret < imageEnd_) {
            resetBreakpoint(closeAPI_);
            setBreakpoint(imageBase_ + 0x1000, BreakType::Write);
        }
    } else if (c.Rip == allocAPI_) {
        auto ret = read<Address>(c.Rsp);
        if (ret >= imageBase_ && ret < imageEnd_) {
            resetBreakpoint(allocAPI_);
            installGuard();
        }
    } else if (a == imageBase_ + 0x1000) {
        if (!tm_.address)
            selectTM(c.Rip);
        resetBreakpoint(a);
        setBreakpoint(allocAPI_);
    }
}
DWORD Themida64::onStep(Address a) {
    if (guardStepping_) {
        protect(guardStart_, guardEnd_ - guardStart_, PAGE_NOACCESS);
        guardStepping_ = false;
        return DBG_CONTINUE;
    }
    return DebuggerCore::onStep(a);
}
SoftAction Themida64::onSoftware(HANDLE, Address a) {
    if (dotNet(a))
        return SoftAction::Clear;
    throw std::runtime_error("Unexpected software breakpoint");
}
DWORD Themida64::onAccess(HANDLE t, const EXCEPTION_RECORD &e) {
    if (e.NumberParameters < 2 || !guardStart_ || e.ExceptionInformation[1] < guardStart_ ||
        e.ExceptionInformation[1] >= guardEnd_)
        return DebuggerCore::onAccess(t, e);
    protect(guardStart_, guardEnd_ - guardStart_, PAGE_EXECUTE_READWRITE);
    auto a = reinterpret_cast<Address>(e.ExceptionAddress);
    if (tmGuard_) {
        tmGuard_ = false;
        installGuard();
    } else if (a < imageBase_ || a >= imageEnd_)
        guardStepping_ = true;
    else if (a >= guardEnd_) {
        if (!tm_.address)
            selectTM(a);
        guardAddresses_.push_back(e.ExceptionInformation[1]);
        guardStepping_ = true;
    } else if (e.ExceptionInformation[0] == 8 && tlsCounter_ < tlsTotal_) {
        ++tlsCounter_;
        good(L"TLS " + std::to_wstring(tlsCounter_) + L": " + hex(a));
        if (!tm_.address)
            throw std::runtime_error("No Themida section for TLS guard");
        guardStart_ = tm_.address;
        guardEnd_ = imageEnd_;
        tmGuard_ = true;
        protect(guardStart_, guardEnd_ - guardStart_, PAGE_READWRITE);
    } else if (traceMSVC_) {
        writeMSVCOEP(a);
        finish(realOEP_);
    } else {
        Address oep = a;
        checkVirtualOEP(oep);
        auto c = context(t, CONTEXT_CONTROL);
        auto ret = read<Address>(c.Rsp);
        if (tm_.contains(ret)) {
            auto corrected = correctOEP(oep);
            if (corrected == oep &&
                (linker_ == 9 || linker_ == 10 || linker_ == 11 || linker_ == 12 || linker_ == 14) &&
                guardAddresses_.size() >= 2 &&
                guardAddresses_.back() == guardAddresses_[guardAddresses_.size() - 2] + 1) {
                cookie_ = oep;
                realOEP_ = guardAddresses_[guardAddresses_.size() - 2];
                traceMSVC_ = true;
                c.Rip = ret;
                c.Rsp += 8;
                setContext(t, c);
                installGuard();
                return DBG_CONTINUE;
            }
            oep = corrected;
        }
        finish(oep);
    }
    if (guardStepping_) {
        auto c = context(t, CONTEXT_CONTROL);
        c.EFlags |= 0x100;
        setContext(t, c);
    }
    return DBG_CONTINUE;
}
void Themida64::writeMSVCOEP(Address crt) {
    Bytes b{0x48, 0x83, 0xec, 0x28, 0xe8, 0, 0, 0, 0, 0x48, 0x83, 0xc4, 0x28, 0xe9, 0, 0, 0, 0};
    auto relative = [](Address to, Address next) {
        auto delta = static_cast<std::int64_t>(to) - static_cast<std::int64_t>(next);
        if (delta < INT32_MIN || delta > INT32_MAX)
            throw std::runtime_error("OEP jump outside rel32 range");
        return static_cast<std::int32_t>(delta);
    };
    store(b, 5, relative(cookie_, realOEP_ + 9));
    store(b, 14, relative(crt, realOEP_ + 18));
    write(realOEP_, std::span<const std::uint8_t>(b));
    good(L"Restored virtualized MSVC OEP.");
}
void Themida64::finish(Address oep) {
    Dumper d(process_.get(), pid_, executable_, imageBase_, oep, log_);
    auto iat = determineIAT(oep, d);
    traceImports(iat, d);
    auto output = unpackedPath(executable_);
    d.dump(output, iat, isDll_);
    good(L"Saved " + output.wstring());
    terminateSuccess();
}
#endif
} // namespace mm
