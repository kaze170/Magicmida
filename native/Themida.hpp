// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "ThemidaCommon.hpp"
#include "Patcher.hpp"
namespace mm {
#ifndef _WIN64
class Themida final : public ThemidaCommon {
    struct EFLPatch {
        Address address{};
        Bytes original;
    };
    std::array<EFLPatch, 3> efl_{};
    Address closeAPI_{}, allocAPI_{}, heapAPI_{}, fastCall_{}, setInfoAPI_{}, queryInfoAPI_{}, protectAPI_{};
    DWORD queryInfoService_{};
    Address cmpBase_{}, magicJump_{}, magicV1_{}, iatJumper_{};
    std::array<Address, 4> magic_{};
    unsigned baseAccessCount_{}, allocCount_{}, tlsCount_{}, tlsTotal_{};
    bool wow64_{}, compressed_{}, baseAccessed_{}, newVersion_{}, v2Sections_{}, guardStepping_{};
    Address guardStart_{}, guardEnd_{};
    DWORD guardProtection_{};
    void installGuard(DWORD protection);
    void iatFix(Address caller);
    void iatFix3(Address address);
    void iatFix4();
    void iatFix5(Address eax);
    void iatFixV1(Address compare);
    bool newIATBreakpoint(Address &address);
    bool installEFL(Address address, const CONTEXT &context, EFLPatch &patch);
    bool exceptionHandler(Address address);
    void restoreMSVC6(HANDLE thread, Address &oep);
    void restoreMSVC9DLL(Address &oep);
    void fixCallSites(Address iat);
    void finish(Address oep);
    void onStart() override;
    DWORD onAccess(HANDLE, const EXCEPTION_RECORD &) override;
    DWORD onStep(Address) override;
    void onHardware(HANDLE, Address, CONTEXT &) override;
    SoftAction onSoftware(HANDLE, Address) override;

  public:
    using ThemidaCommon::ThemidaCommon;
};
void mitigateHeaderAntiDump(HANDLE process, Address base, Address oep, Address iat, Address virtualProtect,
                            const Logger &logger);
#endif
} // namespace mm
