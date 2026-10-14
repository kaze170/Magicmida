// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "ThemidaCommon.hpp"
namespace mm {
#ifdef _WIN64
class Themida64 final : public ThemidaCommon {
    Address closeAPI_{}, allocAPI_{}, guardStart_{}, guardEnd_{}, cookie_{}, realOEP_{};
    bool guardStepping_{}, tmGuard_{}, traceMSVC_{};
    unsigned tlsCounter_{}, tlsTotal_{};
    void installGuard();
    void finish(Address oep);
    void writeMSVCOEP(Address crt);
    void onStart() override;
    DWORD onAccess(HANDLE, const EXCEPTION_RECORD &) override;
    DWORD onStep(Address) override;
    void onHardware(HANDLE, Address, CONTEXT &) override;
    SoftAction onSoftware(HANDLE, Address) override;

  public:
    using ThemidaCommon::ThemidaCommon;
};
#endif
} // namespace mm
