// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "DebuggerCore.hpp"
#include "Dumper.hpp"
#include <beaengine/BeaEngine.h>
namespace mm {
int disassemble(DISASM &dis, std::span<const std::uint8_t> bytes, Address va = 0);
class ThemidaCommon : public DebuggerCore {
  protected:
    bool createData_{}, v3_{}, vmOEP_{}, ancient_{};
    DWORD baseOfData_{};
    Address imageEnd_{};
    BYTE linker_{};
    Region tm_{};
    Bytes tmBytes_;
    std::vector<Address> guardAddresses_;
    Address sleepAPI_{}, strlenAPI_{}, corExeMain_{};
    void initPE();
    void injectScylla(bool required);
    void selectTM(Address address);
    Address findTM(std::string_view pattern, Address start = 0) const;
    void checkVirtualOEP(Address oep);
    Address determineIAT(Address oep, Dumper &dumper);
    void traceImports(Address iat, Dumper &dumper);
    void onDll(const std::wstring &name, Address base) override;
    bool dotNet(Address address);
    Address correctOEP(Address hit);

  public:
    ThemidaCommon(Path p, bool data, Logger logger, std::atomic_bool &cancel)
        : DebuggerCore(std::move(p), std::move(logger), cancel), createData_(data) {}
};
} // namespace mm
