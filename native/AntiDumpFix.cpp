// SPDX-License-Identifier: GPL-3.0-only
#include "Themida.hpp"
namespace mm {
#ifndef _WIN64
void mitigateHeaderAntiDump(HANDLE p, Address base, Address oep, Address iat, Address virtualProtect,
                            const Logger &logger) {
    Address slot{};
    for (std::size_t i = 0; i < 512; ++i) {
        Address value{};
        if (!readMemory(p, iat + i * sizeof(Address), &value, sizeof(value)))
            break;
        if (value == virtualProtect) {
            slot = iat + i * sizeof(Address);
            break;
        }
    }
    if (!slot)
        throw std::runtime_error("VirtualProtect not found for PE-header mitigation");
    auto original = readMemory(p, oep, 5);
    if (original[0] != 0xe9)
        throw std::runtime_error("Virtualized OEP is not a near jump");
    auto lfanew = readValue<DWORD>(p, base + 0x3c);
    auto entry = readValue<DWORD>(p, base + lfanew + 0x28);
    Bytes code{0x6a, 0, 0x54, 0x6a, 4, 0x68, 0, 4, 0, 0, 0x68};
    auto append = [&]<class T>(T v) {
        auto off = code.size();
        code.resize(off + sizeof(T));
        store(code, off, v);
    };
    append(base);
    append(WORD(0x15ff));
    append(slot);
    append(WORD(0x05c7));
    append(DWORD(base + lfanew + 0x28));
    append(entry);
    const BYTE args[] = {0x54, 0xff, 0x74, 0x24, 4, 0x68, 0, 4, 0, 0, 0x68};
    code.insert(code.end(), std::begin(args), std::end(args));
    append(base);
    append(WORD(0x15ff));
    append(slot);
    append(BYTE(0x58));
    append(BYTE(0xe9));
    append(DWORD(load<DWORD>(original, 1) - (code.size() + 4 - 5)));
    writeMemory(p, oep, code.data(), code.size());
    log(logger, LogType::Good, L"Installed PE-header VM mitigation at OEP.");
    log(logger, LogType::Info,
        L"This legacy mitigation assumes enough space at OEP; other VM anti-dumps are not fixed.");
}
#endif
} // namespace mm
