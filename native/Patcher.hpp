// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "PEInfo.hpp"
namespace mm {
class Patcher {
    Path path_;
    Bytes data_;
    PEImage pe_;
    Logger log_;
    void applyLayout(const PEImage &layout);
    void save();

  public:
    Patcher(Path path, Logger log)
        : path_(std::move(path)), data_(readFile(path_)), pe_(data_), log_(std::move(log)) {}
    // Without a same-build reference, only a conservative PE32 BaseOfData split
    // is possible. False means no change, not a successfully inferred layout.
    bool createData(const Path &reference = {});
    void shrink();
    void dumpProcess(DWORD pid);
};
} // namespace mm
