// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "PEInfo.hpp"
namespace mm {
#ifndef _WIN64
class Patcher {
    Path path_;
    Bytes data_;
    PEImage pe_;
    Logger log_;
    std::optional<std::size_t> find(std::string_view pattern, std::size_t start) const;
    void createMSVC();
    void createMaple();
    void split(DWORD rdata, DWORD data, DWORD end, DWORD zeroSize = 0);
    void shrinkExports();
    void save();

  public:
    Patcher(Path path, Logger log)
        : path_(std::move(path)), data_(readFile(path_)), pe_(data_), log_(std::move(log)) {}
    void createData();
    void shrink();
    void dumpProcess(DWORD pid);
};
#endif
} // namespace mm
