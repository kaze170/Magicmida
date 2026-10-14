// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include "Binary.hpp"
namespace mm {
using Address = std::uintptr_t;
using Bytes = std::vector<std::uint8_t>;
using Path = std::filesystem::path;
enum class LogType { Info, Good, Fatal };
using Logger = std::function<void(LogType, const std::wstring &)>;
inline void log(const Logger &sink, LogType type, const std::wstring &text) {
    if (sink)
        sink(type, text);
}
std::wstring widen(std::string_view text);
std::string narrow(std::wstring_view text);
std::wstring hex(std::uint64_t value);
std::wstring lower(std::wstring text);
std::string lower(std::string text);
[[noreturn]] void winError(const char *operation, DWORD code = GetLastError());
inline void check(BOOL ok, const char *operation) {
    if (!ok)
        winError(operation);
}
class Handle {
    HANDLE value_ = nullptr;

  public:
    Handle() = default;
    explicit Handle(HANDLE value) : value_(value) {}
    ~Handle() { reset(); }
    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;
    Handle(Handle &&other) noexcept : value_(std::exchange(other.value_, nullptr)) {}
    Handle &operator=(Handle &&other) noexcept {
        if (this != &other)
            reset(std::exchange(other.value_, nullptr));
        return *this;
    }
    void reset(HANDLE value = nullptr) noexcept {
        if (*this)
            CloseHandle(value_);
        value_ = value;
    }
    HANDLE get() const noexcept { return value_; }
    explicit operator bool() const noexcept { return value_ && value_ != INVALID_HANDLE_VALUE; }
};
struct Region {
    Address address{};
    std::size_t size{};
    bool contains(Address a) const { return a >= address && a - address < size; }
};
Bytes readFile(const Path &path);
void writeFileAtomic(const Path &path, std::span<const std::uint8_t> data);
Path executablePath();
Path unpackedPath(const Path &path);
DWORD windowsBuild();
bool readMemory(HANDLE process, Address address, void *buffer, std::size_t size);
Bytes readMemory(HANDLE process, Address address, std::size_t size);
void writeMemory(HANDLE process, Address address, const void *buffer, std::size_t size);
template <class T> T readValue(HANDLE process, Address address) {
    T v{};
    if (!readMemory(process, address, &v, sizeof(v)))
        winError("ReadProcessMemory");
    return v;
}
template <class T> void writeValue(HANDLE process, Address address, const T &v) {
    writeMemory(process, address, &v, sizeof(v));
}
CONTEXT context(HANDLE thread, DWORD flags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS);
void setContext(HANDLE thread, const CONTEXT &ctx);
#ifdef _WIN64
inline auto &ip(CONTEXT &c) {
    return c.Rip;
}
inline auto &sp(CONTEXT &c) {
    return c.Rsp;
}
#else
inline auto &ip(CONTEXT &c) {
    return c.Eip;
}
inline auto &sp(CONTEXT &c) {
    return c.Esp;
}
#endif
std::string_view oneCoreModule(std::string_view api);
} // namespace mm
