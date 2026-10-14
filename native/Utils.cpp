// SPDX-License-Identifier: GPL-3.0-only
#include "Utils.hpp"
#include <cwctype>
#include <cctype>
#include <sstream>
namespace mm {
std::wstring widen(std::string_view text) {
    if (text.empty())
        return {};
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()),
                                nullptr, 0);
    if (!n)
        winError("MultiByteToWideChar");
    std::wstring out(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), n);
    return out;
}
std::string narrow(std::wstring_view text) {
    if (text.empty())
        return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr,
                                nullptr);
    if (!n)
        winError("WideCharToMultiByte");
    std::string out(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), n, nullptr,
                        nullptr);
    return out;
}
std::wstring hex(std::uint64_t value) {
    std::wostringstream s;
    s << std::hex << std::uppercase << value;
    return s.str();
}
std::wstring lower(std::wstring s) {
    for (auto &c : s)
        c = static_cast<wchar_t>(std::towlower(c));
    return s;
}
std::string lower(std::string s) {
    for (auto &c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
void winError(const char *operation, DWORD code) {
    throw std::runtime_error(std::string(operation) + " (Windows error " + std::to_string(code) + ")");
}
Bytes readFile(const Path &path) {
    Handle h(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!h)
        winError("CreateFile");
    LARGE_INTEGER size{};
    check(GetFileSizeEx(h.get(), &size), "GetFileSizeEx");
    if (size.QuadPart < 0 || static_cast<std::uint64_t>(size.QuadPart) > SIZE_MAX ||
        size.QuadPart > UINT32_MAX)
        throw std::runtime_error("File is too large for a PE image");
    Bytes data(static_cast<std::size_t>(size.QuadPart));
    std::size_t done = 0;
    while (done < data.size()) {
        DWORD n{};
        check(ReadFile(h.get(), data.data() + done,
                       static_cast<DWORD>(std::min<std::size_t>(1 << 20, data.size() - done)), &n, nullptr),
              "ReadFile");
        if (!n)
            throw std::runtime_error("Short file read");
        done += n;
    }
    return data;
}
void writeFileAtomic(const Path &path, std::span<const std::uint8_t> data) {
    auto temp = path;
    temp +=
        L".mm-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()) + L".tmp";
    Handle h(
        CreateFileW(temp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!h)
        winError("CreateFile(output)");
    try {
        for (std::size_t done = 0; done < data.size();) {
            DWORD n{};
            check(WriteFile(h.get(), data.data() + done,
                            static_cast<DWORD>(std::min<std::size_t>(1 << 20, data.size() - done)), &n,
                            nullptr),
                  "WriteFile");
            if (!n)
                throw std::runtime_error("Short file write");
            done += n;
        }
        check(FlushFileBuffers(h.get()), "FlushFileBuffers");
        h.reset();
        check(MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH),
              "MoveFileEx");
    } catch (...) {
        h.reset();
        DeleteFileW(temp.c_str());
        throw;
    }
}
Path executablePath() {
    std::wstring s(32768, 0);
    auto n = GetModuleFileNameW(nullptr, s.data(), static_cast<DWORD>(s.size()));
    if (!n || n >= s.size())
        winError("GetModuleFileName");
    s.resize(n);
    return s;
}
Path unpackedPath(const Path &p) {
    return p.parent_path() / (p.stem().wstring() + L"U" + p.extension().wstring());
}
DWORD windowsBuild() {
    using Fn = LONG(WINAPI *)(OSVERSIONINFOW *);
    auto f = reinterpret_cast<Fn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
    OSVERSIONINFOW v{};
    v.dwOSVersionInfoSize = sizeof(v);
    if (!f || f(&v) < 0)
        throw std::runtime_error("RtlGetVersion failed");
    return v.dwBuildNumber;
}
bool readMemory(HANDLE p, Address a, void *b, std::size_t n) {
    SIZE_T done{};
    return ReadProcessMemory(p, reinterpret_cast<const void *>(a), b, n, &done) && done == n;
}
Bytes readMemory(HANDLE p, Address a, std::size_t n) {
    Bytes b(n);
    if (!readMemory(p, a, b.data(), n))
        winError("ReadProcessMemory");
    return b;
}
void writeMemory(HANDLE p, Address a, const void *b, std::size_t n) {
    if (!n)
        return;
    DWORD old{};
    check(VirtualProtectEx(p, reinterpret_cast<void *>(a), n, PAGE_EXECUTE_READWRITE, &old),
          "VirtualProtectEx");
    SIZE_T done{};
    BOOL ok = WriteProcessMemory(p, reinterpret_cast<void *>(a), b, n, &done);
    DWORD error = GetLastError(), ignored{};
    BOOL restored = VirtualProtectEx(p, reinterpret_cast<void *>(a), n, old, &ignored);
    if (!ok || done != n)
        winError("WriteProcessMemory", error);
    check(restored, "VirtualProtectEx(restore)");
    check(FlushInstructionCache(p, reinterpret_cast<void *>(a), n), "FlushInstructionCache");
}
CONTEXT context(HANDLE t, DWORD flags) {
    CONTEXT c{};
    c.ContextFlags = flags;
    check(GetThreadContext(t, &c), "GetThreadContext");
    return c;
}
void setContext(HANDLE t, const CONTEXT &c) {
    check(SetThreadContext(t, &c), "SetThreadContext");
}
} // namespace mm
