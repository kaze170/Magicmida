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
    static std::atomic<std::uint64_t> sequence{0};
    auto prefix =
        L".mm-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()) + L"-";
    Path temp;
    Handle h;
    DWORD error = ERROR_FILE_EXISTS;
    for (unsigned attempt = 0; attempt < 64; ++attempt) {
        // A short sibling name also works when the target basename is near
        // the filesystem's per-component limit (appending a suffix would fail).
        temp = path.parent_path() /
               (prefix + std::to_wstring(sequence.fetch_add(1, std::memory_order_relaxed)) + L".tmp");
        h.reset(
            CreateFileW(temp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (h)
            break;
        error = GetLastError();
        if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS)
            winError("CreateFile(output)", error);
        // Never remove someone else's file on a collision. Try a fresh name.
    }
    if (!h)
        winError("CreateFile(unique output)", error);
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
namespace {
struct MemorySpan {
    Address address{};
    std::size_t size{};
    MEMORY_BASIC_INFORMATION region{};
    DWORD original{};
    bool changed{};
};
std::string memoryDiagnostic(const char *operation, const MemorySpan &span, DWORD requested, DWORD error) {
    return std::string(operation) + " (Windows error " + std::to_string(error) + "; address=0x" +
           narrow(hex(span.address)) + "; size=0x" + narrow(hex(span.size)) + "; requested=0x" +
           narrow(hex(requested)) + "; current=0x" + narrow(hex(span.region.Protect)) + "; state=0x" +
           narrow(hex(span.region.State)) + "; type=0x" + narrow(hex(span.region.Type)) + "; allocation=0x" +
           narrow(hex(reinterpret_cast<Address>(span.region.AllocationBase))) + ")";
}
std::vector<MemorySpan> memorySpans(HANDLE process, Address address, std::size_t size) {
    if (size && size - 1 > UINTPTR_MAX - address)
        throw std::runtime_error("Memory range overflow: address=0x" + narrow(hex(address)) + " size=0x" +
                                 narrow(hex(size)));
    std::vector<MemorySpan> result;
    while (size) {
        MemorySpan span;
        span.address = address;
        span.size = size;
        if (!VirtualQueryEx(process, reinterpret_cast<const void *>(address), &span.region,
                            sizeof(span.region)))
            throw std::runtime_error(memoryDiagnostic("VirtualQueryEx", span, 0, GetLastError()));
        auto start = reinterpret_cast<Address>(span.region.BaseAddress);
        if (span.region.State != MEM_COMMIT || address < start || address - start >= span.region.RegionSize)
            throw std::runtime_error(
                memoryDiagnostic("Memory range is not committed", span, 0, ERROR_INVALID_ADDRESS));
        span.size = std::min<std::size_t>(size, span.region.RegionSize - (address - start));
        result.push_back(span);
        size -= span.size;
        if (size)
            address += span.size;
    }
    return result;
}
void changeProtection(HANDLE process, MemorySpan &span, DWORD protection, const char *operation) {
    if (span.region.Protect == protection)
        return;
    if (!VirtualProtectEx(process, reinterpret_cast<void *>(span.address), span.size, protection,
                          &span.original))
        throw std::runtime_error(memoryDiagnostic(operation, span, protection, GetLastError()));
    span.changed = true;
}
// Attempt every restoration even if one fails; report the first failure only
// after the remaining pages have been put back.
std::string restoreProtections(HANDLE process, std::vector<MemorySpan> &spans) {
    std::optional<std::size_t> failed;
    DWORD error{};
    for (std::size_t i = spans.size(); i > 0; --i) {
        auto &span = spans[i - 1];
        if (!span.changed)
            continue;
        DWORD ignored{};
        if (!VirtualProtectEx(process, reinterpret_cast<void *>(span.address), span.size, span.original,
                              &ignored) &&
            !failed) {
            error = GetLastError();
            failed = i - 1;
        }
        span.changed = false;
    }
    return failed
               ? memoryDiagnostic("VirtualProtectEx(restore)", spans[*failed], spans[*failed].original, error)
               : std::string{};
}
} // namespace
void protectMemory(HANDLE process, Address address, std::size_t size, DWORD protection) {
    if (!size)
        throw std::runtime_error("Empty guard protection range at 0x" + narrow(hex(address)));
    // Preflight the complete range first. A single VirtualProtectEx spanning
    // separate reservations or an uncommitted gap is invalid on Windows.
    auto spans = memorySpans(process, address, size);
    try {
        for (auto &span : spans)
            changeProtection(process, span, protection, "VirtualProtectEx(guard)");
    } catch (const std::exception &error) {
        auto restoreError = restoreProtections(process, spans);
        if (!restoreError.empty())
            throw std::runtime_error(std::string(error.what()) + "; " + restoreError);
        throw;
    }
}
void writeMemory(HANDLE process, Address address, const void *buffer, std::size_t size) {
    if (!size)
        return;
    auto spans = memorySpans(process, address, size);
    try {
        for (auto &span : spans) {
            auto basic = span.region.Protect & 0xff;
            bool writable = basic == PAGE_READWRITE || basic == PAGE_WRITECOPY ||
                            basic == PAGE_EXECUTE_READWRITE || basic == PAGE_EXECUTE_WRITECOPY;
            // PEB/TEB pages can reject protection changes (ERROR_INVALID_PARAMETER)
            // even though WriteProcessMemory is permitted. Do not touch their
            // protection when the existing mapping is already writable.
            if (writable && !(span.region.Protect & PAGE_GUARD))
                continue;
            bool executable = basic == PAGE_EXECUTE || basic == PAGE_EXECUTE_READ ||
                              basic == PAGE_EXECUTE_READWRITE || basic == PAGE_EXECUTE_WRITECOPY;
            DWORD desired = executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
            desired |= span.region.Protect & (PAGE_NOCACHE | PAGE_WRITECOMBINE);
            changeProtection(process, span, desired, "VirtualProtectEx(write)");
        }
        SIZE_T done{};
        BOOL ok = WriteProcessMemory(process, reinterpret_cast<void *>(address), buffer, size, &done);
        DWORD error = ok ? ERROR_PARTIAL_COPY : GetLastError();
        if (!ok || done != size) {
            MemorySpan whole = spans.front();
            whole.address = address;
            whole.size = size;
            throw std::runtime_error(memoryDiagnostic("WriteProcessMemory", whole, 0, error) +
                                     "; written=" + std::to_string(done));
        }
    } catch (const std::exception &error) {
        auto restoreError = restoreProtections(process, spans);
        if (!restoreError.empty())
            throw std::runtime_error(std::string(error.what()) + "; " + restoreError);
        throw;
    }
    auto restoreError = restoreProtections(process, spans);
    if (!restoreError.empty())
        throw std::runtime_error(restoreError);
    check(FlushInstructionCache(process, reinterpret_cast<const void *>(address), size),
          "FlushInstructionCache");
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
