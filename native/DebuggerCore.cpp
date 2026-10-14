// SPDX-License-Identifier: GPL-3.0-only
#include "DebuggerCore.hpp"
#include <tlhelp32.h>
#include <winternl.h>
namespace mm {
DebuggerCore::DebuggerCore(Path p, Logger l, std::atomic_bool &c)
    : executable_(std::filesystem::absolute(p)), log_(std::move(l)), cancel_(c) {
}
DebuggerCore::~DebuggerCore() {
    stopTarget();
    threads_.clear();
    process_.reset();
    if (!dllExecutable_.empty())
        DeleteFileW(dllExecutable_.c_str());
}
void DebuggerCore::makeDllExecutable() {
    auto data = readFile(executable_);
    PEImage pe(data);
    auto &oh = pe.nt.OptionalHeader;
#ifdef _WIN64
    Bytes stub{0x48, 0x83, 0xec, 0x28, 0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0,    0, 0, 0x48, 0x8b,
               0x48, 0x10, 0xba, 1,    0,    0,    0,    0x45, 0x31, 0xc0, 0xe8, 0, 0, 0,    0};
#else
    Bytes stub{0x8b, 0x40, 0x08, 0x6a, 0, 0x6a, 1, 0x50, 0xe8, 0, 0, 0, 0};
#endif
    auto index = pe.sectionAt(oh.AddressOfEntryPoint);
    if (!index)
        throw std::runtime_error("DLL entrypoint outside sections");
    auto &s = pe.sections[*index].header;
    if (s.SizeOfRawData < stub.size())
        throw std::runtime_error("DLL entrypoint section too small");
    auto offset = std::size_t(s.PointerToRawData) + s.SizeOfRawData - stub.size();
    bounds(data.size(), offset, stub.size());
    if (!std::all_of(data.begin() + offset, data.begin() + offset + stub.size(),
                     [](auto b) { return b == 0; }))
        throw std::runtime_error("No room for DLL entrypoint stub");
    DWORD newEP = rva32(std::uint64_t(s.VirtualAddress) + s.SizeOfRawData - stub.size());
    store(stub, stub.size() - 4, static_cast<DWORD>(oh.AddressOfEntryPoint - newEP - stub.size()));
    std::copy(stub.begin(), stub.end(), data.begin() + offset);
    oh.AddressOfEntryPoint = newEP;
    pe.nt.FileHeader.Characteristics &= ~IMAGE_FILE_DLL;
    oh.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY;
    pe.switchManifest(data, 2, 1);
    pe.save(data);
    auto temporary = executable_;
    temporary += L".MM-" + std::to_wstring(GetCurrentProcessId()) + L".exe";
    if (std::filesystem::exists(temporary))
        throw std::runtime_error("Temporary DLL executable already exists");
    writeFileAtomic(temporary, data);
    // Only claim ownership after creation; never delete a pre-existing file.
    dllExecutable_ = std::move(temporary);
}
void DebuggerCore::launch() {
    auto file = readFile(executable_);
    filePE_ = std::make_unique<PEImage>(file);
    isDll_ = (filePE_->nt.FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
    if (isDll_)
        makeDllExecutable();
    auto target = isDll_ ? dllExecutable_ : executable_;
    auto command = L"\"" + target.wstring() + L"\"";
    auto cwd = std::filesystem::current_path();
    if (cwd == executablePath().parent_path())
        cwd = executable_.parent_path();
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    check(CreateProcessW(target.c_str(), command.data(), nullptr, nullptr, FALSE,
                         DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE | CREATE_DEFAULT_ERROR_MODE, nullptr,
                         cwd.c_str(), &si, &pi),
          "CreateProcess");
    process_.reset(pi.hProcess);
    pid_ = pi.dwProcessId;
    active_ = true;
    CloseHandle(pi.hThread);
}
void DebuggerCore::created(const DEBUG_EVENT &e) {
    Handle file(e.u.CreateProcessInfo.hFile);
    // The debug-event handle may be distinct from the CreateProcess handle.
    if (e.u.CreateProcessInfo.hProcess != process_.get())
        CloseHandle(e.u.CreateProcessInfo.hProcess);
    threads_.emplace(e.dwThreadId, Handle(e.u.CreateProcessInfo.hThread));
    imageBase_ = reinterpret_cast<Address>(e.u.CreateProcessInfo.lpBaseOfImage);
    using Query = LONG(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    auto query =
        reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    PROCESS_BASIC_INFORMATION pbi{};
    if (!query || query(process_.get(), 0, &pbi, sizeof(pbi), nullptr) < 0)
        throw std::runtime_error("Cannot read PEB");
    auto peb = reinterpret_cast<Address>(pbi.PebBaseAddress);
    info(L"Debug session: PID " + std::to_wstring(pid_) + L"; PEB 0x" + hex(peb) + L"; image base 0x" +
         hex(imageBase_));
    // Ldr checks BeingDebugged before issuing its initial breakpoint. Clearing
    // it here would suppress the event on which onStart() depends.
    pebBase_ = peb;
#ifdef _WIN64
    constexpr Address shim = 0x2d8;
#else
    constexpr Address shim = 0x1e8;
#endif
    Address value{};
    if (rpm(peb + shim, &value, sizeof(value)) && value)
        write<Address>(peb + shim, 0);
    info(L"Windows build " + std::to_wstring(windowsBuild()) + L"; PID " + std::to_wstring(pid_) +
         L"; image base " + hex(imageBase_));
    // Wait for the loader breakpoint before resolving APIs: Toolhelp module
    // enumeration is not reliable at CREATE_PROCESS_DEBUG_EVENT.
    loadedModules_[lower(executable_.filename().wstring())] = imageBase_;
}
bool DebuggerCore::run() {
    try {
        launch();
        while (!cancel_) {
            DEBUG_EVENT e{};
            if (!waitEvent(e, 100)) {
                if (GetLastError() == ERROR_SEM_TIMEOUT)
                    continue;
                winError("WaitForDebugEvent");
            }
            currentThread_ = e.dwThreadId;
            DWORD status = DBG_CONTINUE;
            bool exited = false;
            switch (e.dwDebugEventCode) {
            case CREATE_PROCESS_DEBUG_EVENT:
                created(e);
                break;
            case CREATE_THREAD_DEBUG_EVENT:
                threads_.emplace(e.dwThreadId, Handle(e.u.CreateThread.hThread));
                updateAll();
                break;
            case EXIT_THREAD_DEBUG_EVENT:
                threads_.erase(e.dwThreadId);
                break;
            case EXIT_PROCESS_DEBUG_EVENT:
                if (initialBreak_)
                    warning(L"Target exited before the loader breakpoint; unpacker was not initialized.");
                info(L"Process ended: " + std::to_wstring(e.u.ExitProcess.dwExitCode));
                exited = true;
                break;
            case EXCEPTION_DEBUG_EVENT:
                status = exception(e);
                break;
            case LOAD_DLL_DEBUG_EVENT: {
                Handle file(e.u.LoadDll.hFile);
                std::wstring name(32768, 0);
                DWORD n =
                    file ? GetFinalPathNameByHandleW(file.get(), name.data(), static_cast<DWORD>(name.size()),
                                                     FILE_NAME_NORMALIZED)
                         : 0;
                name.resize(n < name.size() ? n : 0);
                auto base = reinterpret_cast<Address>(e.u.LoadDll.lpBaseOfDll);
                if (!name.empty())
                    loadedModules_[lower(Path(name).filename().wstring())] = base;
                onDll(lower(name), base);
                break;
            }
            case UNLOAD_DLL_DEBUG_EVENT:
                std::erase_if(loadedModules_, [&](const auto &entry) {
                    return entry.second == reinterpret_cast<Address>(e.u.UnloadDll.lpBaseOfDll);
                });
                break;
            case OUTPUT_DEBUG_STRING_EVENT: {
                auto &d = e.u.DebugString;
                if (!d.nDebugStringLength || d.nDebugStringLength > 4096)
                    break;
                auto bytes = read(reinterpret_cast<Address>(d.lpDebugStringData),
                                  std::size_t(d.nDebugStringLength) * (d.fUnicode ? 2 : 1));
                bytes.push_back(0);
                bytes.push_back(0);
                if (d.fUnicode)
                    info(std::wstring(reinterpret_cast<const wchar_t *>(bytes.data())));
                else {
                    std::string s(reinterpret_cast<const char *>(bytes.data()));
                    for (char &c : s)
                        if (static_cast<unsigned char>(c) > 127)
                            c = '?';
                    info(widen(s));
                }
                break;
            }
            case RIP_EVENT:
                throw std::runtime_error("Windows debugger RIP event");
            default:
                break;
            }
            continuePending(status);
            if (exited) {
                active_ = false;
                return finished_ && e.u.ExitProcess.dwExitCode == 0;
            }
        }
        warning(L"Cancelled; terminating debug target.");
    } catch (const std::exception &e) {
        warning(widen(e.what()));
    }
    stopTarget();
    return false;
}
bool DebuggerCore::waitEvent(DEBUG_EVENT &event, DWORD timeout) {
    if (!WaitForDebugEvent(&event, timeout))
        return false;
    pendingThread_ = event.dwThreadId;
    return true;
}
void DebuggerCore::continuePending(DWORD status) {
    if (!pendingThread_)
        throw std::runtime_error("No pending debug event");
    check(ContinueDebugEvent(pid_, pendingThread_, status), "ContinueDebugEvent");
    pendingThread_ = 0;
}
void DebuggerCore::stopTarget() noexcept {
    if (!active_ || !process_)
        return;
    TerminateProcess(process_.get(), 1);
    if (pendingThread_) {
        ContinueDebugEvent(pid_, pendingThread_, DBG_CONTINUE);
        pendingThread_ = 0;
    }
    auto deadline = GetTickCount64() + 5000;
    while (GetTickCount64() < deadline) {
        DEBUG_EVENT e{};
        if (!WaitForDebugEvent(&e, 100)) {
            if (GetLastError() != ERROR_SEM_TIMEOUT)
                break;
            continue;
        }
        if (e.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
            Handle file(e.u.LoadDll.hFile);
        } else if (e.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
            Handle t(e.u.CreateThread.hThread);
        } else if (e.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            Handle file(e.u.CreateProcessInfo.hFile), threadHandle(e.u.CreateProcessInfo.hThread);
            if (e.u.CreateProcessInfo.hProcess != process_.get())
                CloseHandle(e.u.CreateProcessInfo.hProcess);
        }
        ContinueDebugEvent(e.dwProcessId, e.dwThreadId, DBG_CONTINUE);
        if (e.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            active_ = false;
            return;
        }
    }
    DebugActiveProcessStop(pid_);
    active_ = false;
}
void DebuggerCore::protect(Address a, std::size_t n, DWORD p) {
    protectMemory(process_.get(), a, n, p);
}
void DebuggerCore::apply(CONTEXT &c) {
    c.Dr0 = hardware_[0].address;
    c.Dr1 = hardware_[1].address;
    c.Dr2 = hardware_[2].address;
    c.Dr3 = hardware_[3].address;
    c.Dr6 = 0;
    c.Dr7 = 0;
    for (unsigned i = 0; i < 4; ++i)
        if (hardware_[i].address && !hardware_[i].disabled)
            c.Dr7 |= (Address(1) << (2 * i)) | (Address(hardware_[i].type) << (16 + 4 * i));
}
void DebuggerCore::updateAll() {
    for (auto &[id, t] : threads_) {
        auto c = context(t.get(), CONTEXT_DEBUG_REGISTERS);
        apply(c);
        setContext(t.get(), c);
    }
}
void DebuggerCore::setBreakpoint(Address a, BreakType t) {
    if (!a)
        throw std::runtime_error("Null breakpoint address");
    for (auto &b : hardware_)
        if (!b.address) {
            b = {a, t, false};
            updateAll();
            return;
        }
    throw std::runtime_error("All four hardware breakpoints are in use");
}
void DebuggerCore::resetBreakpoint(Address a) {
    for (auto &b : hardware_)
        if (b.address == a)
            b = {};
    updateAll();
}
bool DebuggerCore::hasBreakpoint(Address a) const {
    return std::any_of(hardware_.begin(), hardware_.end(), [&](auto &b) { return b.address == a && a; });
}
void DebuggerCore::enableBreakpoints() {
    bool changed = false;
    for (auto &b : hardware_)
        if (b.disabled) {
            b.disabled = false;
            changed = true;
        }
    if (changed)
        updateAll();
}
void DebuggerCore::setSoftBP(Address a) {
    if (software_.contains(a))
        return;
    auto old = read<std::uint8_t>(a);
    write<std::uint8_t>(a, 0xcc);
    software_.emplace(a, old);
}
void DebuggerCore::clearSoftBPs() {
    for (auto [a, b] : software_)
        write(a, b);
    software_.clear();
    reenable_ = 0;
}
DWORD DebuggerCore::exception(const DEBUG_EVENT &e) {
    const auto &ex = e.u.Exception.ExceptionRecord;
    Address a = reinterpret_cast<Address>(ex.ExceptionAddress);
    HANDLE t = thread();
    if (ex.ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
        return onAccess(t, ex);
    if (ex.ExceptionCode == EXCEPTION_BREAKPOINT) {
        auto it = software_.find(a);
        if (it == software_.end()) {
            if (initialBreak_) {
                initialBreak_ = false;
                write<BYTE>(pebBase_ + 2, 0);
                info(L"Loader breakpoint reached; initializing unpacker.");
                onStart();
                updateAll();
                return DBG_CONTINUE;
            }
            return DBG_EXCEPTION_NOT_HANDLED;
        }
        auto c = context(t, CONTEXT_CONTROL);
        ip(c) = a;
        setContext(t, c);
        write(a, it->second);
        auto action = onSoftware(t, a);
        if (finished_) {
            software_.erase(a);
            return DBG_CONTINUE;
        }
        if (action == SoftAction::Clear)
            software_.erase(a);
        else if (action == SoftAction::KeepNoStep)
            write<std::uint8_t>(a, 0xcc);
        else {
            reenable_ = a;
            c = context(t, CONTEXT_CONTROL);
            c.EFlags |= 0x100;
            setContext(t, c);
        }
        return DBG_CONTINUE;
    }
    if (ex.ExceptionCode != EXCEPTION_SINGLE_STEP)
        return DBG_EXCEPTION_NOT_HANDLED;
    auto c = context(t);
    auto hits = c.Dr6 & 15;
    if (hits && !(c.Dr6 & (1 << 14))) {
        for (unsigned i = 0; i < 4; ++i)
            if (hits & (1 << i)) {
                auto b = hardware_[i];
                if (!b.address)
                    continue;
                onHardware(t, b.address, c);
                // Child handlers may have changed control/integer context. Read it again.
                if (b.type == BreakType::Execute)
                    for (auto &cur : hardware_)
                        if (cur.address == b.address) {
                            cur.disabled = true;
                            updateAll();
                            auto next = context(t, CONTEXT_CONTROL);
                            next.EFlags |= 0x100;
                            setContext(t, next);
                            break;
                        }
            }
        return DBG_CONTINUE;
    }
    if (reenable_) {
        write<std::uint8_t>(reenable_, 0xcc);
        reenable_ = 0;
        return DBG_CONTINUE;
    }
    return onStep(a);
}
DWORD DebuggerCore::onAccess(HANDLE, const EXCEPTION_RECORD &e) {
    info(L"Access violation at " + hex(reinterpret_cast<Address>(e.ExceptionAddress)));
    return DBG_EXCEPTION_NOT_HANDLED;
}
DWORD DebuggerCore::onStep(Address) {
    enableBreakpoints();
    return DBG_CONTINUE;
}
void DebuggerCore::onDll(const std::wstring &name, Address) {
    if (name.find(L"aclayers.dll") != std::wstring::npos)
        throw std::runtime_error("Disable Windows compatibility mode for Magicmida and target");
}
void DebuggerCore::terminateSuccess() {
    check(TerminateProcess(process_.get(), 0), "TerminateProcess");
    finished_ = true;
}
Address DebuggerCore::moduleBase(const wchar_t *dll) {
    if (auto it = loadedModules_.find(lower(std::wstring(dll))); it != loadedModules_.end())
        return it->second;
    Handle snap(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid_));
    if (!snap)
        winError("CreateToolhelp32Snapshot");
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    check(Module32FirstW(snap.get(), &me), "Module32First");
    do {
        if (lower(me.szModule) == lower(std::wstring(dll)))
            return reinterpret_cast<Address>(me.modBaseAddr);
    } while (Module32NextW(snap.get(), &me));
    throw std::runtime_error("Required module is not loaded in target: " + narrow(dll));
}
Address DebuggerCore::api(const wchar_t *dll, const char *name) {
    HMODULE local = GetModuleHandleW(dll);
    if (!local)
        local = LoadLibraryW(dll);
    if (!local)
        winError("LoadLibrary");
    auto proc = GetProcAddress(local, name);
    if (!proc)
        winError(name);
    HMODULE owner{};
    check(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                 GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                             reinterpret_cast<LPCWSTR>(proc), &owner),
          "GetModuleHandleEx");
    wchar_t path[32768]{};
    check(GetModuleFileNameW(owner, path, 32768) != 0, "GetModuleFileName");
    auto basename = lower(Path(path).filename().wstring());
    return moduleBase(basename.c_str()) +
           (reinterpret_cast<Address>(proc) - reinterpret_cast<Address>(owner));
}
} // namespace mm
