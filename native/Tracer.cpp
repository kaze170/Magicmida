// SPDX-License-Identifier: GPL-3.0-only
#include "DebuggerCore.hpp"
namespace mm {
bool DebuggerCore::trace(Address start, unsigned limit,
                         const std::function<bool(unsigned, CONTEXT &)> &predicate) {
    HANDLE t = thread();
    auto saved = context(t);
    DWORD tid = currentThread_;
    std::vector<HANDLE> suspended;
    for (auto &[id, h] : threads_)
        if (id != tid) {
            if (SuspendThread(h.get()) != DWORD(-1))
                suspended.push_back(h.get());
        }
    auto cleanup = [&] {
        for (auto h : suspended)
            ResumeThread(h);
    };
    try {
        auto c = saved;
        ip(c) = start;
        c.EFlags |= 0x100;
        c.Dr7 = 0;
        setContext(t, c);
        continuePending(DBG_CONTINUE);
        unsigned count = 0;
        for (;;) {
            if (cancel_)
                throw std::runtime_error("Tracing cancelled");
            DEBUG_EVENT e{};
            if (!waitEvent(e, 100)) {
                if (GetLastError() == ERROR_SEM_TIMEOUT)
                    continue;
                winError("WaitForDebugEvent(trace)");
            }
            if (e.dwThreadId == tid && e.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
                e.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
                c = context(t);
                ++count;
                bool done = predicate(count, c);
                if (done || count >= limit) {
                    setContext(t, saved);
                    cleanup();
                    return done;
                }
                c.EFlags |= 0x100;
                setContext(t, c);
            } else {
                if (e.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
                    auto [it, inserted] = threads_.emplace(e.dwThreadId, Handle(e.u.CreateThread.hThread));
                    if (inserted && SuspendThread(it->second.get()) != DWORD(-1))
                        suspended.push_back(it->second.get());
                } else if (e.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT) {
                    if (e.dwThreadId == tid)
                        throw std::runtime_error("Traced thread exited");
                    auto it = threads_.find(e.dwThreadId);
                    if (it != threads_.end()) {
                        std::erase(suspended, it->second.get());
                        threads_.erase(it);
                    }
                } else if (e.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
                    Handle file(e.u.LoadDll.hFile);
                } else if (e.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT ||
                           e.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
                    throw std::runtime_error("Unexpected exception or process exit while tracing imports");
            }
            continuePending(DBG_CONTINUE);
        }
    } catch (...) {
        cleanup();
        throw;
    }
}
} // namespace mm
