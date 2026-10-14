// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "PEInfo.hpp"
namespace mm {
enum class BreakType : unsigned { Execute = 0, Write = 1, Access = 3 };
enum class SoftAction { Keep, Clear, KeepNoStep };
class DebuggerCore {
    struct Breakpoint {
        Address address{};
        BreakType type{};
        bool disabled{};
    };
    std::array<Breakpoint, 4> hardware_{};
    std::map<Address, std::uint8_t> software_;
    Address reenable_{};
    bool initialBreak_ = true;
    bool active_ = false;
    DWORD pendingThread_{};
    void stopTarget() noexcept;
    std::map<std::wstring, Address> loadedModules_;
    Path dllExecutable_;
    void launch();
    void makeDllExecutable();
    DWORD exception(const DEBUG_EVENT &e);
    void apply(CONTEXT &c);
    void updateAll();
    void created(const DEBUG_EVENT &e);

  protected:
    Path executable_;
    Logger log_;
    std::atomic_bool &cancel_;
    Handle process_;
    DWORD pid_{}, currentThread_{};
    Address imageBase_{};
    bool isDll_{}, finished_{};
    std::map<DWORD, Handle> threads_;
    std::unique_ptr<PEImage> filePE_;
    void info(const std::wstring &s) { log(log_, LogType::Info, s); }
    void good(const std::wstring &s) { log(log_, LogType::Good, s); }
    void warning(const std::wstring &s) { log(log_, LogType::Fatal, s); }
    bool rpm(Address a, void *b, std::size_t n) { return readMemory(process_.get(), a, b, n); }
    template <class T> T read(Address a) { return readValue<T>(process_.get(), a); }
    Bytes read(Address a, std::size_t n) { return readMemory(process_.get(), a, n); }
    template <class T> void write(Address a, const T &v) {
        static_assert(std::is_trivially_copyable_v<T>);
        writeValue(process_.get(), a, v);
    }
    void write(Address a, std::span<const std::uint8_t> b) {
        writeMemory(process_.get(), a, b.data(), b.size());
    }
    bool waitEvent(DEBUG_EVENT &event, DWORD timeout);
    void continuePending(DWORD status);
    void protect(Address a, std::size_t n, DWORD protection);
    void setBreakpoint(Address a, BreakType type = BreakType::Execute);
    void resetBreakpoint(Address a);
    bool hasBreakpoint(Address a) const;
    void enableBreakpoints();
    void setSoftBP(Address a);
    void clearSoftBPs();
    Address moduleBase(const wchar_t *dll);
    Address api(const wchar_t *dll, const char *name);
    HANDLE thread() { return threads_.at(currentThread_).get(); }
    void terminateSuccess();
    virtual void onStart() = 0;
    virtual DWORD onAccess(HANDLE, const EXCEPTION_RECORD &);
    virtual void onHardware(HANDLE, Address, CONTEXT &) = 0;
    virtual SoftAction onSoftware(HANDLE, Address) = 0;
    virtual void onDll(const std::wstring &, Address);
    virtual DWORD onStep(Address);
    // Consumes the current event and leaves the final tracing event pending.
    // The caller's outer debug loop continues that final event exactly once.
    bool trace(Address start, unsigned limit, const std::function<bool(unsigned, CONTEXT &)> &predicate);

  public:
    DebuggerCore(Path executable, Logger logger, std::atomic_bool &cancel);
    virtual ~DebuggerCore();
    DebuggerCore(const DebuggerCore &) = delete;
    DebuggerCore &operator=(const DebuggerCore &) = delete;
    bool run();
};
} // namespace mm
