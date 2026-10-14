// SPDX-License-Identifier: GPL-3.0-only
#include "Themida.hpp"
#include "Themida64.hpp"
#include "resource.h"
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <windowsx.h>
#include <deque>
#include <mutex>
#include <thread>
namespace mm {
#ifdef _WIN64
using Unpacker = Themida64;
constexpr const wchar_t *title = L"Magicmida64 — native C++";
#else
using Unpacker = Themida;
constexpr const wchar_t *title = L"Magicmida — native C++";
#endif
std::atomic_bool consoleCancel = false;
BOOL WINAPI consoleHandler(DWORD code) {
    if (code == CTRL_C_EVENT || code == CTRL_BREAK_EVENT) {
        consoleCancel = true;
        return TRUE;
    }
    return FALSE;
}
void consoleLog(LogType type, const std::wstring &text) {
    static const wchar_t *names[] = {L"Info", L"Good", L"Fatal"};
    auto line = L"[" + std::wstring(names[static_cast<unsigned>(type)]) + L"] " + text + L"\r\n";
    auto out = GetStdHandle(type == LogType::Fatal ? STD_ERROR_HANDLE : STD_OUTPUT_HANDLE);
    if (!out || out == INVALID_HANDLE_VALUE)
        return;
    DWORD mode{}, n{};
    if (GetConsoleMode(out, &mode))
        WriteConsoleW(out, line.data(), static_cast<DWORD>(line.size()), &n, nullptr);
    else {
        auto bytes = narrow(line);
        WriteFile(out, bytes.data(), static_cast<DWORD>(bytes.size()), &n, nullptr);
    }
}
std::optional<Path> chooseFile(HWND owner, const wchar_t *title = nullptr) {
    std::wstring path(32768, 0);
    OPENFILENAMEW o{};
    o.lStructSize = sizeof(o);
    o.hwndOwner = owner;
    o.lpstrTitle = title;
    o.lpstrFile = path.data();
    o.nMaxFile = static_cast<DWORD>(path.size());
    o.lpstrFilter = L"Application or DLL\0*.exe;*.dll\0Any file\0*.*\0\0";
    o.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER;
    if (!GetOpenFileNameW(&o)) {
        auto error = CommDlgExtendedError();
        if (error)
            winError("GetOpenFileName", error);
        return {};
    }
    path.resize(std::wcslen(path.c_str()));
    return Path(path);
}
INT_PTR CALLBACK pidDialog(HWND w, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_INITDIALOG) {
        SetWindowLongPtrW(w, DWLP_USER, lp);
        return TRUE;
    }
    if (msg == WM_COMMAND) {
        if (LOWORD(wp) == IDCANCEL) {
            EndDialog(w, IDCANCEL);
            return TRUE;
        }
        if (LOWORD(wp) == IDOK) {
            BOOL translated{};
            auto pid = GetDlgItemInt(w, IDC_PID, &translated, FALSE);
            if (!translated || !pid) {
                MessageBoxW(w, L"Enter a nonzero decimal process ID.", L"Invalid PID", MB_ICONWARNING);
                return TRUE;
            }
            *reinterpret_cast<DWORD *>(GetWindowLongPtrW(w, DWLP_USER)) = pid;
            EndDialog(w, IDOK);
            return TRUE;
        }
    }
    return FALSE;
}
class Window {
    HINSTANCE instance_;
    HWND hwnd_{}, list_{};
    HFONT font_{};
    HIMAGELIST icons_{};
    std::thread worker_;
    std::atomic_bool cancel_ = false, done_ = false;
    bool busy_ = false, closing_ = false;
    std::mutex mutex_;
    std::deque<std::pair<LogType, std::wstring>> pending_;
    std::vector<std::wstring> lines_;
    int dpi_ = 96;
    int px(int v) const { return MulDiv(v, dpi_, 96); }
    void createControl(const wchar_t *cls, const wchar_t *text, int id, DWORD style = 0) {
        auto h = CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 0, 0, hwnd_,
                                 reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), instance_, nullptr);
        if (!h)
            winError("CreateWindowEx(control)");
        SendMessageW(h, WM_SETFONT, reinterpret_cast<WPARAM>(font_), TRUE);
    }
    void layout() {
        RECT r{};
        GetClientRect(hwnd_, &r);
        int w = r.right, h = r.bottom;
        auto place = [&](int id, int x, int y, int cx, int cy) {
            MoveWindow(GetDlgItem(hwnd_, id), px(x), px(y), px(cx), px(cy), TRUE);
        };
        place(IDC_UNPACK, 10, 10, 90, 28);
        place(IDC_DATA, 112, 10, 200, 28);
        place(IDC_DUMP, 320, 10, 102, 28);
        place(IDC_SHRINK, 432, 10, 210, 28);
        MoveWindow(GetDlgItem(hwnd_, IDC_CANCEL), w - px(100), px(10), px(90), px(28), TRUE);
        MoveWindow(list_, px(10), px(48), std::max(1, w - px(20)), std::max(1, h - px(83)), TRUE);
        MoveWindow(GetDlgItem(hwnd_, IDC_STATUS), px(12), h - px(27), std::max(1, w - px(24)), px(22), TRUE);
        ListView_SetColumnWidth(list_, 0, std::max(1, w - px(50)));
    }
    void setBusy(bool busy) {
        busy_ = busy;
        for (int id : {IDC_UNPACK, IDC_DATA, IDC_DUMP, IDC_SHRINK})
            if (auto h = GetDlgItem(hwnd_, id))
                EnableWindow(h, !busy);
        EnableWindow(GetDlgItem(hwnd_, IDC_CANCEL), busy);
        SetWindowTextW(GetDlgItem(hwnd_, IDC_STATUS), busy ? L"Working…" : L"Ready");
    }
    Logger logger() {
        return [this](LogType type, const std::wstring &text) {
            std::lock_guard lock(mutex_);
            pending_.emplace_back(type, text);
        };
    }
    void drain() {
        std::deque<std::pair<LogType, std::wstring>> queue;
        {
            std::lock_guard lock(mutex_);
            queue.swap(pending_);
        }
        for (auto &[type, text] : queue) {
            lines_.push_back(text);
            LVITEMW item{};
            item.mask = LVIF_TEXT | LVIF_IMAGE;
            item.iItem = ListView_GetItemCount(list_);
            item.pszText = text.data();
            item.iImage = static_cast<int>(type);
            ListView_InsertItem(list_, &item);
            ListView_EnsureVisible(list_, item.iItem, FALSE);
        }
        if (done_.exchange(false)) {
            if (worker_.joinable())
                worker_.join();
            setBusy(false);
            if (closing_)
                DestroyWindow(hwnd_);
        }
    }
    void start(std::function<void(const Logger &)> job) {
        if (busy_)
            return;
        cancel_ = false;
        done_ = false;
        setBusy(true);
        try {
            worker_ = std::thread([this, job = std::move(job)] {
                auto log = logger();
                try {
                    job(log);
                } catch (const std::exception &e) {
                    log(LogType::Fatal, widen(e.what()));
                }
                done_ = true;
            });
        } catch (...) {
            setBusy(false);
            throw;
        }
    }
    void copyLog() {
        std::wstring text;
        for (auto &line : lines_)
            text += line + L"\r\n";
        auto size = (text.size() + 1) * sizeof(wchar_t);
        auto mem = GlobalAlloc(GMEM_MOVEABLE, size);
        if (!mem)
            winError("GlobalAlloc");
        auto p = GlobalLock(mem);
        if (!p) {
            GlobalFree(mem);
            winError("GlobalLock");
        }
        std::memcpy(p, text.c_str(), size);
        GlobalUnlock(mem);
        if (!OpenClipboard(hwnd_)) {
            GlobalFree(mem);
            winError("OpenClipboard");
        }
        EmptyClipboard();
        if (!SetClipboardData(CF_UNICODETEXT, mem)) {
            auto error = GetLastError();
            CloseClipboard();
            GlobalFree(mem);
            winError("SetClipboardData", error);
        }
        CloseClipboard();
    }
    void command(int id) {
        if (id == IDM_COPY) {
            copyLog();
            return;
        }
        if (id == IDC_CANCEL) {
            cancel_ = true;
            EnableWindow(GetDlgItem(hwnd_, IDC_CANCEL), FALSE);
            SetWindowTextW(GetDlgItem(hwnd_, IDC_STATUS), L"Cancelling…");
            return;
        }
        if (busy_)
            return;
        if (id == IDC_UNPACK) {
            auto path = chooseFile(hwnd_);
            if (!path)
                return;
            bool data = IsDlgButtonChecked(hwnd_, IDC_DATA) == BST_CHECKED;
            start([this, path = *path, data](const Logger &log) {
                Unpacker u(path, data, log, cancel_);
                u.run();
            });
            return;
        }
        if (id == IDC_DUMP) {
            DWORD pid{};
            if (DialogBoxParamW(instance_, MAKEINTRESOURCEW(IDD_PID), hwnd_, pidDialog,
                                reinterpret_cast<LPARAM>(&pid)) != IDOK)
                return;
            auto p = chooseFile(hwnd_);
            if (p)
                start([p = *p, pid](const Logger &log) { Patcher(p, log).dumpProcess(pid); });
        } else if (id == IDC_SHRINK || id == IDM_CREATE_DATA || id == IDM_CREATE_REFERENCE) {
            auto p = chooseFile(hwnd_);
            if (!p)
                return;
            Path reference;
            if (id == IDM_CREATE_REFERENCE) {
                auto ref = chooseFile(
                    hwnd_, L"Choose a reference PE from the SAME BUILD with the original section layout");
                if (!ref)
                    return;
                reference = *ref;
            }
            if (MessageBoxW(hwnd_,
                            id == IDC_SHRINK
                                ? L"This compacts raw padding but retains all sections and overlay. "
                                  L"It invalidates signatures. Make a backup first. Continue?"
                                : L"This rewrites section headers in the selected file. Make a backup first. "
                                  L"Continue?",
                            L"Confirm file modification", MB_YESNO | MB_ICONWARNING) != IDYES)
                return;
            start([p = *p, id, reference](const Logger &log) {
                Patcher patch(p, log);
                if (id == IDC_SHRINK)
                    patch.shrink();
                else
                    patch.createData(reference);
            });
        }
    }
    LRESULT message(UINT msg, WPARAM wp, LPARAM lp) {
        switch (msg) {
        case WM_CREATE: {
            dpi_ = static_cast<int>(GetDpiForWindow(hwnd_));
            font_ = CreateFontW(-px(14), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH,
                                L"Segoe UI");
            createControl(L"BUTTON", L"Unpack", IDC_UNPACK, WS_TABSTOP | BS_PUSHBUTTON);
            createControl(L"BUTTON", L"Auto create data sections", IDC_DATA, WS_TABSTOP | BS_AUTOCHECKBOX);
            CheckDlgButton(hwnd_, IDC_DATA, BST_CHECKED);
            createControl(L"BUTTON", L"Dump process", IDC_DUMP, WS_TABSTOP);
            createControl(L"BUTTON", L"Compact (keep all sections)", IDC_SHRINK, WS_TABSTOP);
            createControl(L"BUTTON", L"Cancel", IDC_CANCEL, WS_TABSTOP);
            createControl(WC_LISTVIEWW, L"", IDC_LOG,
                          WS_TABSTOP | LVS_REPORT | LVS_NOCOLUMNHEADER | LVS_SHOWSELALWAYS);
            createControl(L"STATIC", L"Ready", IDC_STATUS);
            list_ = GetDlgItem(hwnd_, IDC_LOG);
            ListView_SetExtendedListViewStyle(list_, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
            icons_ = ImageList_Create(px(16), px(16), ILC_COLOR32 | ILC_MASK, 3, 0);
            if (!icons_)
                winError("ImageList_Create");
            for (int id : {IDI_INFO, IDI_GOOD, IDI_FATAL}) {
                auto icon = static_cast<HICON>(
                    LoadImageW(instance_, MAKEINTRESOURCEW(id), IMAGE_ICON, px(16), px(16), 0));
                if (icon) {
                    ImageList_AddIcon(icons_, icon);
                    DestroyIcon(icon);
                }
            }
            ListView_SetImageList(list_, icons_, LVSIL_SMALL);
            LVCOLUMNW col{};
            col.mask = LVCF_WIDTH;
            col.cx = 600;
            ListView_InsertColumn(list_, 0, &col);
            setBusy(false);
            layout();
            SetTimer(hwnd_, 1, 50, nullptr);
            return 0;
        }
        case WM_SIZE:
            if (list_)
                layout();
            return 0;
        case WM_GETMINMAXINFO: {
            auto *m = reinterpret_cast<MINMAXINFO *>(lp);
            m->ptMinTrackSize = {px(800), px(300)};
            return 0;
        }
        case WM_COMMAND:
            command(LOWORD(wp));
            return 0;
        case WM_TIMER:
            drain();
            return 0;
        case WM_CONTEXTMENU: {
            auto target = reinterpret_cast<HWND>(wp);
            auto menu = CreatePopupMenu();
            if (!menu)
                winError("CreatePopupMenu");
            if (target == list_)
                AppendMenuW(menu, MF_STRING, IDM_COPY, L"Copy entire log");
            else if (target == GetDlgItem(hwnd_, IDC_DATA)) {
                AppendMenuW(menu, MF_STRING | (busy_ ? MF_GRAYED : 0), IDM_CREATE_DATA,
                            L"Conservative automatic split");
                AppendMenuW(menu, MF_STRING | (busy_ ? MF_GRAYED : 0), IDM_CREATE_REFERENCE,
                            L"Restore layout from same-build reference...");
            }
            POINT pt{GET_X_LPARAM(lp), GET_Y_LPARAM(lp)};
            if (pt.x == -1 && pt.y == -1) {
                RECT r{};
                GetWindowRect(target, &r);
                pt = {r.left + 10, r.top + 10};
            }
            auto selected =
                TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd_, nullptr);
            DestroyMenu(menu);
            if (selected)
                command(selected);
            return 0;
        }
        case WM_CLOSE:
            if (busy_) {
                if (MessageBoxW(hwnd_,
                                L"Cancel the operation and close? The debug target will be terminated.",
                                L"Magicmida", MB_YESNO | MB_ICONQUESTION) == IDYES) {
                    closing_ = true;
                    cancel_ = true;
                }
                return 0;
            }
            DestroyWindow(hwnd_);
            return 0;
        case WM_DESTROY:
            KillTimer(hwnd_, 1);
            PostQuitMessage(0);
            return 0;
        default:
            return DefWindowProcW(hwnd_, msg, wp, lp);
        }
    }
    static LRESULT CALLBACK procedure(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
        Window *self = reinterpret_cast<Window *>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (msg == WM_NCCREATE) {
            self = static_cast<Window *>(reinterpret_cast<CREATESTRUCTW *>(lp)->lpCreateParams);
            self->hwnd_ = hwnd;
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        }
        if (!self)
            return DefWindowProcW(hwnd, msg, wp, lp);
        try {
            return self->message(msg, wp, lp);
        } catch (const std::exception &e) {
            MessageBoxW(hwnd, widen(e.what()).c_str(), L"Magicmida error", MB_ICONERROR);
            return msg == WM_CREATE ? -1 : 0;
        }
    }

  public:
    explicit Window(HINSTANCE instance) : instance_(instance) {}
    ~Window() {
        cancel_ = true;
        if (worker_.joinable())
            worker_.join();
        if (icons_)
            ImageList_Destroy(icons_);
        if (font_)
            DeleteObject(font_);
    }
    int run(int show) {
        INITCOMMONCONTROLSEX cc{sizeof(cc), ICC_LISTVIEW_CLASSES};
        check(InitCommonControlsEx(&cc), "InitCommonControlsEx");
        WNDCLASSEXW cls{};
        cls.cbSize = sizeof(cls);
        cls.lpfnWndProc = procedure;
        cls.hInstance = instance_;
        cls.lpszClassName = L"Magicmida.Native";
        cls.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        cls.hIcon = LoadIconW(instance_, MAKEINTRESOURCEW(IDI_MAGICMIDA));
        cls.hIconSm = cls.hIcon;
        cls.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
        if (!RegisterClassExW(&cls))
            winError("RegisterClassEx");
        auto h = CreateWindowExW(0, cls.lpszClassName, title, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,
                                 CW_USEDEFAULT, 960, 500, nullptr, nullptr, instance_, this);
        if (!h)
            winError("CreateWindowEx");
        ShowWindow(h, show);
        UpdateWindow(h);
        MSG msg{};
        int result;
        while ((result = GetMessageW(&msg, nullptr, 0, 0)) > 0) {
            if (!IsDialogMessageW(h, &msg)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        if (result < 0)
            winError("GetMessage");
        return static_cast<int>(msg.wParam);
    }
};
} // namespace mm
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    using namespace mm;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    int argc{};
    auto raw = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!raw)
        return 1;
    std::vector<std::wstring> args(raw, raw + argc);
    LocalFree(raw);
    if (argc > 1) {
        // Keep redirected handles intact; otherwise attach to the invoking console.
        if (!GetStdHandle(STD_OUTPUT_HANDLE) || GetStdHandle(STD_OUTPUT_HANDLE) == INVALID_HANDLE_VALUE)
            AttachConsole(ATTACH_PARENT_PROCESS);
        SetConsoleCtrlHandler(consoleHandler, TRUE);
        const auto usage = L"Usage: Magicmida.exe /unpack <file> [--no-data]\r\n"
                           L"       Magicmida.exe /create-data <file> [--reference <same-build PE>]\r\n"
                           L"       Magicmida.exe /shrink <file>\r\n"
                           L"Use the matching architecture. Section edits overwrite the file; back up first. "
                           L"Exit codes: 0 success, 1 failure/cancel/no safe split, 2 usage.";
        if (args[1] == L"/?" || args[1] == L"/help" || args[1] == L"--help") {
            consoleLog(LogType::Info, usage);
            return 0;
        }
        bool unpack = args[1] == L"/unpack" && (argc == 3 || (argc == 4 && args[3] == L"--no-data"));
        bool sections = args[1] == L"/create-data" && (argc == 3 || (argc == 5 && args[3] == L"--reference"));
        bool shrink = args[1] == L"/shrink" && argc == 3;
        if (!unpack && !sections && !shrink) {
            consoleLog(LogType::Fatal, usage);
            return 2;
        }
        try {
            if (sections)
                return Patcher(args[2], consoleLog).createData(argc == 5 ? Path(args[4]) : Path{}) ? 0 : 1;
            if (shrink) {
                Patcher(args[2], consoleLog).shrink();
                return 0;
            }
            Unpacker u(args[2], argc < 4, consoleLog, consoleCancel);
            return u.run() ? 0 : 1;
        } catch (const std::exception &e) {
            consoleLog(LogType::Fatal, widen(e.what()));
            return 1;
        }
    }
    try {
        Window w(instance);
        return w.run(show);
    } catch (const std::exception &e) {
        MessageBoxW(nullptr, widen(e.what()).c_str(), L"Magicmida", MB_ICONERROR);
        return 1;
    }
}
