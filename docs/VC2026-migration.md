# Visual Studio 2026／C++26 原生移植

## 目標與目前狀態

依需求使用 **Visual Studio 2026、MSVC v145、`.slnx`、`/std:c++latest`**。
這是原生 C++ 程式，不是透過 NMake／CustomBuild 呼叫 Delphi 的包裝專案。

- 入口：根目錄 `Magicmida.slnx`。
- 四種組態：`Debug|Win32`、`Release|Win32`、`Debug|x64`、`Release|x64`。
- C++ 程式碼：`native/`；BeaEngine 以原始 C 程式碼重新編譯。
- Pascal 原始碼及舊專案保留作為對照，不參與原生方案的建置。
- `/std:c++latest` 表示使用所安裝 MSVC 提供的 C++26 預覽能力，**不保證所有 C++26 特性均已實作**。
- 原生執行環境為 Windows 10／11；不宣稱保留舊 Pascal 工具鏈的 Windows XP 相容性。

**四組態真正 VS2026／MSVC 建置已通過；Windows 除錯器整合測試仍在排查，授權目標完整回歸尚未完成。**
在 Windows 建置矩陣與授權目標回歸測試通過前，不能將這份移植視為已證實與 Pascal 版完全等效。

## 模組對照

| 原始模組 | 原生實作 | 涵蓋的執行路徑 |
| --- | --- | --- |
| `Magicmida.dpr` | `native/Main.cpp` | GUI／CLI 分流、`/unpack`、Unicode 參數、結束碼 |
| `Unit2.pas`／`.dfm` | `Main.cpp`、`Magicmida.rc`、`resource.h` | Unpack、auto data、Dump process、Shrink、建立 sections、複製 log、原始圖示 |
| `Utils.pas` | `Utils.*`、`Binary.hpp` | HANDLE RAII、檔案／記憶體操作、Windows 版本、pattern 搜尋、記錄 |
| `PEInfo.pas` | `PEInfo.*` | PE32／PE32+、section／RVA、對齊、新增／縮減 sections、manifest ID 切換 |
| `DebuggerCore.pas` | `DebuggerCore.*` | 程序啟動、DLL 入口 stub、PEB、除錯事件、軟／硬體中斷點、目標 API 位址解析 |
| `Tracer.pas` | `Tracer.cpp` | 單步、指令上限、暫停其他執行緒、事件所有權與 context 還原 |
| `Dumper.pas` | `Dumper.*` | 遠端 exports、forward／ordinal、user32 特例、IAT 投票、OneCore、import／lookup table、.NET dump |
| `ThemidaCommon.pas` | `ThemidaCommon.*` | PE 分析、Themida section、IAT 搜尋、Delphi／Go／MSVC 路徑、匯入追蹤、.NET 偵測 |
| `Themida.pas` | `Themida.*` | x86 Themida 1／2／3、舊版 magic jumps、EFL patches、TLS、MSVC6／9 OEP、call-site 修復 |
| `Themida64.pas` | `Themida64.*` | x64 Themida 3、ScyllaHide、page guards、TLS、MSVC OEP 重建 |
| `AntiDumpFix.pas` | `AntiDumpFix.cpp` | x86 虛擬化 OEP 的 PE-header mitigation；不是完整 VM anti-dump 修復 |
| `OneCoreUAP.pas` | `OneCoreUAP.*` | 原始 3,003 筆 API → API-set DLL 對照，逐筆檢查 |
| `BeaEngineDelphi.pas`／舊 `.obj` | `third_party/beaengine`、`BeaEngine.vcxproj` | 使用 C API，按 Win32／x64 重新編譯，不混用 Delphi ABI |

這份對照涵蓋原本交付的 GUI／CLI 功能。未使用的 Pascal 私有輔助方法、VCL／FPC
型別別名及執行緒封裝不必逐一保留同名 C++ 方法；它不是供第三方連結的 Delphi class ABI 相容層。

## 有意調整與安全性修正

1. 使用 `uintptr_t` 儲存位址，PE RVA 維持 32 位元；禁止靜默截斷。
2. Pattern 搜尋回傳 `optional<size_t>`，修正 offset 0 命中、最後一個候選位置、長 pattern 與短 buffer 問題。
3. 二進位讀寫透過 `memcpy` 和範圍檢查，避免未對齊 dereference、整數溢位與空列表存取。
4. GUI 一次執行一項操作；工作執行緒透過佇列傳送 log，不直接操作 UI 控制項。
5. 取消／錯誤會終止本工具啟動的目標，處理尚未繼續的 debug event，並回收 HANDLE。
6. 等到 Windows loader 初始中斷點才初始化解包邏輯，避免 CREATE_PROCESS 時 DLL 尚未完成載入、Toolhelp 尚不可用。
7. API 位址由目標已載入的模組 base 加上 export RVA 算出，不假設本程序與目標的 ASLR base 相同。
8. Trace 結束後還原 context、成對 ResumeThread；不將 trace 的最後一個事件重複 Continue。
9. IAT 範圍受 SizeOfImage 限制，避免小型目標被固定 5,120-entry 讀取越界；建立獨立、以零結尾的 lookup table。
10. IAT 推估範圍可能混有非匯入資料：保留未分類 word 並記錄位址／數量，不將它們清零或偽造為 import；遇到空隙或不同 DLL 時建立獨立 descriptor／零結尾 OFT，保持原始 FirstThunk 位置。尾端只納入原有的零值，不強制覆寫下一個 word。完全沒有可解析 API 仍回報失敗。保留的資料可能是真正未解析的 import，必須以實際目標驗證，不保證輸出可執行。
11. PE 儲存只清理移除的 section headers，不任意覆寫後方 0x200 bytes；resource directory 可以不在 section 起點。
12. 檔案輸出先寫同目錄暫存檔，再 replace；失敗時保留原檔。臨時 DLL executable 只有建立成功才由此工具負責刪除。
13. x86 dump-process 以實際模組 base 讀取 `.text`；處理 ASLR，不使用磁碟上的 preferred ImageBase。
14. CLI 保留 `/unpack`，新增 `/help`、`--no-data`；成功／失敗／參數錯誤分別回傳 0／1／2。

這些差異本身需要 Windows 回歸測試，不能只靠編譯判定行為正確。

## Windows 執行修正追蹤

- `VirtualProtectEx` error 87：對本來就可寫的資料頁不再強制改成可執行頁；跨區域写入逐區驗證、調整並還原原保護屬性。
- Loader 初始化：保留 CREATE_PROCESS 階段的 `PEB.BeingDebugged`，等 loader breakpoint 到達才清除，避免初始中斷點被 Windows 省略而未呼叫解包初始化。
- x64 `Unresolved IAT group`：不再假設推估 IAT 內每個非零連續區塊都是單一 DLL 的完整匯入；以保留資料與分段 OFT 重建處理，附回歸測試與診斷。
- 使用者回報 x86 看似正常，x64 已到 TLS／OEP 還原與大量 API trace；這是該目標的階段性證據，尚不是全部目標的執行等效證明。

## 建置與執行

安裝 Visual Studio 2026 的「使用 C++ 的桌面開發」、v145 x86/x64 工具與 Windows SDK。
雙擊 `Magicmida.slnx`，將 **Magicmida** 設為啟始專案。

PowerShell 7：

```powershell
./tools/Build-Native.ps1 -Platform Win32 -Configuration Debug -Test
./tools/Build-Native.ps1 -Platform Win32 -Configuration Release -Test
./tools/Build-Native.ps1 -Platform x64 -Configuration Debug -Test
./tools/Build-Native.ps1 -Platform x64 -Configuration Release -Test
```

輸出位於 `artifacts/bin/<Platform>/<Configuration>/`，中間檔按專案隔離於
`artifacts/obj/`。`scylla_hide.ini` 會複製到輸出目錄。

- Win32 版本只能處理 x86 目標；x64 版本只能處理 x64 目標。
- x86 ScyllaHide：`InjectorCLIx86.exe`＋`HookLibraryx86.dll`，可選；未提供時沿用內建處理。
- x64 ScyllaHide：`InjectorCLIx64.exe`＋`HookLibraryx64.dll`，必要；舊版 injector 會被拒絕。
- ScyllaHide 檔案放在所執行的 `Magicmida.exe` 旁；建置不會自行下載或執行外部 injector。
- 執行時才會啟動使用者提供的 injector。其注入完成與否仍需在 Windows 上觀察。
- 原生 manifest 在 `native/Magicmida.manifest`，與 Pascal 版的根目錄 manifest 分開。
- Debug build 需要開發環境的 debug CRT；部署 Release build 時需有對應架構的 Visual C++ runtime。

## 驗證紀錄（2026-10-15）

| 驗證 | 狀態 |
| --- | --- |
| 所有原生 C++ 來源及測試的 Win32／x64 編譯 | 已在 Linux 使用 Zig／Clang 的 Windows target 通過；不是 MSVC |
| BeaEngine C 原始碼 Win32／x64 編譯 | 已通過；第三方程式保留其既有警告 |
| Win32／x64 應用與測試 EXE 完整連結 | 已通過交叉連結；EXE 沒有在 Linux 執行 |
| RC icons／version／manifest 資源 | 已通過交叉資源編譯與連結 |
| Portable unit tests | 已執行，新增稀疏／混合 DLL／未知資料 IAT 與隨機覆蓋檢查，通過；另以 AddressSanitizer／UBSan 執行通過 |
| `.slnx`／`.vcxproj` XML、來源／filters、3,003 筆 mapping、legacy patterns | `tools/validate_native.py` 提供離線一致性檢查 |
| 真正 VS2026／v145 Debug／Release × Win32／x64 | **四組態已通過真正 MSVC 建置**；最新修改仍需對應 CI 驗證 |
| Windows native unit／integration／CLI tests | 已執行；前次 CI 的除錯器 callback 測試未通過，正補診斷；新增稀疏 IAT 的真正 Windows loader 綁定測試待本次 CI |
| 真實 Themida、ScyllaHide、TLS／OEP、.NET、DLL 目標 | **待授權樣本回歸測試** |

Portable 檢查可在 Linux 執行：

```sh
python3 tools/validate_native.py
mkdir -p artifacts/portable
g++ -std=c++23 -Wall -Wextra -Wpedantic -Inative -Itests -DMM_PORTABLE_MAIN \
  tests/PortableTests.cpp native/OneCoreUAP.cpp -o artifacts/portable/tests
artifacts/portable/tests
```

此處使用 C++23 僅因 portable 測試子集不依賴 C++26 特性；Windows 專案仍使用 `/std:c++latest`。
交叉建置可用已安裝的 Zig 重現（工具不會自動下載編譯器）：

```sh
python3 tools/cross_check.py --zig /path/to/zig
```

它會編譯四種組態、連結應用／測試 EXE、核對 PE 架構與 GUI／Console subsystem，
但不會假裝在 Linux 執行 Windows integration tests。

`Magicmida.Tests.exe` 另涵蓋：

- 真正 Windows PE32／PE32+ 結構、截斷／錯誤 headers、RVA／alignment、section append／trim。
- 非零 resource offset 的 EXE／DLL manifest ID 切換。
- BeaEngine ABI 與指令邊界。
- Unicode 檔案、原子替換失敗保留原檔、暫存檔清理。
- 記憶體保護還原、reserved memory holes。
- 用本程序真正 exports 建立合成 IAT，檢查輸出的 descriptors、名稱與 lookup terminator。
- 以測試程式本身作為子程序，測試軟／硬體中斷點與取消，不需要任何受保護第三方樣本。

## Windows 手動驗收清單

不要拿重要原檔進行 destructive 測試；使用可還原 VM、自己的測試程式或已取得授權的樣本。
解包器會**執行目標程式碼**，不是靜態檢查器，也不是安全沙箱。

- [ ] 四組 MSVC 建置、native tests 與 CLI smoke tests 全部通過。
- [ ] GUI 啟動、DPI、所有 icon、右鍵選單、copy log、取消與關閉視窗。
- [ ] 含空白／繁體中文路徑、錯誤架構、畸形 PE、不存在路徑、輸出無寫入權限。
- [ ] x86 Themida 1、2、3 各有至少一個已知可解目標；對照 Pascal 版 log 與輸出 PE。
- [ ] x64 Themida 3，使用符合版本的 ScyllaHide，確認注入與 hardware breakpoints。
- [ ] EXE／DLL、.NET、TLS callback、MSVC6／9／14、Delphi／Go IAT 路徑。
- [ ] 在乾淨程序與重新開機後執行輸出，區分正確輸出與只在當次 DLL base 下可用的 dump。
- [ ] x86 create-data／MapleStory 特例、Shrink、Dump process，以及 destructive 操作的備份／錯誤提示。

## 沿用的限制

- 不修復所有 VM anti-dumps，不提供通用反虛擬化。
- x86 的 PE-header OEP mitigation 沿用「入口附近有足夠空間」假設；其他 VM 檢查仍可能使輸出無法執行。
- DLL relocation 資訊可能不足；ASLR flag 會依原有策略移除。
- x64 Themida 2 原本未支援，這次不額外宣稱支援。
- create-data／Shrink／Dump process 在原 GUI 只對 x86 開放；x64 仍不提供這些操作。
- Shrink 與 data-section heuristic 不是泛用 PE 修復器，可能使不相容目標損壞。
- Windows 相容性模式仍須關閉；需要 XP 的舊目標須使用 legacy 工具鏈。

## 授權與相依性

Magicmida 為 GPLv3。BeaEngine 是 LGPLv3-or-later；原始碼固定於
`6eaf28674c20e73f094ac0f7aee5a770c6a94b3a`，來源與兩份 license 均保留。
發布靜態連結 binary 時應一併履行對應原始碼及重新連結等授權義務。
不應將未測試的交叉建置 EXE 當作已驗收的 Windows release 發布。
