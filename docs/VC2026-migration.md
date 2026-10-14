# Visual Studio 2026／C++26 原生版

## 專案與清理範圍

入口為 `Magicmida.slnx`，四種組態為 Debug／Release × Win32／x64。
使用 MSVC v145 與 `/std:c++latest`；這代表編譯器提供的 C++26 預覽能力，
不代表所有 C++26 規格已實作。原生執行環境為 Windows 10／11。

此分支已依要求移除 Delphi／Pascal／Lazarus 原始碼與專案、DFM、舊 manifest、
預編譯 OBJ／RES，以及 BeaEngine 未使用的其他語言 bindings；歷史版本仍在 Git 中。
保留的內容均為原生程式、建置／測試工具、文件、資源、必要第三方 C 原始碼與授權。
圖示已整理到 `native/assets/`，原生 manifest 在 `native/Magicmida.manifest`。

| 模組 | 用途 |
| --- | --- |
| `Main.cpp`、RC／resource.h | GUI、Unicode CLI、背景工作、取消、記錄 |
| `Utils.*`、`Binary.hpp` | HANDLE、檔案／記憶體操作、邊界檢查、pattern 搜尋 |
| `PEInfo.*` | PE32／PE32+、RVA、sections、manifest |
| `DebuggerCore.*`、`Tracer.cpp` | 程序與除錯事件、軟／硬體中斷點、單步與 context 還原 |
| `Dumper.*`、`ImportPlan.hpp` | exports／forward／ordinal、稀疏 IAT、OFT、.NET dump |
| `ThemidaCommon.*`、`Themida.*`、`Themida64.*` | 共用邏輯、x86 Themida 1／2／3、x64 Themida 3 |
| `Patcher.*` | 跨架構 section 配置還原、保守壓縮、複製程序 executable sections |
| `AntiDumpFix.cpp` | 有限的 x86 header anti-dump mitigation，不是完整 VM 修復 |
| `OneCoreUAP.*` | 3,003 筆 API → API-set 對照 |
| `third_party/beaengine` | 按架構重新編譯的 C disassembler 與授權 |

## Create data sections：不再以遊戲名稱決定策略

不再檢查檔名是否含 MapleStory，也不依賴該遊戲的 RTTI／固定位置特徵。
兩種架構的 GUI 都可在 **Auto create data sections** 上按右鍵，選擇：

1. **Conservative automatic split**：PE32 有有效且對齊的 `BaseOfData`、該位置確實
   位於 merged executable section 內、入口點不落在待拆出的區域時，保守拆出
   `.text`／`.data`。保留原有 executable 權限，不假定資料區內絕無程式碼。
   不需要特定 linker 版本，也不要求 raw offset 等於 RVA。
2. **Restore layout from same-build reference**：另選同一版本、原始 section 配置正確的 PE，
   還原名稱、邊界、權限。使用的是**目標 dump 的內容**，不是把參考檔的資料複製過來。
   保留未分類區域、其餘 sections、overlay，以及原本 BSS 中已初始化的執行期狀態。

PE32+ 沒有 `BaseOfData`；缺乏參考資料時會明確記錄無法安全自動拆分並保持檔案不變。
自動模式也不會憑零區塊或字串猜測 `.rdata`／`.data` 的界線。
**這比誤改權限導致 TLS 或 VM code 壞掉更重要。** 若需要正確的唯讀／可寫權限分界，
請使用原始同版配置，而不是任意另一支程式作為參考。

套用前檢查架構、對齊、section 範圍與重疊、header 容量、新增 header 是否覆蓋既有資料／directory、
入口點是否仍可執行、TLS index 是否可寫、TLS callbacks 是否仍可執行。
參考 section 不得跨越目標既有 section；不吻合時拒絕寫入，不暗中合併。
這些檢查不能證明兩個檔案來自同一 build，參考檔的正確性仍需使用者確認。

CLI：

```text
Magicmida.exe /unpack <file> [--no-data]
Magicmida.exe /create-data <file> [--reference <same-build PE>]
Magicmida.exe /shrink <file>
```

Standalone `/create-data` 沒有安全拆分依據時回傳 1；自動解包後的 optional split
無法進行時只記錄不變更，不把已成功輸出的 dump 當作解包失敗。
一般結束碼為 0 成功、1 失敗／取消、2 參數錯誤。

## Compact 與 Dump process 的調整

- `/shrink`／**Compact (keep all sections)** 不再刪除未被 directory 指向的 section，
  也不再搬移或縮減 export directory 的內容。保留 VM、custom data、所有 section RVA 與虛擬範圍。
- 只壓縮 raw padding 與零尾端，保留 overlay；debug data 的實體長度及 `PointerToRawData`
  會一起處理。遇到非零 raw gaps、COFF symbols／relocation／line metadata 等未支援配置，
  明確拒絕，避免丟棄未知資料。
- section 修改／壓縮會讓原有數位簽章失效，清除 certificate directory，並不重新簽章。
  overlay 的保留不表示理解或修復其中自訂的絕對檔案指標；仍需目標回歸測試。
- Dump process 使用實際模組 base 與 executable section 範圍，不再假設 `BaseOfData`、
  第一 section 或固定 `.text` 長度；x64 也可使用。另存 `.novm` 並保留原副檔名。
  需選擇該程序的主模組檔案；時間戳／架構檢查不是完整身分比對。
  它不會移除虛擬化、修復 relocation 或辨識 executable section 裡的內嵌資料。
- 所有修改先驗證，再使用同目錄暫存檔原子替換；失敗應保留原檔。請仍先備份。

## 已修正的執行問題

- 可寫 PEB／資料頁不再一律改成 RWX，避免 Windows error 87；跨區域寫入逐區驗證並還原保護。
- 保留 CREATE_PROCESS 階段的 `PEB.BeingDebugged`，等 loader breakpoint 到達才清除，
  避免 Windows 省略初始化事件。
- 稀疏 IAT 遇到未知資料不再整組中止或清零；保留未知 word 並記錄位址／數量，
  依洞與 DLL 分組建立獨立零結尾 OFT，保持 FirstThunk 的真實位置。
  不憑空覆寫尾端 terminator；完全沒有可解析 API 仍失敗。
- 除錯器測試在第一個使用者程式碼停止點才安裝 HWBP，避免 loader 還原初始 context
  清掉測試所設的 DR7。仍驗證軟／硬體 callback、trace 控制與 debug registers 還原、取消。

## 建置與驗證

安裝 Visual Studio 2026 C++ desktop workload、v145 x86/x64 工具及 Windows SDK。
PowerShell 7：

```powershell
./tools/Build-Native.ps1 -Platform Win32 -Configuration Debug -Test
./tools/Build-Native.ps1 -Platform Win32 -Configuration Release -Test
./tools/Build-Native.ps1 -Platform x64 -Configuration Debug -Test
./tools/Build-Native.ps1 -Platform x64 -Configuration Release -Test
```

輸出在 `artifacts/bin/<Platform>/<Configuration>/`。
Debug build 需要 debug CRT；部署 Release build 需要對應 Visual C++ runtime。

### 紀錄（2026-10-15）

- 前一版 IAT／debugger 修正 `4331926`：真正 Windows VS2026 四組態建置、native integration、CLI 全通過
  （[CI 38601065569](https://github.com/kaze170/Magicmida/actions/runs/38601065569)）。使用者亦回報該目標正常。
- 本次 section／原生清理：四組態 Linux Zig／Clang Windows target 編譯／完整連結通過；
  10,532 項 portable 檢查及 ASan／UBSan 通過。
- 本次新增 Windows 測試須由對應 CI 驗證，不能以交叉編譯代替執行結果。
- 授權目標的 Themida／ScyllaHide／TLS／OEP／DLL／.NET 完整回歸仍需要實際樣本，
  不能把單一目標成功推廣成全部目標等效。

Windows suite 涵蓋：PE 結構／壞檔／RVA、manifest、disassembler、Unicode／原子寫入、
記憶體保護、稀疏匯入及真正 Windows loader 綁定、image-end IAT、數百項大型 import table、
section reference 還原、非 identity raw offsets、BSS 狀態保留、TLS 權限、錯誤不覆寫、
raw／virtual payload 一致性、壓縮冪等性、debug 指標／overlay、主模組程式碼複製、除錯與取消。
CLI suite 另在真正 MSVC 測試 EXE 上執行 section 還原及壓縮後，交給 Windows loader 啟動。

`tools/validate_native.py` 不再讀取已刪除的 Pascal 檔。移除前已逐筆確認 3,003 筆對照，
將其有序內容 SHA-256 與保留的 12 組 unpacker signatures 記在 `tools/native-baseline.json`。
驗證同時檢查原生來源／filters／資源／授權，以及禁止舊語言／預編譯檔回流。

Linux 可執行：

```sh
python3 tools/validate_native.py
mkdir -p artifacts/portable
g++ -std=c++23 -Wall -Wextra -Wpedantic -Werror -Inative -Itests -DMM_PORTABLE_MAIN \
  tests/PortableTests.cpp native/OneCoreUAP.cpp -o artifacts/portable/tests
artifacts/portable/tests
python3 tools/cross_check.py --zig /path/to/zig
```

Portable 子集不依賴 C++26 特性；Windows 專案仍使用 `/std:c++latest`。

## 執行限制

- Win32／x64 需與目標架構相同。不限遊戲名稱，不等於支援所有 packer／compiler／VM。
- x64 必須提供適當版本 ScyllaHide injector／HookLibrary；x86 可選。放在 Magicmida.exe 旁，
  建置僅複製 profile，不下載或捆綁 injector。禁止啟用 Windows compatibility mode。
- 仍不承諾完整 VM anti-dump／devirtualization；輸出 DLL 可能缺 relocation。
- 保留的 IAT 未分類資料可能仍是未解析匯入；必須實際執行輸出驗證。
- section 權限恢復、TLS 與自訂 overlay 使用方式都需要同一目標的回歸測試。
