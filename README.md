# APKBA Analyzer

给非技术编辑使用的 APK/XAPK/APKM intake 与端到端取证工具。拖入安装包和应用图标后，选择一台明确的 Android 手机，即可完成静态检查、安装、启动、媒体基线、人工媒体确认和 schema3 证据包生成。正常流程不再依赖 Agent1 对话。

## 第一版会检查什么

- APK/XAPK/APKM 原件的文件大小和 SHA-256。
- ZIP 结构、CRC、重复条目、越界路径、加密条目和异常压缩比。
- 包名、应用名、版本、SDK、权限和启动 Activity。
- APK 签名及签名证书 SHA-256；优先使用 Android SDK `apksigner`，找不到时用内置解析器提取证书并明确标记“未完整验证”。
- XAPK 的 `manifest.json`、base APK、split 文件、各 split SHA-256 及签名一致性。
- APKM 的 `info.json`、base APK、split 文件、各 split SHA-256 及签名一致性。
- 图标格式、尺寸和是否为正方形。

静态扫描不联网、不安装 APK、不执行 APK，也不修改原件。只有点击“连接手机取证”后，工具才会把扫描通过的安装包安装到下拉框中明确选择的手机；它不会自动截图或录屏。工具不是杀毒软件，不会给出“安全”或“官方来源”的承诺。

## 编辑使用

Windows 双击 `dist\APKBA-Analyzer.exe` 单文件发布版，macOS 打开 `APKBA-Analyzer.app`：

1. 把 `.apk`、`.xapk` 或 `.apkm` 与对应图标拖到窗口任意位置。可以一次拖入两个文件，工具会自动分流。
2. 也可以分别点击“选择安装包”和“选择图标”。
3. 选择输出位置，连接手机并开启“开发者选项 → USB 调试”，在手机弹窗中授权电脑。
4. 从“本窗口手机”中明确选择设备，再点击“连接手机取证”。如果旧 APK 的 `targetSdk` 低于手机系统允许的最低值，工具会在安装前显示风险提示；只有人工点击“兼容安装”才会使用 Android 官方的低目标 SDK 测试参数，并把该事实写入交接记录。
5. 工具安装并启动应用、记录截图/录屏前基线后会停止。编辑在手机上手动截图和录屏，完成后点击“截图/录屏完成 · 记录边界”。
6. 程序自动读取前基线之后、结束边界之前的媒体，并打开本地审查窗口。逐张勾选本次截图，检查录屏代表帧或完整回放，并确认“可见”“黑屏/禁止录屏”或“部分受保护”。
7. 点击“生成证据包”。程序会拉取确认媒体、复制原始安装包和图标、写入 schema3 `observations.json`，验证哈希、图片、MP4 和目录残留。验证通过的证据目录可直接交给 Agent2。
8. EXE 重启后可点击“完成已有取证”，选择含 `.apkba-pending-session.json` 的交接文件夹继续，不需要重新安装。

交接目录保持扁平：一个原始 APK/XAPK/APKM、一个 `icon.*`、`scan_report.json`、`agent1_handoff.json`、浏览器可打开的 `scan_summary.html` 和说明文件。取证准备模式会生成 `.apkba-pending-session.json`；成功完成后，证据包直接位于最后人工选择的目录下，文件夹名为 `<应用名>_<包名>_<日期>/`，包含 `_READY`、`observations.json`、版本说明、源安装包、截图和原始 MP4。原始 intake 输入继续保留。

## 本地开发（Windows）

项目要求 Python 3.11 或更新版本。当前机器可直接运行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe main.py
```

命令行扫描：

```powershell
.\.venv\Scripts\python.exe main.py scan `
  --source "E:\path\app.xapk" `
  --icon "E:\path\icon.png" `
  --output "E:\path\intake-output"
```

只读列出设备与指定设备取证准备：

```powershell
.\.venv\Scripts\python.exe main.py devices
.\.venv\Scripts\python.exe main.py prepare `
  --source "E:\path\app.xapk" `
  --icon "E:\path\icon.png" `
  --output "E:\path\intake-output" `
  --serial "从 devices 输出中复制的序列号"
```

命令行不会默认绕过低目标 SDK 安装限制。仅在明确用于测试旧应用时加入：

```powershell
  --allow-low-target-sdk-bypass
```

命令行完成取证时，先冻结边界并查看候选媒体，再传入人工确认的远程路径：

```powershell
.\.venv\Scripts\python.exe main.py finish-preflight `
  --bundle "E:\path\Example_Agent1_Intake"

.\.venv\Scripts\python.exe main.py finish `
  --bundle "E:\path\Example_Agent1_Intake" `
  --output "E:\path\final-evidence-output" `
  --screenshot "/sdcard/DCIM/Screenshots/Screenshot_Example.png" `
  --recording "/sdcard/DCIM/Screen recordings/Example.mp4" `
  --visibility visible `
  --review-method operator_confirmed_playback
```

桌面版会在最后的媒体确认窗口中让编辑手动选择最终证据包保存根目录，并记住上一次选择。应用证据包文件夹会直接生成在所选目录中，不会自动增加日期目录；应用文件夹名称本身仍包含取证日期。验证通过的每个最终证据包根目录都会包含一个无扩展名、严格为 0 字节的 `_READY` 文件。

运行测试：

```powershell
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check .
```

## 构建桌面程序

Windows：

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\scripts\build-windows.ps1
```

输出为单文件 `dist\APKBA-Analyzer.exe`，其中包含官方 Android Platform Tools 的电脑端 ADB。其他 Windows 电脑只需这个 EXE；手机端仍需开启 USB 调试并授权。不要运行 `build` 或 `.pyinstaller-work` 目录里的中间 EXE。

macOS：

```bash
chmod +x scripts/*.sh
./scripts/build-macos.sh
```

输出为 `dist/APKBA-Analyzer.app`，并会嵌入构建机上的官方 ADB。构建必须在目标系统本机执行；Windows 不能直接生成 macOS `.app`。

## Android 工具增强

安装 Android SDK Command-line Tools 后，工具会自动发现 `apkanalyzer`；安装 Build Tools 后会自动发现 `apksigner`。没有 SDK 时会回退到打包在程序内的 Androguard。所有不可确认信息都会保留为警告，不会伪造字段。
