# APKBA Analyzer

给非技术编辑使用的 APK/XAPK/APKM intake 与取证准备工具。拖入安装包和应用图标后，它可以只完成静态检查，也可以连接一台明确选择的 Android 手机，自动执行 Agent1 在“好了”之前的安装、启动和媒体基线步骤。

## 第一版会检查什么

- APK/XAPK/APKM 原件的文件大小和 SHA-256。
- ZIP 结构、CRC、重复条目、越界路径、加密条目和异常压缩比。
- 包名、应用名、版本、SDK、权限和启动 Activity。
- APK 签名及签名证书 SHA-256；优先使用 Android SDK `apksigner`，找不到时用内置解析器提取证书并明确标记“未完整验证”。
- XAPK 的 `manifest.json`、base APK、split 文件、各 split SHA-256 及签名一致性。
- APKM 的 `info.json`、base APK、split 文件、各 split SHA-256 及签名一致性。
- 图标格式、尺寸和是否为正方形。

静态扫描不联网、不安装 APK、不执行 APK，也不修改原件。只有点击“连接手机并开始取证”后，工具才会把扫描通过的安装包安装到下拉框中明确选择的手机；它不会自动截图或录屏。工具不是杀毒软件，不会给出“安全”或“官方来源”的承诺。

## 编辑使用

Windows 双击 `dist\APKBA-Analyzer.exe` 单文件发布版，macOS 打开 `APKBA-Analyzer.app`：

1. 把 `.apk`、`.xapk` 或 `.apkm` 与对应图标拖到窗口任意位置。可以一次拖入两个文件，工具会自动分流。
2. 也可以分别点击“选择安装包”和“选择图标”。
3. 选择输出位置，连接手机并开启“开发者选项 → USB 调试”，在手机弹窗中授权电脑。
4. 只需要静态交接包时，点击“扫描并生成交接包”。
5. 需要完成取证准备时，从“取证手机”中明确选择设备，再点击“连接手机取证”。如果旧 APK 的 `targetSdk` 低于手机系统允许的最低值，工具会在安装前显示风险提示；只有人工点击“兼容安装”才会使用 Android 官方的低目标 SDK 测试参数，并把该事实写入交接记录。
6. 工具安装并启动应用、记录截图/录屏前基线后会停止。编辑在手机上手动截图和录屏，完成后点击“截图/录屏完成 · 记录边界”。工具会把本次取证的结束时间和边界内媒体数量写入交接包；记录成功后可以直接开始下一份 APK。
7. 把整个文件夹交给 Agent1 并回复“好了”。Agent1 只会选择前基线之后、结束边界之前的媒体；如果截图或录屏黑屏/被禁止，需要在“好了”后明确说明。

交接目录保持扁平：一个原始 APK/XAPK/APKM、一个 `icon.*`、`scan_report.json`、`agent1_handoff.json`、浏览器可打开的 `scan_summary.html` 和说明文件。取证准备模式还会生成与 Agent1 兼容的 `.apkba-pending-session.json`；Agent1 从人工截图/录屏完成后的验证阶段继续。

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
