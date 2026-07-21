# APKBA Analyzer

给非技术编辑使用的离线 APK/XAPK intake 工具。拖入安装包和应用图标后，它会完成静态检查并生成一个可直接交给 Agent1 的文件夹。

## 第一版会检查什么

- APK/XAPK 原件的文件大小和 SHA-256。
- ZIP 结构、CRC、重复条目、越界路径、加密条目和异常压缩比。
- 包名、应用名、版本、SDK、权限和启动 Activity。
- APK 签名及签名证书 SHA-256；优先使用 Android SDK `apksigner`，找不到时用内置解析器提取证书并明确标记“未完整验证”。
- XAPK 的 `manifest.json`、base APK、split 文件、各 split SHA-256 及签名一致性。
- 图标格式、尺寸和是否为正方形。

工具默认不联网、不安装 APK、不执行 APK，也不修改原件。它不是杀毒软件，不会给出“安全”或“官方来源”的承诺。

## 编辑使用

Windows 双击打包后的 `APKBA-Analyzer.exe`，macOS 打开 `APKBA-Analyzer.app`：

1. 把一个 `.apk` 或 `.xapk` 拖到左侧。
2. 把对应图标拖到右侧。
3. 选择输出位置，点击“开始扫描并生成交接包”。
4. 扫描通过后点击“打开交接包”，把整个文件夹交给 Agent1。

交接目录保持扁平：一个原始 APK/XAPK、一个 `icon.*`、`scan_report.json`、`agent1_handoff.json`、浏览器可打开的 `scan_summary.html` 和说明文件。Agent1 仍负责安装、启动、人工截图/录屏和最终证据包验证。

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

输出为 `dist\APKBA-Analyzer\APKBA-Analyzer.exe`。

macOS：

```bash
chmod +x scripts/*.sh
./scripts/build-macos.sh
```

输出为 `dist/APKBA-Analyzer.app`。构建必须在目标系统本机执行；Windows 不能直接生成 macOS `.app`。

## Android 工具增强

安装 Android SDK Command-line Tools 后，工具会自动发现 `apkanalyzer`；安装 Build Tools 后会自动发现 `apksigner`。没有 SDK 时会回退到打包在程序内的 Androguard。所有不可确认信息都会保留为警告，不会伪造字段。
