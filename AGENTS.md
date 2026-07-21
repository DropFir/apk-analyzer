# APKBA Analyzer Repository Rules

This repository contains only the editor-facing APK/XAPK intake analyzer. It is
independent from the sibling `agent1`, `agent2`, and `agent3` repositories.

## Required behavior

- Keep the default scan offline. Never upload APKs, XAPKs, icons, reports, or hashes.
- Treat every APK/XAPK as untrusted data. Never execute it and never load native code from it.
- Do not modify source packages or icons. Copy them only when creating an intake bundle.
- Inspect ZIP members before extraction. Reject traversal paths, duplicate names, encrypted
  entries, excessive expansion, and undeclared XAPK split files.
- Parse an APK manifest once per scan. For XAPK, parse only the declared base APK manifest.
- Preserve factual uncertainty. Missing tools or unverifiable signatures are warnings or
  blockers, never invented values.
- Keep generated JSON paths relative and use `/` separators so bundles remain portable.
- Do not commit APKs, XAPKs, icons supplied by users, generated intake bundles, credentials,
  local IDE state, virtual environments, or build outputs.
- Support Windows and macOS. Avoid hard-coded drive letters and user-home paths.
- Run the automated tests before committing changes.

## Project layout

- `src/apkba_analyzer/`: scanner core, intake writer, CLI, and PySide6 UI.
- `tests/`: isolated synthetic archives; tests must not use real APK payloads.
- `scripts/`: platform build launchers.
- `main.py`: development and packaged-app entry point.
