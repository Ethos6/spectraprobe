# Changelog

## 0.2.0 — 2026-10-18

### Added
- **`spectra diff <old> <new>`** compares two builds: added/removed imports, exports, dependencies, symbols, indicators and sections. Section changes are ranked by size. Exits with code 1 when the targets differ, like `diff`. Also available as the `diff_targets` MCP tool and as `diffReports()` in the library.
- Demo GIF in the README, recorded from real CLI output (`scripts/record_demo.py`).

### Fixed
- File names such as `*.debug`, `*.so` and `*.json` are no longer reported as domains in string indicators.

## 0.1.0 — 2026-10-17

First release: format identification, hashing, entropy, strings and indicators, PE/ELF/Mach-O/WASM/ZIP parsers, JavaScript analysis, provider detection, evidence model, knowledge graph, sessions, reports, CLI and MCP server.
