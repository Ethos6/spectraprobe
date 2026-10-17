# Contributing to SpectraProbe

Thanks for your interest! SpectraProbe is a static software-analysis toolkit for defensive and authorized research. Contributions that add format coverage, provider adapters, or test fixtures are especially welcome.

## Getting started

```bash
git clone https://github.com/Ethos6/spectraprobe
cd spectraprobe
npm install
npm run build
npm test
```

Useful scripts:

- `npm run typecheck` — strict TypeScript, no emit
- `npm test` / `npm run test:watch` — Vitest
- `npm run build` — compile to `dist/`
- `node dist/cli/cli.js <command>` — run the CLI from source

## Guidelines

- **TypeScript strict mode** stays on. No `any` escapes without a clear reason.
- **Parsers are readers.** They must never execute, modify, or write to a target. Use the bounds-checked `ByteReader` and fail safely on malformed input (collect a warning, don't crash the whole run).
- **Findings cite evidence.** Use `EvidenceCollector`; a finding without supporting evidence is a bug.
- **Deterministic tests.** Add a fixture in `test/fixtures.ts` (hand-crafted buffers, no network, no reliance on host binaries) for every new parser or analysis.
- **Optional stays optional.** New external tools are added as *providers* that detect availability and degrade gracefully; never make the core depend on them.
- **Scope.** This project is static-analysis only. Please do not propose runtime hooking, stealth monitoring, access-control/DRM circumvention, or credential-capture features — they are out of scope and will be declined.

## Good first contributions

- A new format parser (e.g. `.NET` metadata tables, DEX structure, firmware containers)
- A provider adapter that actually invokes a tool (Ghidra headless, radare2, JADX) and maps its output into findings
- More indicator extractors or capability heuristics
- Documentation and real-world examples

## Submitting

1. Fork and branch.
2. Add tests; run `npm run typecheck && npm test`.
3. Open a PR describing the change and the authorized-research use case it serves.
