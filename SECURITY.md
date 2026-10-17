# Security policy

## Scope and intent

SpectraProbe is a **static** analysis toolkit for defensive security, debugging, interoperability, and authorized software investigation. It parses and reads files; it does not execute the software it analyses, and it intentionally excludes runtime hooking, stealth monitoring, access-control/DRM circumvention, credential capture, and persistence mechanisms.

Analyse only software you own, open-source software, research samples in an environment you control, or targets you have a lawful basis to inspect.

## Handling untrusted input safely

SpectraProbe is frequently pointed at untrusted or malicious files. The parsers are written to treat all input as hostile:

- Binary reads are bounds-checked and fail with an error rather than reading out of bounds.
- Malformed structures produce a warning and partial results instead of crashing a whole run.
- External provider processes run with hard timeouts and bounded output capture.
- No file under analysis is ever executed.

Still, treat results as data. When analysing live malware, do so in an isolated environment.

## Reporting a vulnerability

If you find a security issue in SpectraProbe itself (for example a parser that can be made to hang, exhaust memory, or crash on a crafted file), please open a GitHub issue describing the problem and attach a minimal, **non-malicious** reproduction fixture where possible. For sensitive reports, open a minimal issue asking for a private channel.

We aim to acknowledge reports promptly and fix denial-of-service and memory-safety issues as a priority.
