# PEBWatch

PEBWatch is a Windows x64 defensive research prototype for detecting tampering
with the Process Environment Block. It snapshots PEB state, compares it over
time, and cross-checks the PEB module list against memory regions discovered
with `VirtualQuery`.

The goal is to demonstrate practical PEB forensics: module unlinking,
command-line tampering, image path spoofing, and debug flag manipulation.

## What is implemented

- direct PEB access through `__readgsqword(0x60)` on x64
- manual PEB, LDR, and process-parameter structure definitions
- `InLoadOrderModuleList` walking
- baseline and current PEB snapshots
- detection of added and removed modules between snapshots
- `VirtualQuery` scan for committed `MEM_IMAGE` regions with PE headers
- phantom module detection when image-backed memory is missing from the PEB list
- `BeingDebugged` and `NtGlobalFlag` change detection
- `ProcessDebugPort` consistency checks through `NtQueryInformationProcess`
- `ImagePathName` and command-line change detection

## Defensive use cases

- identify modules unlinked from the PEB loader lists
- detect post-launch command-line or image-path tampering
- spot basic anti-debug flag manipulation
- compare user-mode process metadata against memory-backed evidence
- support incident-response and malware-analysis lab workflows

## Build

Requirements:

- Visual Studio 2022
- x64 Native Tools Command Prompt

Build:

```bat
cl /W4 /O2 /DWIN32_LEAN_AND_MEAN /Fe:pebwatch.exe src\main.c src\peb_reader.c src\tamper_detect.c /link ntdll.lib kernel32.lib
```

Run:

```bat
pebwatch.exe
```

The tool takes a baseline snapshot, prints loaded modules, and then checks for
changes every two seconds.

## Current status

PEBWatch is a lab-oriented prototype. It uses manual structure layouts and
process-local checks. It does not currently use ETW, kernel VAD traversal, or a
driver component; those would be natural future extensions.

## Responsible use

This project is for defensive forensics, malware-analysis labs, and authorized
security research. It does not include stealth, persistence, injection, or
evasion features.

## Related writeup

- [PEB Internals](https://iwishi808.github.io/2026/05/15/peb-windows-internals/)

## License

MIT
