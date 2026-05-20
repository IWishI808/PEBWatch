# PEBWatch

Runtime PEB (Process Environment Block) tamper detection for Windows x64.

Takes periodic snapshots of the PEB and compares them to detect:
- Module list unlinking (rootkit-style hiding)
- Phantom modules (loaded but unlinked from PEB)
- BeingDebugged flag inconsistencies
- NtGlobalFlag changes
- ImagePathName spoofing
- Command line tampering

## How it works

1. Reads the PEB directly via `__readgsqword(0x60)` (GS segment, x64 TEB offset)
2. Walks `InLoadOrderModuleList` to snapshot all loaded modules
3. Cross-references PEB module count against a `VirtualQuery` memory scan for MZ headers
4. Compares `BeingDebugged` against `NtQueryInformationProcess(ProcessBasicInformation)`
5. Validates `ImagePathName` against `QueryFullProcessImageNameW`

## Build

Requirements: Visual Studio 2022, x64 target.

```
cl /W4 /O2 /Fe:pebwatch.exe src\main.c src\peb_reader.c src\tamper_detect.c /link ntdll.lib kernel32.lib
```

Or open a x64 Native Tools Command Prompt and run the above.

## Usage

```
pebwatch.exe
```

Runs in a loop, printing detected changes every 2 seconds. Ctrl+C to stop.

## Status

Work in progress. Structure definitions are manual (not relying on SDK winternl.h completeness).
