#include "pebwatch.h"
#include <stdio.h>
#include <winternl.h>

/* NtQueryInformationProcess typedef - not always in headers */
typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
);

/*
 * find_module_by_base - Look up a module in a snapshot by DllBase address.
 * Returns index or -1 if not found.
 */
static int find_module_by_base(const PEB_SNAPSHOT *snap, PVOID dll_base)
{
    DWORD i;
    for (i = 0; i < snap->module_count; i++) {
        if (snap->module_list[i].DllBase == dll_base)
            return (int)i;
    }
    return -1;
}

/*
 * compare_snapshots - Diff two PEB snapshots and populate a tamper report.
 *
 * Checks for:
 *   - Modules present in current but not in baseline (added)
 *   - Modules present in baseline but not in current (removed/unlinked)
 *   - BeingDebugged flag changes
 *   - NtGlobalFlag changes
 *   - ImagePathName changes
 *   - CommandLine changes
 */
BOOL compare_snapshots(const PEB_SNAPSHOT *baseline,
                       const PEB_SNAPSHOT *current,
                       PTAMPER_REPORT report)
{
    DWORD i;

    if (!baseline || !current || !report)
        return FALSE;

    ZeroMemory(report, sizeof(TAMPER_REPORT));

    /* Check for added modules (in current but not in baseline) */
    for (i = 0; i < current->module_count; i++) {
        if (find_module_by_base(baseline, current->module_list[i].DllBase) < 0) {
            if (report->added_count < 32) {
                wcscpy_s(report->added_names[report->added_count],
                         MAX_PATH_CHARS,
                         current->module_list[i].BaseDllName);
                report->added_count++;
            }
            report->modules_added = TRUE;
        }
    }

    /* Check for removed modules (in baseline but not in current) */
    for (i = 0; i < baseline->module_count; i++) {
        if (find_module_by_base(current, baseline->module_list[i].DllBase) < 0) {
            if (report->removed_count < 32) {
                wcscpy_s(report->removed_names[report->removed_count],
                         MAX_PATH_CHARS,
                         baseline->module_list[i].BaseDllName);
                report->removed_count++;
            }
            report->modules_removed = TRUE;
        }
    }

    /* Debug flag */
    if (baseline->being_debugged != current->being_debugged)
        report->debug_flag_changed = TRUE;

    /* NtGlobalFlag */
    if (baseline->nt_global_flag != current->nt_global_flag)
        report->ntglobalflag_changed = TRUE;

    /* ImagePathName */
    if (wcscmp(baseline->image_path, current->image_path) != 0)
        report->image_path_changed = TRUE;

    /* CommandLine */
    if (wcscmp(baseline->command_line, current->command_line) != 0)
        report->command_line_changed = TRUE;

    return TRUE;
}

/*
 * check_module_unlinking - Detect modules that are loaded in memory but
 * unlinked from the PEB module list (rootkit technique).
 *
 * Strategy: Walk the entire virtual address space with VirtualQuery,
 * look for committed MEM_IMAGE regions, check for MZ signature at base,
 * and compare against the PEB snapshot's module list.
 *
 * Returns count of phantom (unlinked) modules found.
 */
DWORD check_module_unlinking(const PEB_SNAPSHOT *snap)
{
    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR addr = 0;
    DWORD phantom_count = 0;
    WORD mz_sig;

    if (!snap)
        return 0;

    while (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) {
        /*
         * We're looking for regions that:
         *   1. Are committed (MEM_COMMIT)
         *   2. Are image-backed (MEM_IMAGE)
         *   3. Start at the allocation base (region base == allocation base)
         *   4. Have a valid MZ header
         */
        if (mbi.State == MEM_COMMIT &&
            mbi.Type == MEM_IMAGE &&
            mbi.BaseAddress == mbi.AllocationBase &&
            mbi.RegionSize >= 0x1000) {

            /* Try to read MZ signature */
            __try {
                mz_sig = *(WORD *)mbi.BaseAddress;
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                mz_sig = 0;
            }

            if (mz_sig == 0x5A4D) { /* 'MZ' */
                /* Check if this base is in the PEB module list */
                if (find_module_by_base(snap, mbi.BaseAddress) < 0) {
                    phantom_count++;
                    wprintf(L"  [!] Phantom module at 0x%p (size 0x%llX) - NOT in PEB module list\n",
                            mbi.BaseAddress, (unsigned long long)mbi.RegionSize);
                }
            }
        }

        /* Advance to next region */
        addr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (addr == 0) /* overflow, we've wrapped */
            break;
    }

    return phantom_count;
}

/*
 * check_debug_consistency - Compare PEB.BeingDebugged against
 * NtQueryInformationProcess(ProcessBasicInformation).
 *
 * If BeingDebugged is 0 but NQIP says we're being debugged (or vice versa),
 * someone patched the PEB flag.
 *
 * Returns TRUE if consistent, FALSE if tampered.
 */
BOOL check_debug_consistency(void)
{
    PMY_PEB peb;
    HMODULE ntdll;
    pfnNtQueryInformationProcess pNtQIP;
    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS status;
    ULONG ret_len = 0;
    BOOLEAN peb_debug;
    BOOLEAN nqip_debug;

    peb = get_peb();
    if (!peb)
        return TRUE; /* can't check, assume ok */

    peb_debug = peb->BeingDebugged;

    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return TRUE;

    pNtQIP = (pfnNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!pNtQIP)
        return TRUE;

    ZeroMemory(&pbi, sizeof(pbi));
    status = pNtQIP(GetCurrentProcess(),
                    ProcessBasicInformation,
                    &pbi,
                    sizeof(pbi),
                    &ret_len);

    if (status != 0) /* STATUS_SUCCESS */
        return TRUE;

    /*
     * pbi.PebBaseAddress points to the real PEB. Read BeingDebugged from
     * the NQIP-returned PEB address to cross-validate.
     * Also, we can use ProcessDebugPort (class 7) for a stronger check.
     */
    {
        DWORD_PTR debug_port = 0;
        status = pNtQIP(GetCurrentProcess(),
                        (PROCESSINFOCLASS)7, /* ProcessDebugPort */
                        &debug_port,
                        sizeof(debug_port),
                        &ret_len);

        if (status == 0) {
            nqip_debug = (debug_port != 0) ? TRUE : FALSE;
        } else {
            /* Fallback: just use PEB value */
            return TRUE;
        }
    }

    if ((peb_debug != 0) != (nqip_debug != 0)) {
        wprintf(L"  [!] Debug inconsistency: PEB.BeingDebugged=%d, ProcessDebugPort=%d\n",
                peb_debug, nqip_debug);
        return FALSE;
    }

    return TRUE;
}

/*
 * check_image_path - Compare PEB ImagePathName against
 * QueryFullProcessImageNameW result.
 *
 * If someone patched the PEB's ImagePathName (e.g., to spoof the process
 * identity), this will catch it.
 *
 * Returns TRUE if consistent, FALSE if tampered.
 */
BOOL check_image_path(const PEB_SNAPSHOT *snap)
{
    WCHAR real_path[MAX_PATH_CHARS];
    DWORD size = MAX_PATH_CHARS;

    if (!snap)
        return TRUE;

    if (!QueryFullProcessImageNameW(GetCurrentProcess(), 0, real_path, &size)) {
        /* Can't verify, don't raise false alarm */
        return TRUE;
    }

    real_path[size] = L'\0';

    /*
     * The PEB ImagePathName might use \??\ or \Device\HarddiskVolume
     * prefix while QueryFullProcessImageName returns a DOS path.
     * Do a suffix comparison on the filename portion.
     */
    {
        const WCHAR *peb_filename = wcsrchr(snap->image_path, L'\\');
        const WCHAR *real_filename = wcsrchr(real_path, L'\\');

        if (!peb_filename) peb_filename = snap->image_path;
        else peb_filename++;

        if (!real_filename) real_filename = real_path;
        else real_filename++;

        if (_wcsicmp(peb_filename, real_filename) != 0) {
            wprintf(L"  [!] ImagePathName mismatch:\n");
            wprintf(L"      PEB:  %ls\n", snap->image_path);
            wprintf(L"      Real: %ls\n", real_path);
            return FALSE;
        }
    }

    return TRUE;
}
