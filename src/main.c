#include "pebwatch.h"
#include <stdio.h>

#define POLL_INTERVAL_MS  2000

static void print_banner(void)
{
    wprintf(L"PEBWatch - PEB tamper detection\n");
    wprintf(L"-------------------------------\n");
    wprintf(L"Polling every %d ms. Press Ctrl+C to stop.\n\n", POLL_INTERVAL_MS);
}

static void print_snapshot(const PEB_SNAPSHOT *snap)
{
    wprintf(L"[Snapshot] Modules: %u | BeingDebugged: %d | NtGlobalFlag: 0x%08X\n",
            snap->module_count, snap->being_debugged, snap->nt_global_flag);
    wprintf(L"           ImagePath: %ls\n", snap->image_path);
}

static void print_report(const TAMPER_REPORT *report)
{
    DWORD i;

    if (report->modules_added) {
        wprintf(L"  [+] %u module(s) ADDED:\n", report->added_count);
        for (i = 0; i < report->added_count; i++)
            wprintf(L"      + %ls\n", report->added_names[i]);
    }

    if (report->modules_removed) {
        wprintf(L"  [-] %u module(s) REMOVED (potential unlinking):\n", report->removed_count);
        for (i = 0; i < report->removed_count; i++)
            wprintf(L"      - %ls\n", report->removed_names[i]);
    }

    if (report->debug_flag_changed)
        wprintf(L"  [!] BeingDebugged flag CHANGED\n");

    if (report->ntglobalflag_changed)
        wprintf(L"  [!] NtGlobalFlag CHANGED\n");

    if (report->image_path_changed)
        wprintf(L"  [!] ImagePathName CHANGED\n");

    if (report->command_line_changed)
        wprintf(L"  [!] CommandLine CHANGED\n");

    if (report->debug_inconsistency)
        wprintf(L"  [!] Debug state INCONSISTENT (PEB patched?)\n");

    if (report->phantom_modules_detected)
        wprintf(L"  [!] %u phantom module(s) detected (loaded but unlinked from PEB)\n",
                report->phantom_count);
}

int wmain(int argc, wchar_t *argv[])
{
    PEB_SNAPSHOT *baseline = NULL;
    PEB_SNAPSHOT *current = NULL;
    TAMPER_REPORT report;
    DWORD iteration = 0;
    DWORD phantom_count;
    BOOL has_changes;

    (void)argc;
    (void)argv;

    print_banner();

    /* Allocate snapshots on heap - they're large structs */
    baseline = (PEB_SNAPSHOT *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PEB_SNAPSHOT));
    current  = (PEB_SNAPSHOT *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PEB_SNAPSHOT));

    if (!baseline || !current) {
        wprintf(L"[!] Failed to allocate snapshot memory\n");
        return 1;
    }

    /* Take initial baseline snapshot */
    if (!snapshot_peb(baseline)) {
        wprintf(L"[!] Failed to take baseline PEB snapshot\n");
        return 1;
    }

    wprintf(L"[*] Baseline captured.\n");
    print_snapshot(baseline);
    wprintf(L"\n[*] Listing loaded modules:\n");

    for (DWORD i = 0; i < baseline->module_count; i++) {
        wprintf(L"    [%3u] 0x%p  %ls\n",
                i, baseline->module_list[i].DllBase,
                baseline->module_list[i].BaseDllName);
    }

    wprintf(L"\n[*] Running initial checks...\n");

    /* Initial unlink check */
    phantom_count = check_module_unlinking(baseline);
    if (phantom_count > 0)
        wprintf(L"  [!] %u phantom module(s) found on startup\n", phantom_count);
    else
        wprintf(L"  [OK] No phantom modules detected\n");

    /* Initial debug consistency check */
    if (check_debug_consistency())
        wprintf(L"  [OK] Debug state consistent\n");

    /* Initial image path check */
    if (check_image_path(baseline))
        wprintf(L"  [OK] ImagePathName consistent\n");

    wprintf(L"\n[*] Monitoring for changes...\n\n");

    /* Main monitoring loop */
    while (1) {
        Sleep(POLL_INTERVAL_MS);
        iteration++;

        if (!snapshot_peb(current)) {
            wprintf(L"[!] Failed to take snapshot at iteration %u\n", iteration);
            continue;
        }

        has_changes = FALSE;
        ZeroMemory(&report, sizeof(report));

        /* Compare against baseline */
        compare_snapshots(baseline, current, &report);

        /* Additional checks */
        if (!check_debug_consistency()) {
            report.debug_inconsistency = TRUE;
            has_changes = TRUE;
        }

        if (!check_image_path(current)) {
            /* Already printed by check_image_path */
            has_changes = TRUE;
        }

        phantom_count = check_module_unlinking(current);
        if (phantom_count > 0) {
            report.phantom_modules_detected = TRUE;
            report.phantom_count = phantom_count;
            has_changes = TRUE;
        }

        /* Check if any changes in snapshot comparison */
        if (report.modules_added || report.modules_removed ||
            report.debug_flag_changed || report.ntglobalflag_changed ||
            report.image_path_changed || report.command_line_changed) {
            has_changes = TRUE;
        }

        if (has_changes) {
            wprintf(L"[%u] CHANGES DETECTED:\n", iteration);
            print_report(&report);
            wprintf(L"\n");

            /*
             * Update baseline after reporting so we don't keep
             * re-reporting the same change. Copy current -> baseline.
             */
            memcpy(baseline, current, sizeof(PEB_SNAPSHOT));
        }
    }

    /* Unreachable, but be correct */
    HeapFree(GetProcessHeap(), 0, baseline);
    HeapFree(GetProcessHeap(), 0, current);

    return 0;
}
